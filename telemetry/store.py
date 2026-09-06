import base64
import hashlib
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class EventStore:
    """One writer lock. Appends and projection updates commit in one transaction."""

    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
                stream TEXT NOT NULL, version INTEGER NOT NULL, type TEXT NOT NULL,
                at TEXT NOT NULL, metadata TEXT NOT NULL, data TEXT NOT NULL,
                payload BLOB, payload_sha256 TEXT NOT NULL,
                previous_hash TEXT NOT NULL, hash TEXT NOT NULL,
                UNIQUE(stream, version));
            CREATE INDEX IF NOT EXISTS events_type ON events(type, seq);
            CREATE INDEX IF NOT EXISTS events_stream ON events(stream, seq);
            CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
                BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
                BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, protocol TEXT, ip TEXT, mac TEXT, source_port INTEGER,
                destination_port INTEGER, started_at TEXT, last_at TEXT, closed_at TEXT,
                status TEXT, wire_in INTEGER DEFAULT 0, wire_out INTEGER DEFAULT 0,
                plain_in INTEGER DEFAULT 0, plain_out INTEGER DEFAULT 0,
                events INTEGER DEFAULT 0, username TEXT, requests INTEGER DEFAULT 0);
            CREATE INDEX IF NOT EXISTS sessions_started ON sessions(started_at);
            CREATE TABLE IF NOT EXISTS runtime (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS email_settings (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS email_outbox (
                id TEXT PRIMARY KEY, status TEXT NOT NULL, next_attempt REAL NOT NULL, state TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS email_outbox_due ON email_outbox(status, next_attempt);
            CREATE TABLE IF NOT EXISTS projection_checkpoint (id INTEGER PRIMARY KEY, seq INTEGER);
            INSERT OR IGNORE INTO projection_checkpoint VALUES(1, 0);
        """)
        self.catch_up()

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def append(self, stream, kind, data=None, metadata=None, payload=None, event_id=None):
        # Commands own the transaction; this method never performs external work.
        event_id = event_id or str(uuid.uuid4())
        existing = self.db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        if existing:
            return dict(existing)
        version = self.db.execute("SELECT COALESCE(MAX(version),0)+1 FROM events WHERE stream=?", (stream,)).fetchone()[0]
        last = self.db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        event = dict(id=event_id, stream=stream, version=version, type=kind, at=timestamp(),
                     metadata=canonical(metadata or {}), data=canonical(data or {}),
                     payload_sha256=hashlib.sha256(payload or b"").hexdigest(),
                     previous_hash=last[0] if last else "0" * 64)
        event["hash"] = hashlib.sha256(canonical(event).encode()).hexdigest()
        columns = list(event) + ["payload"]
        cur = self.db.execute(f"INSERT INTO events ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
                              [event.get(c) if c != "payload" else payload for c in columns])
        event.update(seq=cur.lastrowid, payload=payload)
        self.project(event)
        return event

    def project(self, event):
        data, meta = json.loads(event["data"]), json.loads(event["metadata"])
        session_id = meta.get("session_id")
        if event["type"] == "ConnectionOpened":
            self.db.execute("""INSERT INTO sessions
                (id,protocol,ip,mac,source_port,destination_port,started_at,last_at,status)
                VALUES(?,?,?,?,?,?,?,?, 'open')""", (session_id, meta["protocol"], meta["ip"], meta.get("mac"),
                meta["source_port"], meta["destination_port"], event["at"], event["at"]))
        if session_id:
            self.db.execute("UPDATE sessions SET events=events+1,last_at=?,mac=COALESCE(?,mac) WHERE id=?",
                            (event["at"], meta.get("mac"), session_id))
            if event["type"] in ("BytesCaptured", "TerminalBytesCaptured"):
                column = ("wire_" if event["type"] == "BytesCaptured" else "plain_") + data["direction"]
                if column not in ("wire_in", "wire_out", "plain_in", "plain_out"):
                    raise ValueError("Invalid byte direction")
                self.db.execute(f"UPDATE sessions SET {column}={column}+? WHERE id=?", (len(event["payload"] or b""), session_id))
            if event["type"] == "AuthenticationAttempted":
                self.db.execute("UPDATE sessions SET username=? WHERE id=?", (data.get("username"), session_id))
            if event["type"] == "HttpRequestReceived":
                self.db.execute("UPDATE sessions SET requests=requests+1 WHERE id=?", (session_id,))
            if event["type"] == "ConnectionClosed":
                self.db.execute("UPDATE sessions SET status='closed',closed_at=? WHERE id=?", (event["at"], session_id))
        if event["stream"] == "sandbox":
            state = self.runtime()
            if event["type"] == "ContainerReconcileRequested":
                state.update(request_id=event["id"], pending=True, requested_at=event["at"])
            elif event["type"] == "ContainerReconcileCompleted":
                state.update(data, pending=False, checked_at=event["at"])
            self.db.execute("INSERT OR REPLACE INTO runtime VALUES(1,?)", (canonical(state),))
        if event["type"] == "EmailNotificationsConfigured":
            settings = self.email_settings()
            settings.update(data)
            self.db.execute("INSERT OR REPLACE INTO email_settings VALUES(1,?)", (canonical(settings),))
        if event["type"].startswith("EmailNotification") and event["stream"].startswith("email:"):
            notification_id = event["stream"][6:]
            state = self.email_job(notification_id) or {}
            if event["type"] == "EmailNotificationRequested":
                state = {**data, "id": notification_id, "status": "pending", "attempts": 0,
                         "requested_at": event["at"], "next_attempt": data["queued_at"]}
                settings = self.email_settings()
                settings.update(cursor=data["source_through_seq"], next_batch=data["next_batch"])
                self.db.execute("INSERT OR REPLACE INTO email_settings VALUES(1,?)", (canonical(settings),))
            elif event["type"] == "EmailNotificationAttemptStarted":
                state.update(data, status="sending")
            elif event["type"] == "EmailNotificationAccepted":
                state.update(data, status="accepted", accepted_at=event["at"], last_error=None, next_attempt=0)
            elif event["type"] == "EmailNotificationFailed":
                state.update(data, last_error=data["error"], failed_at=event["at"])
                if data.get("error_code") == "unexpected-channels":
                    settings = self.email_settings()
                    settings.update(blocked=True, blocked_reason=data["error"])
                    self.db.execute("INSERT OR REPLACE INTO email_settings VALUES(1,?)", (canonical(settings),))
            self.db.execute("INSERT OR REPLACE INTO email_outbox VALUES(?,?,?,?)",
                            (notification_id, state["status"], state["next_attempt"], canonical(state)))
        self.db.execute("UPDATE projection_checkpoint SET seq=? WHERE id=1", (event["seq"],))

    def email_settings(self):
        with self.lock:
            row = self.db.execute("SELECT state FROM email_settings WHERE id=1").fetchone()
            return json.loads(row[0]) if row else {"enabled": False, "configuration": "token-required", "cursor": 0, "next_batch": 0, "blocked": False}

    def email_job(self, notification_id):
        with self.lock:
            row = self.db.execute("SELECT state FROM email_outbox WHERE id=?", (notification_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def email_work(self):
        with self.lock:
            settings = self.email_settings()
            if not settings["enabled"] or settings["blocked"]:
                return None
            row = self.db.execute("SELECT state FROM email_outbox WHERE status IN ('pending','retry','sending') AND next_attempt<=? ORDER BY next_attempt, id LIMIT 1", (time.time(),)).fetchone()
            return json.loads(row[0]) if row else None

    def connection_snapshot(self, after):
        """A bounded sample plus exact counts across the entire unscheduled range."""
        with self.lock:
            row = self.db.execute("""SELECT MIN(seq) first_seq, MAX(seq) last_seq, COUNT(*) connections,
                COUNT(DISTINCT json_extract(metadata,'$.ip')) unique_ips, MIN(at) first_at, MAX(at) last_at
                FROM events WHERE type='ConnectionOpened' AND seq>?""", (after,)).fetchone()
            if not row["connections"]:
                return None
            samples = []
            for event in self.db.execute("SELECT at, metadata FROM events WHERE type='ConnectionOpened' AND seq>? AND seq<=? ORDER BY seq LIMIT 10", (after, row["last_seq"])):
                meta = json.loads(event["metadata"])
                samples.append({"at": event["at"], **{k: meta.get(k) for k in ("session_id", "ip", "mac", "protocol", "source_port", "destination_port")}})
            return {"source_from_seq": row["first_seq"], "source_through_seq": row["last_seq"],
                    "connections": row["connections"], "unique_ips": row["unique_ips"],
                    "first_at": row["first_at"], "last_at": row["last_at"], "samples": samples}

    def email_summary(self):
        with self.lock:
            settings = self.email_settings()
            result = {k: settings.get(k) for k in ("enabled", "configuration", "blocked", "blocked_reason", "batch_seconds")}
            counts = {r["status"]: r["count"] for r in self.db.execute("SELECT status,COUNT(*) count FROM email_outbox GROUP BY status")}
            result.update(accepted=counts.get("accepted", 0), failed=counts.get("failed", 0),
                          pending=sum(counts.get(s, 0) for s in ("pending", "sending", "retry")))
            latest = self.db.execute("SELECT state FROM email_outbox ORDER BY rowid DESC LIMIT 1").fetchone()
            if latest:
                state = json.loads(latest[0])
                result["latest"] = {k: state.get(k) for k in ("id", "status", "attempts", "last_error", "accepted_at", "requested_at", "next_attempt")}
            return result

    def runtime(self):
        with self.lock:
            row = self.db.execute("SELECT state FROM runtime WHERE id=1").fetchone()
            return json.loads(row[0]) if row else {"pending": False, "status": "unknown", "next_check": 0}

    def catch_up(self, rebuild=False):
        with self.transaction():
            if rebuild:
                self.db.execute("DELETE FROM sessions")
                self.db.execute("DELETE FROM runtime")
                self.db.execute("DELETE FROM email_settings")
                self.db.execute("DELETE FROM email_outbox")
                self.db.execute("UPDATE projection_checkpoint SET seq=0")
            seq = self.db.execute("SELECT seq FROM projection_checkpoint WHERE id=1").fetchone()[0]
            for event in self.db.execute("SELECT * FROM events WHERE seq>? ORDER BY seq", (seq,)):
                self.project(event)

    def verify(self):
        with self.lock:
            previous = "0" * 64
            count = 0
            for row in self.db.execute("SELECT * FROM events ORDER BY seq"):
                event = dict(row)
                seq, payload, digest = event.pop("seq"), event.pop("payload"), event.pop("hash")
                if event["previous_hash"] != previous or event["payload_sha256"] != hashlib.sha256(payload or b"").hexdigest() or hashlib.sha256(canonical(event).encode()).hexdigest() != digest:
                    raise ValueError(f"Event integrity check failed at sequence {seq}")
                previous, count = digest, count + 1
            return {"events": count, "head_hash": previous}

    def events(self, before=None, after=0, session=None, kind=None, limit=100, protocol=None, ip=None):
        clauses, args = ["seq> ?"], [after]
        if before:
            clauses.append("seq < ?")
            args.append(before)
        if session:
            clauses.append("stream = ?")
            args.append(session)
        if kind:
            clauses.append("type = ?")
            args.append(kind)
        for key, value in (("protocol", protocol), ("ip", ip)):
            if value:
                clauses.append("json_extract(metadata, '$." + key + "') = ?")
                args.append(value)
        with self.lock:
            # Payload bytes are fetched separately, keeping the live feed small.
            rows = self.db.execute("SELECT seq,id,stream,version,type,at,metadata,data,hash,payload_sha256,length(payload) AS byte_length FROM events WHERE " + " AND ".join(clauses) + " ORDER BY seq DESC LIMIT ?", args + [min(max(limit, 1), 200)]).fetchall()
            return [{**dict(r), "metadata": json.loads(r["metadata"]), "data": json.loads(r["data"])} for r in rows]

    def payload(self, seq):
        with self.lock:
            row = self.db.execute("SELECT payload FROM events WHERE seq=?", (seq,)).fetchone()
            return None if not row else row[0] or b""

    def sessions(self, protocol=None, ip=None, limit=100):
        clauses, args = ["1=1"], []
        for field, value in (("protocol", protocol), ("ip", ip)):
            if value:
                clauses.append(field + "=?")
                args.append(value)
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM sessions WHERE " + " AND ".join(clauses) + " ORDER BY started_at DESC LIMIT ?", args + [min(max(limit, 1), 200)])]

    def summary(self):
        with self.lock:
            counts = dict(self.db.execute("SELECT COUNT(*) connections, COUNT(DISTINCT ip) devices, COALESCE(SUM(wire_in+wire_out),0) bytes, COALESCE(SUM(status='open'),0) active FROM sessions").fetchone())
            counts["events"] = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            counts["protocols"] = [dict(r) for r in self.db.execute("SELECT protocol,COUNT(*) connections,SUM(wire_in) bytes_in,SUM(wire_out) bytes_out FROM sessions GROUP BY protocol")]
            counts["timeline"] = [dict(r) for r in self.db.execute("SELECT substr(started_at,1,13) hour,COUNT(*) connections FROM sessions WHERE started_at>=? GROUP BY hour ORDER BY hour", (datetime.fromtimestamp(time.time()-86400, timezone.utc).isoformat(),))]
            counts["container"] = self.runtime()
            counts["email"] = self.email_summary()
            return counts

    def close(self):
        with self.lock:
            self.db.close()
