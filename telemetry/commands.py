import time


class Commands:
    def __init__(self, store, health_interval=30):
        self.store = store
        self.health_interval = health_interval

    def record(self, kind, metadata, data=None, payload=None):
        with self.store.transaction():
            return self.store.append(metadata.get("session_id", "system"), kind, data, metadata, payload)

    def request_reconcile(self):
        with self.store.transaction():
            state = self.store.runtime()
            if state.get("pending"):
                return state
            self.store.append("sandbox", "ContainerReconcileRequested", {"reason": "scheduled-health-check"})
            return self.store.runtime()

    def complete_reconcile(self, command):
        request_id = command.get("request_id")
        if not isinstance(request_id, str) or command.get("status") not in ("healthy", "starting", "failed"):
            raise ValueError("request_id and a valid status are required")
        if not isinstance(command.get("actions", []), list) or len(str(command)) > 32768:
            raise ValueError("Invalid reconciliation result")
        with self.store.transaction():
            state = self.store.runtime()
            if state.get("request_id") != request_id:
                raise ValueError("Stale reconciliation result")
            if not state.get("pending"):
                return state  # Retry of the same outcome is idempotent.
            failures = state.get("failures", 0) + 1 if command["status"] == "failed" else 0
            delay = min(300, 5 * 2 ** min(failures, 6)) if failures else self.health_interval
            if command["status"] == "starting":
                delay = 5
            data = {k: command[k] for k in ("status", "container_id", "health", "actions", "error") if k in command}
            data.update(request_id=request_id, failures=failures, next_check=time.time() + delay)
            self.store.append("sandbox", "ContainerReconcileCompleted", data, event_id=request_id + ":result")
            return self.store.runtime()

    def recover_sessions(self):
        with self.store.transaction():
            for row in self.store.db.execute("SELECT * FROM sessions WHERE status='open'").fetchall():
                meta = {"session_id": row["id"], "protocol": row["protocol"], "ip": row["ip"],
                        "mac": row["mac"], "source_port": row["source_port"], "destination_port": row["destination_port"]}
                self.store.append(row["id"], "ConnectionClosed", {"reason": "collector-restarted", "end_time_unknown": True}, meta)
