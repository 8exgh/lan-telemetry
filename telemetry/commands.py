import time
import uuid

from .alerttray import email_content


EMAIL_MAX_ATTEMPTS = 5
EMAIL_LEASE_SECONDS = 60


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

    def configure_email(self, config):
        config.validate_alerttray()
        settings = {
            "enabled": config.alerttray_enabled,
            "configuration": "ready" if config.alerttray_enabled else "token-required" if not config.alerttray_access_token else "email-only-account-required",
            "batch_seconds": config.alerttray_batch_seconds,
            "dashboard_url": config.alerttray_dashboard_url,
            "recipient": config.alerttray_email,
            "blocked": False, "blocked_reason": None,
        }
        with self.store.transaction():
            current = self.store.email_settings()
            if all(current.get(k) == v for k, v in settings.items()):
                return
            # Enable from the present: an existing installation's event history
            # must not turn into an unsolicited backlog of historical emails.
            if settings["enabled"] and not current["enabled"]:
                settings["cursor"] = self.store.db.execute("SELECT COALESCE(MAX(seq),0) FROM events").fetchone()[0]
                settings["next_batch"] = time.time() + settings["batch_seconds"]
            self.store.append("email-settings", "EmailNotificationsConfigured", settings)

    def prepare_email(self):
        with self.store.transaction():
            settings = self.store.email_settings()
            if not settings["enabled"] or settings["blocked"] or settings["next_batch"] > time.time():
                return {"queued": False}
            # One outstanding batch bounds email volume and absorbs scans while
            # an earlier notification is waiting for a retry.
            if self.store.db.execute("SELECT 1 FROM email_outbox WHERE status IN ('pending','sending','retry') LIMIT 1").fetchone():
                return {"queued": False}
            snapshot = self.store.connection_snapshot(settings["cursor"])
            if snapshot is None:
                return {"queued": False}
            now = time.time()
            notification_id = str(uuid.uuid4())
            data = {**snapshot, "queued_at": now, "next_batch": now + settings["batch_seconds"],
                    "request": email_content(snapshot, settings["dashboard_url"], settings["recipient"])}
            self.store.append("email:" + notification_id, "EmailNotificationRequested", data)
            return {"queued": True, "notification_id": notification_id}

    def claim_email(self, command):
        notification_id = command.get("notification_id")
        attempt_id = command.get("attempt_id")
        if not isinstance(notification_id, str) or not isinstance(attempt_id, str):
            raise ValueError("notification_id and attempt_id are required")
        uuid.UUID(attempt_id)
        with self.store.transaction():
            settings = self.store.email_settings()
            if not settings["enabled"] or settings["blocked"]:
                return {"claimed": False}
            job = self.store.email_job(notification_id)
            if not job:
                raise ValueError("Unknown notification")
            if job.get("attempt_id") == attempt_id:
                return {"claimed": job["status"] == "sending", "job": job}
            if job["status"] not in ("pending", "retry", "sending") or job["next_attempt"] > time.time():
                return {"claimed": False}
            if job["status"] == "sending":
                # A worker died or lost its reply. Record the uncertain attempt
                # before retrying; the external API does not deduplicate calls.
                self._fail_email(job, "lease-expired", "Worker did not record an outcome before its lease expired", True)
                return {"claimed": False}
            self.store.append("email:" + notification_id, "EmailNotificationAttemptStarted",
                {"attempt_id": attempt_id, "attempts": job["attempts"] + 1,
                 "next_attempt": time.time() + EMAIL_LEASE_SECONDS})
            return {"claimed": True, "job": self.store.email_job(notification_id)}

    def _fail_email(self, job, code, error, retryable, retry_after=0):
        retry = retryable and job["attempts"] < EMAIL_MAX_ATTEMPTS
        delay = max(min(300, 5 * 2 ** min(job["attempts"], 6)), retry_after)
        self.store.append("email:" + job["id"], "EmailNotificationFailed", {
            "attempt_id": job["attempt_id"], "error_code": code, "error": error,
            "status": "retry" if retry else "failed", "next_attempt": time.time() + delay if retry else 0,
        }, event_id=job["attempt_id"] + ":result")

    def complete_email(self, command):
        notification_id, attempt_id = command.get("notification_id"), command.get("attempt_id")
        if not isinstance(notification_id, str) or not isinstance(attempt_id, str) or command.get("outcome") not in ("accepted", "failed"):
            raise ValueError("notification_id, attempt_id and a valid outcome are required")
        with self.store.transaction():
            job = self.store.email_job(notification_id)
            if not job or job.get("attempt_id") != attempt_id:
                raise ValueError("Stale notification outcome")
            if self.store.db.execute("SELECT 1 FROM events WHERE id=?", (attempt_id + ":result",)).fetchone():
                return {"recorded": True}  # The API response may have been lost.
            if job["status"] != "sending":
                raise ValueError("Notification has no active attempt")
            if command["outcome"] == "accepted":
                provider_id = command.get("provider_notification_id")
                if not isinstance(provider_id, str) or not 1 <= len(provider_id) <= 128 or command.get("channels") != ["email"]:
                    raise ValueError("An email-only acceptance receipt is required")
                self.store.append("email:" + notification_id, "EmailNotificationAccepted", {
                    "attempt_id": attempt_id, "provider_notification_id": provider_id, "channels": ["email"],
                }, event_id=attempt_id + ":result")
            else:
                code, error = command.get("error_code"), command.get("error")
                retryable, retry_after = command.get("retryable", False), command.get("retry_after", 0)
                if not isinstance(code, str) or not 1 <= len(code) <= 80 or not isinstance(error, str) or not 1 <= len(error) <= 1024:
                    raise ValueError("A bounded error code and message are required")
                if not isinstance(retryable, bool) or not isinstance(retry_after, int) or not 0 <= retry_after <= 3600:
                    raise ValueError("Invalid retry options")
                self._fail_email(job, code, error, retryable, retry_after)
            return {"recorded": True}
