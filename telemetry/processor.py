import base64
import fcntl
import json
import logging
import os
import signal
import threading
import time
import urllib.request
import uuid
from pathlib import Path

from .config import Config
from .docker import Docker
from .alerttray import Alerttray, AlerttrayError


class Processor:
    def __init__(self, config, docker=None, alerttray=None):
        self.config, self.docker = config, docker or Docker(config)
        self.alerttray = alerttray or Alerttray(config)
        self.base = os.environ.get("API_URL", f"http://127.0.0.1:{config.api_port}").rstrip("/")
        self.authorization = "Basic " + base64.b64encode(f"processor:{config.processor_password}".encode()).decode()

    def api(self, path, body=None):
        request = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": self.authorization, "Content-Type": "application/json"}, method="GET" if body is None else "POST")
        # Do not send internal credentials through a configured HTTP proxy.
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=20) as response:
            return json.load(response)

    def tick(self):
        # Each integration gets a cycle even when the other one fails.
        try:
            self.tick_container()
        finally:
            self.tick_email()

    def tick_container(self):
        state = self.api("/api/queries/container-work")
        if not state.get("pending"):
            if state.get("next_check", 0) > time.time():
                return
            state = self.api("/api/commands/request-container-reconcile", {})
        outcome = self.docker.reconcile()
        self.api("/api/commands/record-container-reconciled", {**outcome, "request_id": state["request_id"]})
        if outcome["status"] == "failed":
            logging.warning("Container reconciliation failed: %s", outcome.get("error"))

    def tick_email(self):
        if not self.config.alerttray_enabled:
            return
        self.api("/api/commands/prepare-email-notification", {})
        work = self.api("/api/queries/email-work")["job"]
        if not work:
            return
        attempt_id = str(uuid.uuid4())
        claim = self.api("/api/commands/claim-email-notification", {"notification_id": work["id"], "attempt_id": attempt_id})
        if not claim["claimed"]:
            return
        job = claim["job"]
        outcome = {"notification_id": job["id"], "attempt_id": attempt_id}
        try:
            outcome.update(outcome="accepted", **self.alerttray.push(job["request"]))
        except AlerttrayError as error:
            outcome.update(outcome="failed", error_code=error.code, error=str(error),
                           retryable=error.retryable, retry_after=error.retry_after)
        # An error recording this result must not call Alerttray again in this
        # cycle. Its recorded lease permits recovery by a later worker cycle.
        self.api("/api/commands/record-email-notification-result", outcome)


def main():
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = Config.from_env()
    Path(config.data_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
    lockfile = open(Path(config.data_dir) / "processor.lock", "a")
    fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    processor = Processor(config)
    while not stopped.is_set():
        try:
            processor.tick()
        except Exception:
            logging.exception("Processor cycle failed; pending work will be retried")
        stopped.wait(2)
    lockfile.close()


if __name__ == "__main__":
    main()
