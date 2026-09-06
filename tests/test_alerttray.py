import base64
import http.client
import io
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from memory_socket import memory_pair
from telemetry.alerttray import Alerttray, AlerttrayError, NoRedirects, email_content
from telemetry.api import APIHandler
from telemetry.commands import Commands, EMAIL_LEASE_SECONDS
from telemetry.config import Config
from telemetry.processor import Processor
from telemetry.store import EventStore


class EmailWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.directory.name) / "events.db")
        self.commands = Commands(self.store)
        self.config = Config(alerttray_access_token="test-access-token-private", alerttray_email_only_account=True,
            alerttray_email="owner@example.test", alerttray_dashboard_url="http://192.168.1.10:3000",
            processor_password="processor-secret-is-long", query_password="dashboard-secret-is-long")
        self.now = 1000
        self.clock = patch("time.time", side_effect=lambda: self.now)
        self.clock.start()

    def tearDown(self):
        self.clock.stop()
        self.store.close()
        self.directory.cleanup()

    def connect(self, ip="192.168.1.20", protocol="raw"):
        session = str(uuid.uuid4())
        self.commands.record("ConnectionOpened", dict(session_id=session, ip=ip, mac="aa:bb:cc:dd:ee:ff",
            protocol=protocol, source_port=40000, destination_port=9000))
        return session

    def prepare(self):
        self.commands.configure_email(self.config)
        self.connect()
        self.now += 61
        self.assertTrue(self.commands.prepare_email()["queued"])
        return self.store.email_work()

    def claim(self, job):
        return self.commands.claim_email({"notification_id": job["id"], "attempt_id": str(uuid.uuid4())})["job"]

    def accepted(self, job):
        return dict(notification_id=job["id"], attempt_id=job["attempt_id"], outcome="accepted", provider_notification_id="provider-123", channels=["email"])

    def test_opt_in_new_connections_only_and_bounded_digest(self):
        self.connect("192.168.1.99")  # Historical traffic must not be backfilled.
        self.commands.configure_email(Config())
        self.assertEqual({"queued": False}, self.commands.prepare_email())
        self.commands.configure_email(self.config)
        for i in range(15):
            session = self.connect(f"192.168.1.{i+1}", "ssh-password")
            self.commands.record("AuthenticationAttempted", {"session_id": session}, {"password": "captured-secret", "username": "intruder"})
            self.commands.record("BytesCaptured", {"session_id": session}, {"direction": "in"}, b"captured-payload")
        self.assertFalse(self.commands.prepare_email()["queued"])
        self.now += 61
        self.commands.prepare_email()
        job = self.store.email_work()
        self.assertEqual(15, job["connections"])
        self.assertEqual(15, job["unique_ips"])
        self.assertEqual(10, len(job["samples"]))
        self.assertEqual("medium", job["request"]["severity"])
        self.assertEqual({"email": "owner@example.test"}, job["request"]["recipients"])
        serialized = json.dumps(job)
        for value in ("captured-secret", "captured-payload", "192.168.1.99", self.config.alerttray_access_token):
            self.assertNotIn(value, serialized)
        self.assertIn("MAC: aa:bb:cc:dd:ee:ff", job["request"]["message"])
        self.assertIn("http://192.168.1.10:3000/#sessions", job["request"]["message"])
        self.assertFalse(self.commands.prepare_email()["queued"])

    def test_acceptance_replay_and_duplicate_result_do_not_resend(self):
        job = self.claim(self.prepare())
        self.commands.complete_email(self.accepted(job))
        count = self.store.summary()["events"]
        self.commands.complete_email(self.accepted(job))
        self.assertEqual(count, self.store.summary()["events"])
        self.assertIsNone(self.store.email_work())
        snapshot = self.store.email_settings(), self.store.email_summary(), self.store.email_job(job["id"]), self.store.verify()
        self.store.catch_up(rebuild=True)
        self.assertEqual(snapshot, (self.store.email_settings(), self.store.email_summary(), self.store.email_job(job["id"]), self.store.verify()))
        self.assertFalse(self.commands.prepare_email()["queued"])
        self.assertIsNone(self.store.email_work())

    def test_bounded_retries_expired_lease_and_stale_results(self):
        job = self.claim(self.prepare())
        self.assertIsNone(self.store.email_work())
        old = job
        self.now += EMAIL_LEASE_SECONDS + 1
        self.assertFalse(self.commands.claim_email({"notification_id": job["id"], "attempt_id": str(uuid.uuid4())})["claimed"])
        self.assertEqual("retry", self.store.email_job(job["id"])["status"])
        self.assertIsNone(self.store.email_work())
        for attempt in range(2, 6):
            self.now += 301
            job = self.claim(self.store.email_work())
            self.assertEqual(attempt, job["attempts"])
            with self.assertRaises(ValueError):
                self.commands.complete_email(self.accepted(old))
            self.commands.complete_email({"notification_id": job["id"], "attempt_id": job["attempt_id"], "outcome": "failed", "error_code": "http-503", "error": "Alerttray unavailable", "retryable": True})
        self.assertEqual("failed", self.store.email_job(job["id"])["status"])
        self.assertIsNone(self.store.email_work())
        self.assertEqual(1, self.store.email_summary()["failed"])

    def test_routing_mismatch_pauses_new_work_and_configuration_can_recover(self):
        job = self.claim(self.prepare())
        self.commands.complete_email({"notification_id": job["id"], "attempt_id": job["attempt_id"], "outcome": "failed", "error_code": "unexpected-channels", "error": "Email alone was not queued"})
        self.connect()
        self.now += 61
        self.assertTrue(self.store.email_summary()["blocked"])
        self.assertFalse(self.commands.prepare_email()["queued"])
        self.commands.configure_email(self.config)  # Restart after correcting the account.
        self.assertTrue(self.commands.prepare_email()["queued"])

    def test_upgrade_reopen_and_disable_do_not_lose_pending_batches(self):
        self.connect()
        self.store.close()
        self.store = EventStore(Path(self.directory.name) / "events.db")
        self.commands = Commands(self.store)
        job = self.prepare()
        self.commands.configure_email(Config())
        self.assertIsNone(self.store.email_work())
        self.connect("192.168.1.77")
        self.commands.configure_email(self.config)
        self.assertEqual(job, self.store.email_work())
        self.commands.complete_email(self.accepted(self.claim(job)))
        self.now += 61
        self.assertFalse(self.commands.prepare_email()["queued"])

    def api(self, path, body=None, dashboard=False):
        client, connection = memory_pair()
        server = SimpleNamespace(config=self.config, commands=self.commands)
        def serve():
            try:
                APIHandler(connection, client.address, server)
            finally:
                connection.close()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        user, password = ("dashboard", self.config.query_password) if dashboard else ("processor", self.config.processor_password)
        credential = base64.b64encode(f"{user}:{password}".encode()).decode()
        raw = json.dumps(body).encode() if body is not None else b""
        request = f"{'POST' if body is not None else 'GET'} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Basic {credential}\r\nContent-Length: {len(raw)}\r\n\r\n"
        client.sendall(request.encode() + raw)
        response = http.client.HTTPResponse(client)
        response.begin()
        data = json.loads(response.read())
        status = response.status
        client.close()
        thread.join(2)
        if status != 200:
            raise ValueError(status)
        return data

    def test_worker_runs_email_when_docker_fails_and_requires_processor_auth(self):
        self.prepare()
        fake = Mock()
        fake.push.return_value = {"provider_notification_id": "provider-123", "channels": ["email"]}
        processor = Processor(self.config, alerttray=fake)
        processor.api = self.api
        processor.tick_container = Mock(side_effect=RuntimeError("Docker unavailable"))
        with self.assertRaisesRegex(RuntimeError, "Docker unavailable"):
            processor.tick()
        self.assertEqual(1, fake.push.call_count)
        self.assertEqual(1, self.store.email_summary()["accepted"])
        processor.tick_email()
        self.assertEqual(1, fake.push.call_count)
        with self.assertRaisesRegex(ValueError, "401"):
            self.api("/api/commands/prepare-email-notification", {}, dashboard=True)
        self.assertNotIn(self.config.alerttray_access_token, json.dumps(self.api("/api/queries/summary", dashboard=True)))

    def test_provider_failure_is_recorded_and_retried(self):
        self.prepare()
        fake = Mock()
        fake.push.side_effect = AlerttrayError("http-429", "Rate limited", True, 120)
        processor = Processor(self.config, alerttray=fake)
        processor.api = self.api
        processor.tick_email()
        summary = self.store.email_summary()
        self.assertEqual("retry", summary["latest"]["status"])
        self.assertEqual(self.now + 120, summary["latest"]["next_attempt"])
        processor.tick_email()
        self.assertEqual(1, fake.push.call_count)


class AlerttrayClientTests(unittest.TestCase):
    def setUp(self):
        self.config = Config(alerttray_access_token="private-token", alerttray_email_only_account=True)
        self.content = {"purposeId": "lan-telemetry-activity", "title": "Activity", "message": "Connection observed", "severity": "medium", "metadata": {}}

    def response(self, value):
        return io.BytesIO(json.dumps(value).encode())

    def test_exact_reference_contract_and_account_email_default(self):
        def open_request(request, timeout):
            self.assertEqual("https://alerttray.com/api/notifications/push", request.full_url)
            self.assertEqual("POST", request.method)
            self.assertEqual(self.config.alerttray_access_token, request.get_header("X-api-key"))
            self.assertEqual(10, timeout)
            self.assertEqual(self.content, json.loads(request.data))
            return self.response({"success": True, "notificationId": "accepted-1", "channels": ["email"], "skippedChannels": []})
        result = Alerttray(self.config, SimpleNamespace(open=open_request)).push(self.content)
        self.assertEqual({"provider_notification_id": "accepted-1", "channels": ["email"]}, result)

    def test_no_token_no_account_confirmation_and_non_email_severity_never_send(self):
        for config in (Config(), Config(alerttray_access_token="private-token")):
            opener = Mock()
            with self.assertRaises(AlerttrayError):
                Alerttray(config, opener).push(self.content)
            opener.open.assert_not_called()
        with self.assertRaises(AlerttrayError):
            Alerttray(self.config, Mock()).push({**self.content, "severity": "critical"})

    def test_http_errors_are_sanitized_and_redirects_never_forward_token(self):
        for status, retryable in ((401, False), (403, False), (302, False), (429, True), (503, True)):
            opener = Mock()
            opener.open.side_effect = urllib.error.HTTPError("https://alerttray.com", status, self.config.alerttray_access_token, {"Retry-After": "120"}, io.BytesIO(self.config.alerttray_access_token.encode()))
            with self.assertRaises(AlerttrayError) as caught:
                Alerttray(self.config, opener).push(self.content)
            self.assertEqual(retryable, caught.exception.retryable)
            self.assertNotIn(self.config.alerttray_access_token, str(caught.exception))
        request = urllib.request.Request("https://alerttray.com")
        self.assertIsNone(NoRedirects().redirect_request(request, None, 302, "Found", {}, "https://other.test"))

    def test_acceptance_requires_email_only_and_does_not_claim_delivery(self):
        for channels in (["email", "apns"], ["call", "sms"], []):
            opener = Mock()
            opener.open.return_value = self.response({"success": True, "notificationId": "id", "channels": channels})
            with self.assertRaises(AlerttrayError) as caught:
                Alerttray(self.config, opener).push(self.content)
            self.assertEqual("unexpected-channels", caught.exception.code)
            self.assertFalse(caught.exception.retryable)

    def test_configuration_rejects_token_leak_destinations_and_parses_false(self):
        for url in ("http://alerttray.com", "https://user:secret@alerttray.com", "https://alerttray.com?token=secret"):
            with self.assertRaises(ValueError):
                Config(alerttray_api_url=url).validate_alerttray()
        with patch.dict(os.environ, {"PROCESSOR_PASSWORD": "processor-secret-is-long", "QUERY_PASSWORD": "dashboard-secret-is-long", "ALERTTRAY_ACCESS_TOKEN": "private-token", "ALERTTRAY_EMAIL_ONLY_ACCOUNT": "false"}, clear=True), patch("telemetry.config.load_env"):
            self.assertFalse(Config.from_env().alerttray_enabled)
        self.assertNotIn(self.config.alerttray_access_token, repr(self.config))


if __name__ == "__main__":
    unittest.main()
