"""Alerttray's public API: X-API-Key, medium severity, email routing.

Reference: 8exgh/alerttray, nextjs_alerttray/app/api/notifications/push/route.ts.
The API provides queue acceptance, not a confirmation of SMTP delivery. It has
no channel override or idempotency support; see README for the account setup.
"""
import http.client
import json
import urllib.error
import urllib.request


class AlerttrayError(RuntimeError):
    def __init__(self, code, message, retryable=False, retry_after=0):
        self.code, self.retryable, self.retry_after = code, retryable, retry_after
        super().__init__(message)


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        # A redirect must never forward the access token to another destination.
        return None


def email_content(snapshot, dashboard_url="", recipient=""):
    count = snapshot["connections"]
    title = f"LAN Observatory: {count} new connection{'s' if count != 1 else ''}"
    lines = [
        f"Observed {count} connection(s) from {snapshot['unique_ips']} source IP address(es).",
        f"First observed: {snapshot['first_at']}",
        f"Last observed: {snapshot['last_at']}",
        "", "Connection sample:",
    ]
    for sample in snapshot["samples"]:
        lines.append(f"{sample['at']} | {sample['ip']}:{sample['source_port']} -> port {sample['destination_port']} ({sample['protocol']}) | MAC: {sample.get('mac') or 'unavailable'}")
    if count > len(snapshot["samples"]):
        lines.append(f"Plus {count - len(snapshot['samples'])} more connection(s); see the event history.")
    if dashboard_url:
        lines.extend(["", f"Activity dashboard: {dashboard_url.rstrip('/')}/#sessions"])
    lines.extend(["", "Captured credentials and byte payloads are available only in the authenticated dashboard."])
    request = {
        "purposeId": "lan-telemetry-activity", "title": title, "message": "\n".join(lines),
        "severity": "medium",  # high/critical would route to phone and SMS.
        "metadata": {"source": "lan-telemetry", "connections": count, "uniqueIPs": snapshot["unique_ips"],
                     "sourceFromSequence": snapshot["source_from_seq"], "sourceThroughSequence": snapshot["source_through_seq"]},
    }
    if recipient:
        request["recipients"] = {"email": recipient}
    return request


class Alerttray:
    def __init__(self, config, opener=None):
        self.config = config
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())

    def push(self, content):
        if not self.config.alerttray_enabled:
            raise AlerttrayError("not-configured", "Set an Alerttray token and confirm an account with no registered iPhones")
        self.config.validate_alerttray()
        if content.get("severity") != "medium":
            raise AlerttrayError("invalid-severity", "Email alerts require medium severity")
        # Explicit allowlist prevents an outbox record from adding API routing fields.
        payload = {key: content[key] for key in ("purposeId", "title", "message", "severity", "metadata", "recipients") if key in content}
        request = urllib.request.Request(
            self.config.alerttray_api_url.rstrip("/") + "/api/notifications/push",
            data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json", "X-API-Key": self.config.alerttray_access_token},
        )
        try:
            with self.opener.open(request, timeout=10) as response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise AlerttrayError("invalid-response", "Alerttray returned an oversized response", retryable=True)
                result = json.loads(raw)
        except urllib.error.HTTPError as error:
            retry_after = error.headers.get("Retry-After", "") if error.headers else ""
            delay = min(int(retry_after), 3600) if retry_after.isascii() and retry_after.isdigit() and len(retry_after) <= 8 else 0
            status = error.code
            error.close()
            raise AlerttrayError(f"http-{status}", f"Alerttray rejected the notification (HTTP {status})",
                                retryable=status in (408, 429) or status >= 500, retry_after=delay) from None
        except (OSError, urllib.error.URLError, http.client.HTTPException):
            raise AlerttrayError("connection-failed", "Could not reach Alerttray; the request may need retrying", retryable=True) from None
        except (ValueError, UnicodeError):
            raise AlerttrayError("invalid-response", "Alerttray returned an invalid response", retryable=True) from None
        # Never put provider response bodies or exceptions into events: they may
        # echo authentication headers. Only these bounded, checked fields leave here.
        if not isinstance(result, dict) or result.get("success") is not True:
            raise AlerttrayError("not-accepted", "Alerttray did not accept the notification", retryable=True)
        channels = result.get("channels")
        if channels != ["email"] or result.get("skippedChannels", []) != []:
            raise AlerttrayError("unexpected-channels", "Alerttray did not queue email alone. Check the account email and remove registered iPhones; then restart the collector.")
        notification_id = result.get("notificationId")
        if not isinstance(notification_id, str) or not 1 <= len(notification_id) <= 128:
            raise AlerttrayError("invalid-response", "Alerttray did not return a notification ID", retryable=True)
        return {"provider_notification_id": notification_id, "channels": ["email"]}
