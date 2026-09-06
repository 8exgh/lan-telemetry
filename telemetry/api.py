import base64
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class APIHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass

    def reply(self, status, body, binary=False):
        raw = body if binary else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream" if binary else "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if status == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="LAN telemetry"')
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self, command=False):
        config = self.server.config
        candidates = [("processor", config.processor_password)]
        if not command:
            candidates.append(("dashboard", config.query_password))
        given = self.headers.get("Authorization", "")
        return any(hmac.compare_digest(given.encode(), ("Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()).encode()) for user, password in candidates)

    def do_GET(self):
        if not self.authorized():
            self.reply(401, {"error": "Authentication required"})
            return
        url = urlsplit(self.path)
        params = {k: v[-1] for k, v in parse_qs(url.query).items()}
        store = self.server.commands.store
        try:
            if url.path == "/api/queries/summary":
                self.reply(200, store.summary())
            elif url.path == "/api/queries/sessions":
                self.reply(200, store.sessions(params.get("protocol"), params.get("ip"), int(params.get("limit", 100))))
            elif url.path == "/api/queries/events":
                self.reply(200, store.events(int(params["before"]) if params.get("before") else None, int(params.get("after", 0)), params.get("session"), params.get("kind"), int(params.get("limit", 100)), params.get("protocol"), params.get("ip")))
            elif url.path.startswith("/api/queries/payload/"):
                payload = store.payload(int(url.path.rsplit("/", 1)[-1]))
                self.reply(404, {"error": "Event not found"}) if payload is None else self.reply(200, payload, binary=True)
            elif url.path == "/api/queries/container-work":
                self.reply(200, store.runtime())
            else:
                self.reply(404, {"error": "Unknown query"})
        except (ValueError, TypeError):
            self.reply(400, {"error": "Invalid query parameters"})

    def do_POST(self):
        self.close_connection = True
        if not self.authorized(command=True):
            self.reply(401, {"error": "Processor authentication required"})
            return
        try:
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Chunked command bodies are unsupported")
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= 65536:
                self.reply(413, {"error": "Command body too large"})
                return
            command = json.loads(self.rfile.read(size)) if size else {}
            if not isinstance(command, dict):
                raise ValueError("Command must be an object")
            if self.path == "/api/commands/request-container-reconcile":
                result = self.server.commands.request_reconcile()
            elif self.path == "/api/commands/record-container-reconciled":
                result = self.server.commands.complete_reconcile(command)
            else:
                self.reply(404, {"error": "Unknown command"})
                return
            self.reply(200, result)
        except (ValueError, TypeError) as error:
            self.reply(400, {"error": str(error)})


def make_api(config, commands):
    server = ThreadingHTTPServer((config.api_host, config.api_port), APIHandler)
    server.daemon_threads = True
    server.config, server.commands = config, commands
    return server
