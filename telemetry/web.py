import html
import uuid
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit


PAGES = {
    "/": ("Office gateway", "Welcome to the internal service portal. Select a service below."),
    "/status": ("Service status", "File service: online · Backup service: online · Last maintenance: Sunday"),
    "/files": ("Shared files", '<a href="/files/readme.txt">README.txt</a> · <a href="/backup">Backups</a>'),
    "/backup": ("Backup console", '<a href="/backup/archive.zip">Download latest archive</a> · <a href="/admin">Manage backups</a>'),
    "/admin": ("Administration", '<form method="post" action="/login"><label>Username <input name="username"></label><label>Password <input type="password" name="password"></label><button>Sign in</button></form>'),
    "/login": ("Administration", "Account verification pending. Please contact your administrator."),
    "/devices": ("Connected devices", "fileserver · printer-office · backup-node"),
    "/help": ("Help", "Contact the local administrator for account access and file recovery."),
}


class DecoyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.24.0"
    sys_version = ""

    @property
    def capture(self):
        return self.connection.capture

    def log_message(self, *args):
        pass

    def handle_expect_100(self):
        self.send_response_only(100)
        self.end_headers()
        return True

    def body(self, request_id):
        total = 0

        def consume(size):
            nonlocal total
            while size:
                chunk = self.rfile.read(min(size, 32768))
                if not chunk:
                    raise ValueError("Incomplete request body")
                # Exact body is already present in wire events. Record parsed chunk boundaries too.
                self.capture.record("HttpBodyReceived", {"request_id": request_id, "offset": total, "length": len(chunk)}, chunk)
                total += len(chunk)
                size -= len(chunk)

        transfer = self.headers.get_all("Transfer-Encoding", [])
        lengths = self.headers.get_all("Content-Length", [])
        if transfer and lengths or len(lengths) > 1:
            raise ValueError("Ambiguous request framing")
        if transfer:
            if len(transfer) != 1 or transfer[0].lower().strip() != "chunked":
                raise ValueError("Unsupported transfer encoding")
            while True:
                line = self.rfile.readline(8193)
                if len(line) > 8192 or not line.endswith(b"\r\n"):
                    raise ValueError("Invalid chunk framing")
                size = int(line.split(b";", 1)[0].strip(), 16)
                if size < 0:
                    raise ValueError("Invalid chunk size")
                if not size:
                    trailers = []
                    while True:
                        line = self.rfile.readline(8193)
                        if not line or len(line) > 8192 or len(trailers) >= 100:
                            raise ValueError("Invalid trailers")
                        if line == b"\r\n":
                            break
                        trailers.append(line.decode("latin-1"))
                    if trailers:
                        self.capture.record("HttpTrailersReceived", {"request_id": request_id, "trailers": trailers})
                    break
                consume(size)
                if self.rfile.read(2) != b"\r\n":
                    raise ValueError("Invalid chunk delimiter")
        elif lengths:
            size = int(lengths[0])
            if size < 0:
                raise ValueError("Negative content length")
            consume(size)
        return total

    def respond(self):
        request_id = str(uuid.uuid4())
        self.capture.record("HttpRequestReceived", {"request_id": request_id, "method": self.command,
            "target": self.path, "http_version": self.request_version,
            "headers": list(self.headers.raw_items())}, self.raw_requestline)
        try:
            body_length = self.body(request_id)
            path = urlsplit(self.path).path
            status, content_type = 200, "text/html; charset=utf-8"
            if path == "/robots.txt":
                content_type, body = "text/plain", b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
            elif path == "/files/readme.txt":
                content_type, body = "text/plain", b"Internal shared documents. See /help for access.\n"
            elif path == "/backup/archive.zip":
                content_type, body = "application/zip", b"PK\x05\x06" + b"\0" * 18
            else:
                title, content = PAGES.get(path, ("Page not found", 'Return to the <a href="/">service portal</a>.'))
                if path not in PAGES:
                    status = 404
                links = " ".join(f'<a href="{url}">{html.escape(page[0])}</a>' for url, page in PAGES.items() if url != "/login")
                body = f'<!doctype html><html><head><meta charset="utf-8"><title>{title}</title><style>body{{font:16px sans-serif;max-width:850px;margin:60px auto;color:#25354a}}nav{{display:flex;gap:14px;flex-wrap:wrap}}label{{display:block;margin:14px 0}}a{{color:#2463a6}}</style></head><body><small>INTRANET / SERVICES</small><h1>{title}</h1><nav>{links}</nav><hr><section>{content}</section></body></html>'.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            self.capture.record("HttpResponseSent", {"request_id": request_id, "status": status, "body_length": len(body), "request_body_length": body_length})
        except (ValueError, OverflowError) as error:
            self.capture.record("HttpRequestMalformed", {"request_id": request_id, "error": str(error)})
            self.send_error(400)
            self.close_connection = True

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = respond

    def send_error(self, code, message=None, explain=None):
        self.capture.record("HttpProtocolError", {"status": code, "message": message})
        super().send_error(code, message, explain)
