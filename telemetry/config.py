import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


def load_env(path=".env"):
    if Path(path).exists():
        for line in Path(path).read_text().splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())


@dataclass
class Config:
    host: str = "0.0.0.0"
    raw_port: int = 9000
    ssh_open_port: int = 2222
    ssh_password_port: int = 2223
    web_port: int = 8080
    api_host: str = "127.0.0.1"
    api_port: int = 9100
    data_dir: str = "./data"
    processor_password: str = ""
    query_password: str = ""
    docker_socket: str = "/var/run/docker.sock"
    sandbox_image: str = "lan-telemetry-sandbox:local"
    sandbox_name: str = "lan-telemetry-sandbox"
    max_connections: int = 128
    max_session_bytes: int = 64 * 1024 * 1024
    session_seconds: int = 1800
    idle_seconds: int = 120
    min_free_bytes: int = 256 * 1024 * 1024
    health_interval_seconds: int = 30
    alerttray_access_token: str = field(default="", repr=False)
    alerttray_api_url: str = "https://alerttray.com"
    alerttray_email: str = ""
    alerttray_batch_seconds: int = 60
    alerttray_dashboard_url: str = ""
    # The reference API always adds APNS for registered iPhones. Its email
    # route is email-only only when this account has no registered devices.
    alerttray_email_only_account: bool = False

    @property
    def alerttray_enabled(self):
        return bool(self.alerttray_access_token and self.alerttray_email_only_account)

    def validate_alerttray(self):
        for key, schemes in (("alerttray_api_url", ("https",)), ("alerttray_dashboard_url", ("http", "https"))):
            value = getattr(self, key)
            if not value and key == "alerttray_dashboard_url":
                continue
            url = urlsplit(value)
            if url.scheme not in schemes or not url.hostname or url.username or url.password or url.query or url.fragment:
                raise ValueError(f"{key.upper()} must be an absolute {'/'.join(schemes)} URL without credentials, query or fragment")
        if self.alerttray_batch_seconds < 1:
            raise ValueError("ALERTTRAY_BATCH_SECONDS must be positive")
        if self.alerttray_email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", self.alerttray_email):
            raise ValueError("ALERTTRAY_EMAIL must be an email address or empty for the account default")
        if self.alerttray_access_token and (not self.alerttray_access_token.isascii() or any(c.isspace() or ord(c) < 32 for c in self.alerttray_access_token)):
            raise ValueError("ALERTTRAY_ACCESS_TOKEN contains invalid header characters")

    @classmethod
    def from_env(cls):
        load_env()
        config = cls()
        for key in cls.__dataclass_fields__:
            env = "HONEYPOT_HOST" if key == "host" else key.upper()
            if env in os.environ:
                if isinstance(getattr(config, key), bool):
                    value = os.environ[env].lower()
                    if value not in ("true", "false"):
                        raise ValueError(f"{env} must be true or false")
                    setattr(config, key, value == "true")
                else:
                    setattr(config, key, type(getattr(config, key))(os.environ[env]))
        config.validate_alerttray()
        for key in ("processor_password", "query_password"):
            if len(getattr(config, key)) < 20 or getattr(config, key).startswith("replace-"):
                raise ValueError(f"Set a unique {key.upper()} (20+ characters); run scripts/configure.py")
        if config.processor_password == config.query_password:
            raise ValueError("Processor and dashboard query passwords must differ")
        ports = [config.raw_port, config.ssh_open_port, config.ssh_password_port, config.web_port, config.api_port]
        if len(set(ports)) != len(ports) or any(not 1 <= p <= 65535 for p in ports):
            raise ValueError("All five listener/API ports must be distinct and between 1 and 65535")
        for key in ("max_connections", "max_session_bytes", "session_seconds", "idle_seconds", "health_interval_seconds"):
            if getattr(config, key) <= 0:
                raise ValueError(f"{key} must be positive")
        return config
