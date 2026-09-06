import os
from dataclasses import dataclass
from pathlib import Path


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

    @classmethod
    def from_env(cls):
        load_env()
        config = cls()
        for key in cls.__dataclass_fields__:
            env = "HONEYPOT_HOST" if key == "host" else key.upper()
            if env in os.environ:
                setattr(config, key, type(getattr(config, key))(os.environ[env]))
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
