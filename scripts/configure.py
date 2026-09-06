#!/usr/bin/env python3
import os
import secrets
from pathlib import Path

root = Path(__file__).resolve().parents[1]
destination = root / ".env"
if destination.exists():
    raise SystemExit(".env already exists; edit it to change your settings.")
text = (root / ".env.example").read_text()
for value in ("replace-with-a-long-unique-password", "replace-with-at-least-32-random-characters", "replace-with-a-different-long-password", "replace-with-another-long-password"):
    text = text.replace(value, secrets.token_urlsafe(32))
fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as target:
    target.write(text)
print("Created .env with unique credentials. Dashboard login: admin / ADMIN_PASSWORD from .env")
