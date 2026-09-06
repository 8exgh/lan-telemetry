#!/usr/bin/env python3
"""Run the collector, processor and production Next.js server as one supervised group."""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from telemetry.config import Config


def main():
    os.chdir(ROOT)
    config = Config.from_env()
    children = []
    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for command in ([sys.executable, "-m", "telemetry.main"], [sys.executable, "-m", "telemetry.processor"],
                        ["npm", "--prefix", "nextjs-app", "run", "start", "--", "--hostname", os.environ.get("DASHBOARD_HOST", "0.0.0.0"), "--port", os.environ.get("DASHBOARD_PORT", "3000")]):
            children.append(subprocess.Popen(command, start_new_session=True))
        while not stopped:
            if any(child.poll() is not None for child in children):
                raise RuntimeError("A service exited; stopping the service group")
            time.sleep(0.5)
    finally:
        for child in children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
        for child in children:
            try:
                child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)


if __name__ == "__main__":
    main()
