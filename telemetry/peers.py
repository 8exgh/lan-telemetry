import ipaddress
import json
import re
import subprocess
import threading
import time


class Neighbors:
    """Passive host-neighbor lookup only; never mistake a gateway MAC for a peer."""
    def __init__(self):
        self.entries = {}
        self.lock = threading.Lock()
        self.stopped = threading.Event()

    def refresh(self):
        entries = {}
        try:
            result = subprocess.run(["ip", "-j", "neigh", "show"], capture_output=True, timeout=2, check=True)
            for row in json.loads(result.stdout):
                if row.get("lladdr") and re.fullmatch(r"[0-9a-fA-F:]{17}", row["lladdr"]):
                    entries[row["dst"]] = {"mac": row["lladdr"], "interface": row.get("dev"), "neighbor_state": row.get("state"), "mac_source": "ip-neighbor", "mac_observed_at": time.time()}
        except (OSError, subprocess.SubprocessError, ValueError):
            try:
                with open("/proc/net/arp") as arp:
                    for line in arp.read().splitlines()[1:]:
                        fields = line.split()
                        if len(fields) >= 6 and int(fields[2], 16) & 2:
                            entries[fields[0]] = {"mac": fields[3], "interface": fields[5], "mac_source": "proc-arp", "mac_observed_at": time.time()}
            except OSError:
                pass
        with self.lock:
            self.entries = entries

    def lookup(self, ip):
        normalized = ip.split("%")[0]
        parsed = ipaddress.ip_address(normalized)
        if getattr(parsed, "ipv4_mapped", None):
            normalized = str(parsed.ipv4_mapped)
        with self.lock:
            return self.entries.get(normalized, {"mac": None, "mac_source": "unavailable"}).copy()

    def run(self):
        while not self.stopped.is_set():
            self.refresh()
            self.stopped.wait(5)
