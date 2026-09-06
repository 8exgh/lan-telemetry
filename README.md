# LAN Observatory

A LAN honeypot with four TCP listeners in **one collector process**, a CQRS/event-sourced SQLite store, a Docker maintenance processor, and an authenticated Next.js dashboard.

| Default port | Service | Behavior |
| --- | --- | --- |
| `9000` | TCP catch-all | Accepts connections, sends `OK\r\n`, records arbitrary binary input and output. |
| `2222` | Open SSH | Real SSH protocol; accepts `none` authentication for any username. Opens a shell or executes a command inside the sandbox. |
| `2223` | Password SSH | Records authentication attempts; accepts the literal password `password` for any username. Uses the same sandbox. |
| `8080` | Web decoy | Linked intranet pages, forms, files, status, administration and backup pages. Records requests, headers, bodies, trailers and responses. |
| `3000` | Dashboard | Sign in as `admin` with `ADMIN_PASSWORD` from `.env`. |
| `9100` | CQRS API | Loopback only by default. HTTP Basic authentication; separate processor and dashboard identities. |

The SSH services terminate SSH in the collector; they do not expose a container SSH daemon. The Docker container contains Alpine and BusyBox. It has no network access, no host bind mounts, a read-only root filesystem, a non-root user, dropped capabilities, and CPU, memory, PID and tmpfs limits. File changes in `/home/guest` and `/tmp` are ephemeral. Forwarding, SFTP, agent forwarding, X11 and client environment changes are refused and recorded. Both SSH listeners accept shell and exec requests, with one channel per connection.

## Run on your Linux LAN host

Requires Python 3.10+, Node.js 22+, npm, Docker Engine supporting API v1.45, and `iproute2`. The account running the collector and processor must be able to access the local Docker socket. Run these processes on the host so observed IPs and neighbor-table MAC addresses refer to your LAN devices.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
npm ci --prefix nextjs-app

# Only needed when .env does not already exist:
python3 scripts/configure.py

docker build -t lan-telemetry-sandbox:local sandbox
npm run build --prefix nextjs-app
.venv/bin/python scripts/run.py
```

Open `http://<your-LAN-IP>:3000`. Username: **admin**. Password: the generated `ADMIN_PASSWORD` in `.env`. A unique `.env` has already been generated in this workspace; it is ignored by Git and has mode `0600`. On a fresh checkout, `configure.py` generates it. The decoy SSH password is deliberately `password`; the dashboard password is separate.

`scripts/run.py` supervises the collector, processor and Next.js as a group. If one exits, it stops the others. All four decoy ports are owned by the collector's PID. The worker creates the sandbox on its first cycle, checks health periodically, starts a stopped container and restarts an unhealthy one. It records failures and retries with backoff. Build the image first: the worker intentionally does not pull images or run builds.

Set `HONEYPOT_HOST` to a specific LAN address to restrict the decoy listeners to that interface. The default is all IPv4 interfaces. On Linux, `::` enables an IPv6 listener and follows the host's IPv4-mapped socket policy. Keep inbound access limited to your LAN; there is no need for router port forwarding. For HTTPS dashboard access, put the dashboard behind your reverse proxy and set `COOKIE_SECURE=true`. Basic authentication and dashboard sessions otherwise travel over your local HTTP connection.

### Try the sensors

```bash
printf 'hello\000binary\377\n' | nc <LAN-IP> 9000
ssh -p 2222 -o PreferredAuthentications=none guest@<LAN-IP>
ssh -p 2223 -o PreferredAuthentications=password -o PubkeyAuthentication=no guest@<LAN-IP>
# Enter password when prompted on port 2223.
curl -v http://<LAN-IP>:8080/
curl -v -d 'username=probe&password=test' http://<LAN-IP>:8080/login
```

The two SSH ports have their own host/port entries in `known_hosts`. Their shared generated host key persists in `data/ssh_host_rsa_key`.

### Run components separately

Run from the repository root:

```bash
.venv/bin/python -m telemetry.main
.venv/bin/python -m telemetry.processor
npm run dev --prefix nextjs-app
```

These are three separate terminal commands. For a service at boot, adapt [docs/lan-telemetry.service](docs/lan-telemetry.service) to your user and installation path, then install it with systemd. The service template has not been installed automatically.

## Capture and storage

All observations live in `data/events.sqlite3`, including binary payloads as SQLite BLOBs. There are no container-side session log files to tamper with. Events include a global sequence, UUID, aggregate version, UTC timestamp with microsecond formatting, metadata, payload digest, and chained event hash. Session events include source IP/port, destination IP/port, address family, protocol, session ID and available neighbor information. The database, host key and directory are private to the service account.

Capture layers:

* **TCP:** bytes read from and written to the socket, preserving binary contents and per-direction stream offsets. This includes invalid HTTP, incomplete requests, pre-SSH banners, and SSH ciphertext.
* **SSH messages:** decoded SSH message bytes before field parsing, including authentication messages and unsupported requests. These supplement transport capture and preserve authentication bytes even when they cannot be decoded as text.
* **Terminal:** stdin, stdout, stderr, requested command bytes, PTY settings, resize requests and session exit information. PTY stdout/stderr share a terminal stream; without a PTY they are separate.
* **HTTP:** request line, method, original target/query string, duplicate headers in order, request body chunks, chunked trailers, response status and exact wire bytes. The pages are deliberately separate from dashboard authentication.

The dashboard polls every three seconds and supports IP/protocol filtering, session selection, paginated events, complete metadata, text/hex payload previews and exact binary downloads. Payloads render as text, so content received from probes cannot become dashboard HTML.

### What “every byte” means here

This captures application-visible TCP streams. It is not a packet capture: Ethernet/IP/TCP headers, SYN-only scans, retransmissions, packets rejected by the OS, and unread bytes after a connection is closed are outside this capture. Outbound bytes mean accepted by the local kernel, not acknowledged by the remote peer. Successful incoming reads are committed before they reach the protocol parser. There is an unavoidable write-to-event gap for outgoing kernel writes if the process or disk fails at that instant.

MAC addresses are **best effort**, using passive `ip -j neigh` or `/proc/net/arp` lookup on the host. They can be absent on loopback, on routed connections, before neighbor discovery, or in a container/VM network. They are observations, not verified device identities. Missing MACs are stored as null with `mac_source=unavailable`; a gateway's MAC is not substituted. Tables refresh every five seconds, and later events may have a MAC that earlier events lacked. HTTP forwarding headers are recorded but never trusted as the peer IP.

Terminal capture covers interaction through SSH. It is not a kernel audit of every filesystem operation or detached background process. The sandbox is shared across sessions; clients can observe changes made by another sandbox session. An exec is given a container-side timeout; disconnects close its I/O, but detached descendants can survive until the container is restarted. Container resource limits and health recovery bound their effect. Nothing from the honeypot session is executed by a host shell.

### Limits and retention

| Setting | Default | Effect |
| --- | --- | --- |
| `MAX_CONNECTIONS` | 128 | Global concurrent decoy connections; excess connections get rejection events and are closed. |
| `MAX_SESSION_BYTES` | 64 MiB | Sum of stored payload bytes across capture layers, including duplicated decoded data. The triggering chunk is retained, a limit event is written, then the connection closes. |
| `SESSION_SECONDS` | 1800 | Absolute connection and sandbox exec duration. |
| `IDLE_SECONDS` | 120 | TCP/HTTP idle and SSH channel-request wait; SSH handshakes/auth have additional bounded waits. Established SSH sessions retain the absolute duration bound. |
| `MIN_FREE_BYTES` | 256 MiB | Reserve checked at acceptance and on captured payloads; low space closes sessions with a limit event. |
| `HEALTH_INTERVAL_SECONDS` | 30 | Successful Docker health-check interval; failures back off up to five minutes. |

There is **no automatic deletion** of events. Monitor disk usage and archive databases as needed. The reserve is not a disk quota and metadata-only events also consume space. On event persistence failure, the collector stops. After restart, previously open sessions receive a recovery closure event whose actual disconnect time is marked unknown. Credentials supplied to the decoy are intentionally stored in full; access to the event database is access to those credentials.

Stop the service before copying the data directory or rebuilding projections. A stopped copy of the entire directory preserves the SQLite database and any WAL files. For an online backup, use SQLite's backup API; do not copy only the main database file while it is open.

```bash
# Collector must be stopped. These operations take the collector lock.
.venv/bin/python -m telemetry.main --verify
.venv/bin/python -m telemetry.main --replay
```

The hash chain detects inconsistent modification when checked against a trusted prior head hash. It is not an external signature: someone with full write access can rewrite the database and recompute the chain. Projection rebuilds leave the original events unchanged.

## CQRS and Event Modeling

The structure follows the command/event/replay/processor separation in `~/8Examples/inventory-shopify`, including its `nextjs-app/lib/commands/event-replay.ts`, command handlers, and background processor API client. See [the event model](docs/event-model.md) for the flows, contracts and consistency boundaries.

The collector owns the event store. Protocol adapters call local command handlers. Commands append facts and synchronously update rebuildable read models in a SQLite transaction; they do not call Docker. The processor queries pending work, calls Docker, and posts its outcome back through commands using HTTP Basic authentication. It never opens the database. Next.js reads through query endpoints with a separate read-only identity.

| Method | Endpoint | Identity |
| --- | --- | --- |
| GET | `/api/queries/summary` | `dashboard` or `processor` |
| GET | `/api/queries/sessions?protocol=raw&ip=192.168.1.10&limit=100` | `dashboard` or `processor` |
| GET | `/api/queries/events?session=<id>&before=<seq>&after=0&kind=<type>&protocol=raw&ip=<ip>&limit=100` | `dashboard` or `processor` |
| GET | `/api/queries/payload/<seq>` | `dashboard` or `processor`; binary response |
| GET | `/api/queries/container-work` | `dashboard` or `processor` |
| POST | `/api/commands/request-container-reconcile` with `{}` | `processor` only |
| POST | `/api/commands/record-container-reconciled` | `processor` only |

`PROCESSOR_PASSWORD` and `QUERY_PASSWORD` are generated independently. The browser receives neither. Next.js proxies only an allowlist of query endpoints after validating a signed, expiring HttpOnly session cookie. Dashboard login is `admin/ADMIN_PASSWORD`; it has origin checking and a ten-failed-attempts-per-minute limit per Next.js process.

The processor completion body contains `request_id`, `status` (`healthy`, `starting`, `failed`), and optional `container_id`, `health`, `actions`, and `error`. Repeated completions for the current request are idempotent; stale request IDs are rejected. A pending request remains pending across crashes. Reconciliation adopts only the application's labeled container with the expected isolation configuration; a conflicting name/configuration produces a failure event rather than changing another container.

## Verification

```bash
.venv/bin/python -m unittest discover -s tests -v
npm test --prefix nextjs-app
npm run typecheck --prefix nextjs-app
npm run build --prefix nextjs-app

# Full integration on a host with Docker and TCP sockets:
docker build -t lan-telemetry-sandbox:local sandbox
.venv/bin/python scripts/smoke.py
```

The smoke test uses a unique disposable container and temporary event database. It checks both SSH auth modes, real Docker exec and PTY, HTTP, raw TCP, recovery after stopping the container, replay and event hashes, then removes its own test container. CI runs these checks on Ubuntu.

In the initial restricted workspace, the eleven backend checks and three dashboard authentication checks passed, along with TypeScript and the production build. Backend protocol checks ran against real Paramiko/HTTP parsers over in-memory byte streams using the preinstalled Paramiko 2.12; deployment requirements use Paramiko 3.5.1–4.x. OS sockets and Docker were blocked, so live TCP/Docker and browser runtime validation still need the host-side checks above. No LAN services have been left running by setup.

Implementation references: [Paramiko server API](https://docs.paramiko.org/en/stable/api/server.html), [Docker exec API](https://docs.docker.com/reference/api/engine/version/v1.45/#tag/Exec), [Docker container constraints](https://docs.docker.com/reference/cli/docker/container/run/).
