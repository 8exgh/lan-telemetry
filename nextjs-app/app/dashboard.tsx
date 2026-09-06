"use client";
import { useEffect, useState } from "react";

type Session = {
  id: string;
  protocol: string;
  ip: string;
  mac: string | null;
  source_port: number;
  destination_port: number;
  started_at: string;
  last_at: string;
  status: string;
  wire_in: number;
  wire_out: number;
  events: number;
  username: string | null;
};
type Event = {
  seq: number;
  type: string;
  at: string;
  stream: string;
  hash: string;
  payload_sha256: string;
  byte_length: number | null;
  metadata: Record<string, unknown>;
  data: Record<string, unknown>;
};
type Summary = {
  connections: number;
  devices: number;
  bytes: number;
  active: number;
  events: number;
  protocols: { protocol: string; connections: number }[];
  timeline: { hour: string; connections: number }[];
  container: {
    status: string;
    checked_at?: string;
    error?: string;
    actions?: string[];
    pending?: boolean;
  };
  email?: {
    enabled: boolean;
    configuration: string;
    blocked: boolean;
    blocked_reason?: string;
    batch_seconds: number;
    accepted: number;
    pending: number;
    failed: number;
    latest?: { status: string; last_error?: string; accepted_at?: string };
  };
};
const names: Record<string, string> = {
  raw: "TCP catch-all",
  "ssh-open": "SSH · open",
  "ssh-password": "SSH · password",
  http: "Web decoy",
};
const formatBytes = (n: number) =>
  n < 1024
    ? `${n} B`
    : n < 1048576
      ? `${(n / 1024).toFixed(1)} KB`
      : `${(n / 1048576).toFixed(1)} MB`;
const when = (at: string) =>
  new Date(at).toLocaleTimeString([], { hour12: false });
const label = (event: Event) =>
  event.type === "HttpRequestReceived"
    ? `${event.data.method} ${event.data.target}`
    : event.type === "AuthenticationAttempted"
      ? `${event.data.username} · ${event.data.method} · ${event.data.accepted ? "accepted" : "rejected"}`
      : event.type === "BytesCaptured" || event.type === "TerminalBytesCaptured"
        ? `${event.data.direction === "in" ? "Received" : "Sent"} ${formatBytes(event.byte_length || 0)} · ${event.data.layer}`
        : String(
            event.data.reason || event.data.status || event.data.error || "",
          );

async function query<T>(path: string): Promise<T> {
  const response = await fetch(`/api/telemetry/${path}`, { cache: "no-store" });
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Session expired");
  }
  if (!response.ok)
    throw new Error("Collector unavailable. Check the collector service.");
  return response.json();
}

export default function Dashboard() {
  const [summary, setSummary] = useState<Summary>();
  const [sessions, setSessions] = useState<Session[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [protocol, setProtocol] = useState("");
  const [ip, setIp] = useState("");
  const [session, setSession] = useState("");
  const [selected, setSelected] = useState<Event>();
  const [before, setBefore] = useState<number>();
  const [paused, setPaused] = useState(false);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState("");

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const refresh = async () => {
      try {
        const filter = new URLSearchParams({
          ...(protocol ? { protocol } : {}),
          ...(ip ? { ip } : {}),
        });
        const eventFilter = new URLSearchParams(filter);
        if (session) eventFilter.set("session", session);
        if (before) eventFilter.set("before", String(before));
        const results = await Promise.all([
          query<Summary>("summary"),
          query<Session[]>(`sessions?${filter}`),
          query<Event[]>(`events?${eventFilter}`),
        ]);
        if (alive) {
          setSummary(results[0]);
          setSessions(results[1]);
          setEvents(results[2]);
          setError("");
          setUpdated(new Date().toLocaleTimeString([], { hour12: false }));
        }
      } catch (e) {
        if (alive) setError((e as Error).message);
      }
      if (alive && !paused) timer = setTimeout(refresh, 3000);
    };
    refresh();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [protocol, ip, session, before, paused]);

  const chart = Array.from({ length: 24 }, (_, i) => {
    const date = new Date(Date.now() - (23 - i) * 3600000);
    const hour = date.toISOString().slice(0, 13);
    return {
      hour,
      count: summary?.timeline.find((t) => t.hour === hour)?.connections || 0,
    };
  });
  const maximum = Math.max(1, ...chart.map((c) => c.count));

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="/">
          <span className="brand-mark">◉</span>
          <span>
            LAN
            <br />
            <strong>Observatory</strong>
          </span>
        </a>
        <p className="nav-label">WORKSPACE</p>
        <nav>
          <a className="nav-active" href="#overview">
            <span>▦</span> Overview
          </a>
          <a href="#sessions">
            <span>⌁</span> Connections{" "}
            <small>{summary?.connections ?? "—"}</small>
          </a>
          <a href="#events">
            <span>≡</span> Event stream
          </a>
        </nav>
        <div className="sidebar-bottom">
          <span className="local-icon">⌂</span>
          <div>
            <strong>Local network</strong>
            <small>Private observatory</small>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <span>
            Workspace <span className="slash">/</span> <strong>Overview</strong>
          </span>
          <div className="account">
            <span className="avatar">A</span>
            <span>Administrator</span>
            <form action="/api/logout" method="post">
              <button className="text-button">Sign out ↗</button>
            </form>
          </div>
        </header>
        <main className="dashboard" id="overview">
          <div className="page-heading">
            <div>
              <p className="eyebrow">NETWORK INTELLIGENCE</p>
              <h1>A little more visibility.</h1>
              <p className="muted">
                Every connection leaves a trace. See what’s happening on your
                LAN.
              </p>
            </div>
            <button
              className={`live-pill ${error ? "offline" : ""}`}
              onClick={() => setPaused(!paused)}
            >
              <span className="status-dot" />
              {paused
                ? "Updates paused"
                : error
                  ? "Collector offline"
                  : "Live updates"}
              <span>{paused ? "▶" : "Ⅱ"}</span>
            </button>
          </div>
          {error && (
            <div className="error-banner" role="alert">
              {error}
            </div>
          )}
          <section className="metrics" aria-label="Lifetime totals">
            {[
              ["Connections", summary?.connections, "Across all sensors", "⌁"],
              [
                "Unique addresses",
                summary?.devices,
                "Observed source IPs",
                "◎",
              ],
              [
                "Captured traffic",
                summary ? formatBytes(summary.bytes) : undefined,
                "Inbound + outbound TCP bytes",
                "⇄",
              ],
              [
                "Recorded events",
                summary?.events,
                `${summary?.active ?? 0} connections active`,
                "≡",
              ],
            ].map(([title, value, note, icon]) => (
              <article className="metric" key={String(title)}>
                <div>
                  <span>{title}</span>
                  <span className="metric-icon">{icon}</span>
                </div>
                <strong>
                  {value === undefined
                    ? "—"
                    : typeof value === "number"
                      ? value.toLocaleString()
                      : value}
                </strong>
                <small>{note}</small>
              </article>
            ))}
          </section>
          <div className="overview-grid">
            <section className="panel activity-panel">
              <div className="panel-heading">
                <div>
                  <h2>Connection activity</h2>
                  <p>New connections over the last 24 hours</p>
                </div>
                <span className="subtle-badge">24 hours</span>
              </div>
              <div
                className="chart"
                role="img"
                aria-label={`Hourly connections for the last 24 hours; ${chart.reduce((a, b) => a + b.count, 0)} total`}
              >
                <div className="chart-grid">
                  <span>{maximum}</span>
                  <span>{Math.floor(maximum / 2)}</span>
                  <span>0</span>
                </div>
                <div className="bars">
                  {chart.map((c) => (
                    <div
                      key={c.hour}
                      className="bar-slot"
                      title={`${new Date(c.hour + ":00:00Z").toLocaleString()}: ${c.count} connections`}
                    >
                      <div
                        className={c.count ? "bar" : "bar zero"}
                        style={{
                          height: `${Math.max(2, (c.count / maximum) * 100)}%`,
                        }}
                      />
                    </div>
                  ))}
                </div>
              </div>
              <div className="chart-labels">
                <span>24 hours ago</span>
                <span>12 hours ago</span>
                <span>Now</span>
              </div>
            </section>
            <section className="panel sensors-panel">
              <div className="panel-heading">
                <div>
                  <h2>Listening posts</h2>
                  <p>Four ways to observe activity</p>
                </div>
                <span className="sensor-count">04</span>
              </div>
              {Object.entries(names).map(([key, name], i) => (
                <button
                  className="sensor"
                  key={key}
                  onClick={() => {
                    setProtocol(protocol === key ? "" : key);
                    setSession("");
                    setBefore(undefined);
                  }}
                >
                  <span className={`protocol-icon ${key}`}>
                    {["↳", ">_", "⌘", "⊞"][i]}
                  </span>
                  <div>
                    <strong>{name}</strong>
                    <small>
                      {
                        [
                          "Accept & record every byte",
                          "Passwordless container shell",
                          "Password authentication",
                          "Linked intranet pages",
                        ][i]
                      }
                    </small>
                  </div>
                  <span className="sensor-value">
                    {summary?.protocols.find((p) => p.protocol === key)
                      ?.connections ?? 0}
                    <small>connections</small>
                  </span>
                </button>
              ))}
            </section>
          </div>
          <section className="sandbox-status">
            <span
              className={`status-dot ${summary?.container.status === "healthy" ? "" : "amber"}`}
            />
            <strong>Shell sandbox</strong>
            <span className="subtle-badge">
              {summary?.container.status || "unknown"}
            </span>
            <span className="muted">
              {summary?.container.error ||
                (summary?.container.checked_at
                  ? `Last checked ${when(summary.container.checked_at)} · No network access`
                  : "Waiting for the background processor")}
            </span>
            {summary?.container.pending && <small>Check pending</small>}
          </section>
          <section className="sandbox-status" aria-label="Email notifications">
            <span
              className={`status-dot ${summary?.email?.enabled && !summary.email.blocked && !summary.email.latest?.last_error ? "" : "amber"}`}
            />
            <strong>Alerttray email</strong>
            <span className="subtle-badge">
              {!summary?.email?.enabled
                ? "Not configured"
                : summary.email.blocked
                  ? "Paused"
                  : summary.email.latest?.status === "retry"
                    ? "Retrying"
                    : summary.email.latest?.status === "failed"
                      ? "Needs attention"
                      : "Enabled"}
            </span>
            <span className="muted">
              {summary?.email?.blocked_reason ||
                (summary?.email?.configuration === "email-only-account-required"
                  ? "Confirm an Alerttray account with no registered iPhones in .env."
                  : !summary?.email?.enabled
                    ? "Set your Alerttray access token and email account settings in .env."
                    : summary.email.latest?.last_error ||
                      `Connection summaries · ${summary.email.batch_seconds}s interval · ${summary.email.accepted} accepted by Alerttray`)}
            </span>
            {!!summary?.email?.pending && (
              <small>{summary.email.pending} pending</small>
            )}
          </section>
          <section className="panel" id="sessions">
            <div className="panel-heading wrap">
              <div>
                <h2>Recent connections</h2>
                <p>Select a connection to inspect its events</p>
              </div>
              <div className="filters">
                <label className="sr-only" htmlFor="ip">
                  Source IP address
                </label>
                <input
                  id="ip"
                  placeholder="Filter by exact IP address"
                  value={ip}
                  onChange={(e) => {
                    setIp(e.target.value);
                    setSession("");
                    setBefore(undefined);
                  }}
                />
                <label className="sr-only" htmlFor="protocol">
                  Protocol
                </label>
                <select
                  id="protocol"
                  value={protocol}
                  onChange={(e) => {
                    setProtocol(e.target.value);
                    setSession("");
                    setBefore(undefined);
                  }}
                >
                  <option value="">All protocols</option>
                  {Object.entries(names).map(([key, name]) => (
                    <option key={key} value={key}>
                      {name}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Source device</th>
                    <th>Sensor</th>
                    <th>Time</th>
                    <th>Traffic</th>
                    <th>Events</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((s) => (
                    <tr
                      key={s.id}
                      className={session === s.id ? "selected-row" : ""}
                    >
                      <td>
                        <button
                          className="session-button"
                          onClick={() => {
                            setSession(session === s.id ? "" : s.id);
                            setBefore(undefined);
                            document
                              .getElementById("events")
                              ?.scrollIntoView({ behavior: "smooth" });
                          }}
                        >
                          <strong className="mono">
                            {s.ip}:{s.source_port}
                          </strong>
                          <small className="mono">
                            {s.mac || "MAC unavailable"}
                          </small>
                        </button>
                      </td>
                      <td>
                        <span className={`protocol-tag ${s.protocol}`}>
                          {names[s.protocol]}
                        </span>
                        <small className="cell-note">
                          Port {s.destination_port}
                          {s.username ? ` · ${s.username}` : ""}
                        </small>
                      </td>
                      <td className="mono">
                        {when(s.started_at)}
                        <small className="cell-note">
                          {new Date(s.started_at).toLocaleDateString()}
                        </small>
                      </td>
                      <td className="mono">
                        {formatBytes(s.wire_in + s.wire_out)}
                      </td>
                      <td className="mono">{s.events}</td>
                      <td>
                        <span className={`connection-status ${s.status}`}>
                          ● {s.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!sessions.length && (
              <div className="empty-state">
                <span>⌁</span>
                <h3>
                  {summary?.connections
                    ? "No matching connections"
                    : "Quiet is a signal, too."}
                </h3>
                <p>
                  {summary?.connections
                    ? "Try a different IP address or sensor filter."
                    : "New connections will appear here as devices discover your sensors."}
                </p>
              </div>
            )}
            <div className="panel-footer">
              Latest {sessions.length} matching connections{" "}
              <span>{updated ? `Updated ${updated}` : "Connecting…"}</span>
            </div>
          </section>
          <section className="panel events-panel" id="events">
            <div className="panel-heading wrap">
              <div>
                <h2>
                  Event stream{" "}
                  <span className="count-chip">{events.length}</span>
                </h2>
                <p>
                  {session
                    ? `Connection ${session}`
                    : "Immutable observations, in the order they arrived"}
                </p>
              </div>
              <div className="filters">
                {session && (
                  <button
                    onClick={() => {
                      setSession("");
                      setBefore(undefined);
                    }}
                  >
                    All connections ×
                  </button>
                )}
                {before && (
                  <button onClick={() => setBefore(undefined)}>
                    Back to latest ↑
                  </button>
                )}
              </div>
            </div>
            <div className={`events-grid ${selected ? "has-detail" : ""}`}>
              <div className="event-list">
                {events.map((event) => (
                  <button
                    key={event.seq}
                    className={`event-row ${selected?.seq === event.seq ? "selected-event" : ""}`}
                    onClick={() => setSelected(event)}
                  >
                    <span className="event-time mono">
                      {when(event.at)}
                      <small>#{event.seq}</small>
                    </span>
                    <span
                      className={`event-dot ${String(event.metadata.protocol || "system")}`}
                    />
                    <span className="event-description">
                      <strong>
                        {event.type.replace(/([a-z])([A-Z])/g, "$1 $2")}
                      </strong>
                      <small>
                        {label(event) ||
                          String(event.metadata.ip || "Background processor")}
                      </small>
                    </span>
                    <span className="event-source mono">
                      {String(event.metadata.ip || "system")}
                      <small>
                        {String(event.metadata.protocol || "container")}
                      </small>
                    </span>
                    <span className="event-arrow">↗</span>
                  </button>
                ))}
                {!events.length && (
                  <div className="empty-state">
                    <h3>No events in this view</h3>
                    <p>Observations appear here as they are recorded.</p>
                  </div>
                )}
              </div>
              {selected && (
                <EventDetail
                  key={selected.seq}
                  event={selected}
                  close={() => setSelected(undefined)}
                />
              )}
            </div>
            <div className="panel-footer">
              <span>Newest first · Full payloads available per event</span>
              <button
                disabled={events.length < 100}
                onClick={() => setBefore(events[events.length - 1]?.seq)}
              >
                Older events →
              </button>
            </div>
          </section>
          <footer className="page-footer">
            <span>
              LAN OBSERVATORY <span className="footer-dot">·</span> Local by
              design
            </span>
            <span>Timestamps shown in your browser’s timezone</span>
          </footer>
        </main>
      </div>
    </div>
  );
}

function EventDetail({ event, close }: { event: Event; close: () => void }) {
  const [payload, setPayload] = useState<Uint8Array>();
  const [mode, setMode] = useState("text");
  const [error, setError] = useState("");
  useEffect(() => {
    if (!event.byte_length) return;
    const controller = new AbortController();
    fetch(`/api/telemetry/payload/${event.seq}`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error("Unable to load payload");
        setPayload(new Uint8Array(await response.arrayBuffer()));
      })
      .catch((e) => {
        if (e.name !== "AbortError") setError(e.message);
      });
    return () => controller.abort();
  }, [event]);
  const preview = payload?.slice(0, 16384);
  const hex = preview
    ? Array.from({ length: Math.ceil(preview.length / 16) }, (_, i) => {
        const row = preview.slice(i * 16, i * 16 + 16);
        return `${(i * 16).toString(16).padStart(8, "0")}  ${Array.from(row)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(" ")
          .padEnd(47)}  ${Array.from(row)
          .map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "."))
          .join("")}`;
      }).join("\n")
    : "";
  return (
    <aside className="event-detail">
      <div className="detail-heading">
        <span className="eyebrow">EVENT #{event.seq}</span>
        <button onClick={close} aria-label="Close event details">
          ×
        </button>
      </div>
      <h3>{event.type}</h3>
      <p className="mono muted">{event.at}</p>
      <details open>
        <summary>Event metadata</summary>
        <pre>
          {JSON.stringify(
            {
              metadata: event.metadata,
              data: event.data,
              hash: event.hash,
              payload_sha256: event.payload_sha256,
            },
            null,
            2,
          )}
        </pre>
      </details>
      {!!event.byte_length && (
        <>
          <div className="payload-heading">
            <strong>{formatBytes(event.byte_length)} payload</strong>
            <a href={`/api/telemetry/payload/${event.seq}`} download>
              Download ↓
            </a>
          </div>
          <div className="segmented">
            <button
              className={mode === "text" ? "active" : ""}
              onClick={() => setMode("text")}
            >
              Text
            </button>
            <button
              className={mode === "hex" ? "active" : ""}
              onClick={() => setMode("hex")}
            >
              Hex
            </button>
          </div>
          <pre className="payload">
            {error ||
              (preview
                ? mode === "hex"
                  ? hex
                  : new TextDecoder().decode(preview)
                : "Loading bytes…")}
          </pre>
          {event.byte_length > 16384 && (
            <small className="muted">
              Preview shows the first 16 KiB. Download contains every stored
              byte.
            </small>
          )}
        </>
      )}
    </aside>
  );
}
