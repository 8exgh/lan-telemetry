"use client";
import { useState } from "react";

export default function Login() {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <main className="login">
      <div className="login-card">
        <span className="brand-mark">◉</span>
        <p className="eyebrow">LAN OBSERVATORY</p>
        <h1>
          Your network.
          <br />A closer look.
        </h1>
        <p className="muted">
          Sign in to inspect activity across your local sensors.
        </p>
        <form
          onSubmit={async (event) => {
            event.preventDefault();
            setBusy(true);
            setError("");
            const form = new FormData(event.currentTarget);
            try {
              const response = await fetch("/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(Object.fromEntries(form)),
              });
              const result = await response.json();
              if (response.ok) window.location.assign("/");
              else setError(result.error);
            } catch {
              setError("Unable to connect. Please try again.");
            } finally {
              setBusy(false);
            }
          }}
        >
          <label>
            Username
            <input
              name="username"
              autoComplete="username"
              defaultValue="admin"
              required
            />
          </label>
          <label>
            Password
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </label>
          <button className="primary" disabled={busy}>
            {busy ? "Signing in…" : "Sign in →"}
          </button>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </form>
        <small className="muted">
          Private access · Local network telemetry
        </small>
      </div>
      <div className="login-orbit" aria-hidden="true">
        <div />
        <div />
        <div />
        <span>◉</span>
      </div>
    </main>
  );
}
