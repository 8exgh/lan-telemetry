const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { createHmac } = require("node:crypto");
const Module = require("node:module");
const ts = require("typescript");

process.env.ADMIN_PASSWORD = "test-admin-password-with-32-characters";
process.env.SESSION_SECRET = "test-session-secret-with-at-least-32-characters";
process.env.QUERY_PASSWORD = "test-query-password-with-32-characters";
let cookie;
let auth;

function load(path) {
  const filename = resolve(__dirname, "..", path);
  const compiled = ts.transpileModule(readFileSync(filename, "utf8"), {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
  });
  const unit = new Module(filename, module);
  unit.paths = module.paths;
  const original = unit.require.bind(unit);
  unit.require = (name) =>
    name === "next/headers"
      ? {
          cookies: async () => ({
            get: () => (cookie ? { value: cookie } : undefined),
          }),
        }
      : name === "@/lib/auth"
        ? auth
        : original(name);
  unit._compile(compiled.outputText, filename);
  return unit.exports;
}

auth = load("lib/auth.ts");

test("sessions reject missing, malformed, expired and forged tokens", async () => {
  cookie = undefined;
  assert.equal(await auth.authenticated(), false);
  cookie = auth.newSession();
  assert.equal(await auth.authenticated(), true);
  assert.ok(!cookie.includes(process.env.ADMIN_PASSWORD));
  const valid = cookie;
  cookie = valid.slice(0, -1) + (valid.endsWith("a") ? "b" : "a");
  assert.equal(await auth.authenticated(), false);
  cookie = valid.split(".")[0] + "." + "é".repeat(43);
  assert.equal(await auth.authenticated(), false);
  const payload = Buffer.from(
    JSON.stringify({ user: "admin", exp: 0 }),
  ).toString("base64url");
  cookie =
    payload +
    "." +
    createHmac("sha256", process.env.SESSION_SECRET)
      .update(payload)
      .digest("base64url");
  assert.equal(await auth.authenticated(), false);
  cookie = undefined;
});

test("login checks origin and password, sets private cookie, and limits failures", async () => {
  const login = load("app/api/login/route.ts");
  const request = (password, origin = "http://observatory:3000") =>
    new Request("http://observatory:3000/api/login", {
      method: "POST",
      headers: {
        origin,
        host: "observatory:3000",
        "content-type": "application/json",
      },
      body: JSON.stringify({ username: "admin", password }),
    });
  assert.equal(
    (
      await login.POST(
        request(process.env.ADMIN_PASSWORD, "http://other.local"),
      )
    ).status,
    403,
  );
  assert.equal((await login.POST(request("bad"))).status, 401);
  const accepted = await login.POST(request(process.env.ADMIN_PASSWORD));
  assert.equal(accepted.status, 200);
  const setCookie = accepted.headers.get("set-cookie");
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=strict/i);
  assert.ok(!setCookie.includes(process.env.ADMIN_PASSWORD));
  for (let i = 0; i < 9; i++) await login.POST(request("bad"));
  assert.equal((await login.POST(request("bad"))).status, 429);
});

test("dashboard proxy requires a session and cannot invoke commands", async () => {
  const proxy = load("app/api/telemetry/[...path]/route.ts");
  cookie = undefined;
  assert.equal(
    (
      await proxy.GET(new Request("http://observatory/api/telemetry/events"), {
        params: Promise.resolve({ path: ["events"] }),
      })
    ).status,
    401,
  );
  cookie = auth.newSession();
  assert.equal(
    (
      await proxy.GET(
        new Request("http://observatory/api/telemetry/commands/x"),
        { params: Promise.resolve({ path: ["commands", "x"] }) },
      )
    ).status,
    404,
  );
  const originalFetch = global.fetch;
  try {
    global.fetch = async (url, options) => {
      assert.equal(new URL(url).pathname, "/api/queries/events");
      assert.match(options.headers.Authorization, /^Basic /);
      assert.equal(
        Buffer.from(
          options.headers.Authorization.slice(6),
          "base64",
        ).toString(),
        "dashboard:" + process.env.QUERY_PASSWORD,
      );
      return Response.json([]);
    };
    assert.equal(
      (
        await proxy.GET(
          new Request("http://observatory/api/telemetry/events"),
          { params: Promise.resolve({ path: ["events"] }) },
        )
      ).status,
      200,
    );
  } finally {
    global.fetch = originalFetch;
    cookie = undefined;
  }
});
