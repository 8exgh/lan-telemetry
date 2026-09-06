import {
  createHmac,
  timingSafeEqual,
  createHash,
  randomBytes,
} from "node:crypto";
import { cookies } from "next/headers";

export const COOKIE = "lan_telemetry_session";
const AGE = 8 * 60 * 60;

function secret(name: string, minimum = 20) {
  const value = process.env[name];
  if (!value || value.length < minimum || value.startsWith("replace-"))
    throw new Error(`Configure ${name}; run scripts/configure.py`);
  return value;
}

function signature(value: string) {
  return createHmac("sha256", secret("SESSION_SECRET", 32))
    .update(value)
    .digest("base64url");
}

export function validPassword(username: string, password: string) {
  const hash = (value: string) => createHash("sha256").update(value).digest();
  return (
    timingSafeEqual(hash(username), hash("admin")) &&
    timingSafeEqual(hash(password), hash(secret("ADMIN_PASSWORD")))
  );
}

export function newSession() {
  const payload = Buffer.from(
    JSON.stringify({
      user: "admin",
      exp: Math.floor(Date.now() / 1000) + AGE,
      nonce: randomBytes(16).toString("hex"),
    }),
  ).toString("base64url");
  return `${payload}.${signature(payload)}`;
}

export async function authenticated() {
  const token = (await cookies()).get(COOKIE)?.value;
  if (
    !token ||
    token.length > 1024 ||
    !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(token)
  )
    return false;
  const [payload, sig, extra] = token.split(".");
  if (!payload || !sig || extra) return false;
  const expected = signature(payload);
  if (
    sig.length !== expected.length ||
    !timingSafeEqual(Buffer.from(sig), Buffer.from(expected))
  )
    return false;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    return (
      data.user === "admin" &&
      Number.isFinite(data.exp) &&
      data.exp > Date.now() / 1000
    );
  } catch {
    return false;
  }
}

export const cookieOptions = () => ({
  httpOnly: true,
  sameSite: "strict" as const,
  secure: process.env.COOKIE_SECURE === "true",
  path: "/",
  maxAge: AGE,
});

export function sameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (!origin || !host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

export function queryCredentials() {
  return (
    "Basic " +
    Buffer.from(`dashboard:${secret("QUERY_PASSWORD")}`).toString("base64")
  );
}
