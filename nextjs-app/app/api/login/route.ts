import { NextResponse } from "next/server";
import {
  COOKIE,
  cookieOptions,
  newSession,
  sameOrigin,
  validPassword,
} from "@/lib/auth";

export const runtime = "nodejs";
const attempts: number[] = [];

export async function POST(request: Request) {
  if (!sameOrigin(request))
    return NextResponse.json({ error: "Invalid origin" }, { status: 403 });
  if (Number(request.headers.get("content-length") || 0) > 4096)
    return new Response(null, { status: 413 });
  const now = Date.now();
  while (attempts.length && attempts[0] < now - 60_000) attempts.shift();
  if (attempts.length >= 10)
    return NextResponse.json(
      { error: "Too many attempts. Try again in one minute." },
      { status: 429 },
    );
  try {
    // Bound the body even if the client omitted Content-Length.
    const reader = request.body?.getReader();
    let raw = "",
      length = 0;
    const decoder = new TextDecoder();
    if (reader)
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > 4096) {
          await reader.cancel();
          return new Response(null, { status: 413 });
        }
        raw += decoder.decode(value, { stream: true });
      }
    raw += decoder.decode();
    const data = JSON.parse(raw);
    if (
      typeof data.username !== "string" ||
      typeof data.password !== "string" ||
      !validPassword(data.username, data.password)
    ) {
      attempts.push(now);
      return NextResponse.json(
        { error: "Incorrect username or password." },
        { status: 401 },
      );
    }
    const response = NextResponse.json({ ok: true });
    response.cookies.set(COOKIE, newSession(), cookieOptions());
    response.headers.set("Cache-Control", "no-store");
    return response;
  } catch {
    return NextResponse.json(
      { error: "Sign-in unavailable. Check server configuration." },
      { status: 400 },
    );
  }
}
