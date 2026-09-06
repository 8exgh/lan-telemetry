import { authenticated, queryCredentials } from "@/lib/auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
) {
  if (!(await authenticated()))
    return Response.json({ error: "Authentication required" }, { status: 401 });
  const { path } = await context.params;
  const name = path.join("/");
  if (!/^(summary|sessions|events|container-work|payload\/\d+)$/.test(name))
    return new Response(null, { status: 404 });
  const incoming = new URL(request.url);
  const url = new URL(
    `/api/queries/${name}`,
    process.env.API_URL || "http://127.0.0.1:9100",
  );
  for (const key of [
    "before",
    "after",
    "session",
    "kind",
    "limit",
    "protocol",
    "ip",
  ]) {
    const value = incoming.searchParams.get(key);
    if (value !== null) url.searchParams.set(key, value);
  }
  try {
    const result = await fetch(url, {
      cache: "no-store",
      headers: { Authorization: queryCredentials() },
      signal: AbortSignal.timeout(10_000),
    });
    const headers = new Headers({
      "Content-Type": result.headers.get("content-type") || "application/json",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    });
    if (name.startsWith("payload/"))
      headers.set(
        "Content-Disposition",
        `attachment; filename="event-${path[1]}.bin"`,
      );
    return new Response(result.body, { status: result.status, headers });
  } catch {
    return Response.json(
      { error: "Collector unavailable. Check the collector service." },
      { status: 503 },
    );
  }
}
