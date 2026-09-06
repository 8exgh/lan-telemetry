import { NextResponse } from "next/server";
import { COOKIE, cookieOptions, sameOrigin } from "@/lib/auth";

export async function POST(request: Request) {
  if (!sameOrigin(request)) return new Response(null, { status: 403 });
  const response = new NextResponse(null, {
    status: 303,
    headers: { Location: "/login" },
  });
  response.cookies.set(COOKIE, "", { ...cookieOptions(), maxAge: 0 });
  return response;
}
