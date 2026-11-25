import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const ALLOWED_DASHBOARD_ENDPOINTS = new Set([
  "stats",
  "events",
  "timeline",
  "distribution",
  "protocols",
  "topology",
  "sessions",
  "simulate",
  "reset-demo",
  "seed-demo",
  "toggle-waf-mode",
  "arena",
]);

const ALLOWED_ARENA_SUBPATHS = new Set(["battle", "live", "history", "pentest"]);

/**
 * Next.js Server-Side BFF (Backend-For-Frontend) Proxy Route (SEC-PBL6-004)
 *
 * Securely proxies dashboard telemetry and administration requests to the WAF Gateway.
 * Server-side injects ADMIN_API_KEY as 'X-API-Key' header, completely eliminating
 * admin secret leakage in client-side JavaScript bundles.
 *
 * Hardened with:
 *   (a) Strict alphanumeric segment validation (blocks path traversal '..', '%2e%2e', slashes)
 *   (b) Strict whitelist of dashboard endpoints
 *   (c) Origin and path integrity validation against SSRF
 */
async function proxyRequest(request: NextRequest, { params }: { params: { path: string[] } }) {
  const pathSegments = params?.path || [];

  if (!Array.isArray(pathSegments) || pathSegments.length === 0) {
    return NextResponse.json({ error: "Missing path parameter." }, { status: 400 });
  }

  // (a) Validate each path segment against strict alphanumeric/underscore/hyphen regex
  for (const seg of pathSegments) {
    if (!seg || !/^[a-zA-Z0-9_-]+$/.test(seg)) {
      return NextResponse.json({ error: "Invalid path segment." }, { status: 400 });
    }
  }

  // Normalize: skip leading 'api' if present (e.g. /api/gateway/api/dashboard/stats -> /dashboard/stats)
  const segments = pathSegments[0] === "api" ? pathSegments.slice(1) : pathSegments;

  if (segments.length < 2 || segments[0] !== "dashboard") {
    return NextResponse.json(
      { error: "Forbidden: BFF proxy only serves dashboard endpoints." },
      { status: 403 }
    );
  }

  // (b) Whitelist check on dashboard endpoint (and strict Arena subpaths)
  const targetEndpoint = segments[1];
  if (!ALLOWED_DASHBOARD_ENDPOINTS.has(targetEndpoint)) {
    return NextResponse.json(
      { error: `Forbidden: Endpoint '${targetEndpoint}' is not allowed.` },
      { status: 403 }
    );
  }
  if (targetEndpoint === "arena") {
    const isStandardSubpath = segments.length === 3 && ALLOWED_ARENA_SUBPATHS.has(segments[2]);
    const isPentestSubpath =
      segments.length === 4 &&
      segments[2] === "pentest" &&
      ["run", "stream", "catalog", "replay", "replay-benchmark", "export"].includes(segments[3]);
    if (!isStandardSubpath && !isPentestSubpath) {
      return NextResponse.json(
        { error: "Forbidden: Invalid Arena endpoint path." },
        { status: 403 }
      );
    }
  } else if (segments.length !== 2) {
    return NextResponse.json(
      { error: "Forbidden: Unexpected extra dashboard path segments." },
      { status: 403 }
    );
  }

  const cleanPath = `api/${segments.join("/")}`;

  const backendUrl = (
    process.env.BACKEND_URL ||
    process.env.NEXT_PUBLIC_API_BASE_URL ||
    "http://gateway:8000"
  ).replace(/\/$/, "");

  const adminApiKey = process.env.ADMIN_API_KEY || "dev-admin-secret-key-change-me";
  const targetUrl = `${backendUrl}/${cleanPath}${request.nextUrl.search}`;

  // (c) Origin and pathname integrity verification
  try {
    const targetParsed = new URL(targetUrl);
    const backendParsed = new URL(backendUrl);
    if (
      targetParsed.origin !== backendParsed.origin ||
      !targetParsed.pathname.startsWith("/api/dashboard/")
    ) {
      return NextResponse.json({ error: "Forbidden: Target URL violation." }, { status: 403 });
    }
  } catch {
    return NextResponse.json({ error: "Invalid backend URL configuration." }, { status: 500 });
  }

  const forwardHeaders = new Headers();
  forwardHeaders.set("Content-Type", request.headers.get("Content-Type") || "application/json");
  forwardHeaders.set("Accept", request.headers.get("Accept") || "application/json");
  // Server-side privileged injection: client never sees or supplies this key
  forwardHeaders.set("X-API-Key", adminApiKey);

  try {
    let body: BodyInit | null = null;
    if (["POST", "PUT", "PATCH"].includes(request.method)) {
      body = await request.text();
    }

    const upstreamRes = await fetch(targetUrl, {
      method: request.method,
      headers: forwardHeaders,
      body,
      cache: "no-store",
    });

    const contentType = upstreamRes.headers.get("content-type") || "application/json";

    // Handle SSE streaming cleanly without buffering the whole response
    if (contentType.includes("text/event-stream") && upstreamRes.body) {
      return new NextResponse(upstreamRes.body, {
        status: upstreamRes.status,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache, no-transform",
          "Connection": "keep-alive",
        },
      });
    }

    const responseBody = await upstreamRes.text();
    return new NextResponse(responseBody, {
      status: upstreamRes.status,
      headers: {
        "Content-Type": contentType,
      },
    });
  } catch (err) {
    console.error(`BFF Proxy failed to reach Gateway at ${targetUrl}:`, err);
    return NextResponse.json(
      { error: "Bad Gateway: Unable to connect to WAF Gateway backend." },
      { status: 502 }
    );
  }
}

export async function GET(request: NextRequest, context: { params: { path: string[] } }) {
  return proxyRequest(request, context);
}

export async function POST(request: NextRequest, context: { params: { path: string[] } }) {
  return proxyRequest(request, context);
}

export async function PUT(request: NextRequest, context: { params: { path: string[] } }) {
  return proxyRequest(request, context);
}

export async function DELETE(request: NextRequest, context: { params: { path: string[] } }) {
  return proxyRequest(request, context);
}
