import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/**
 * Runtime Environment Configuration Endpoint (Master Plan A6)
 * Returns server-side backend URL and admin key evaluated at request time,
 * eliminating the build-time env freeze for local LAN deployments.
 */
export async function GET() {
  const backendUrl =
    process.env.BACKEND_URL ||
    process.env.NEXT_PUBLIC_API_BASE_URL ||
    "http://localhost:8000";

  const adminApiKey =
    process.env.ADMIN_API_KEY ||
    process.env.NEXT_PUBLIC_ADMIN_API_KEY ||
    "dev-admin-secret-key-change-me";

  return NextResponse.json({
    backendUrl: backendUrl.replace(/\/$/, ""),
    adminApiKey,
  });
}
