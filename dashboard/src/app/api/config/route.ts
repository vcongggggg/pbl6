import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/**
 * Runtime Environment Configuration Endpoint (Master Plan A6)
 * Returns server-side backend URL evaluated at request time,
 * eliminating the build-time env freeze for local LAN deployments.
 *
 * NOTE: Admin credentials (adminApiKey) MUST NEVER be returned here
 * to prevent unauthenticated credential harvesting over the network.
 */
export async function GET() {
  const backendUrl =
    process.env.BACKEND_URL ||
    process.env.NEXT_PUBLIC_API_BASE_URL ||
    "http://localhost:8000";

  return NextResponse.json({
    backendUrl: backendUrl.replace(/\/$/, ""),
  });
}
