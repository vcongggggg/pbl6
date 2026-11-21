/**
 * Centralized Frontend Configuration
 * Reads NEXT_PUBLIC_API_BASE_URL from environment or falls back to default.
 * NOTE: Admin credentials (adminApiKey) are strictly server-side (BFF Proxy) to prevent credential leaks (SEC-PBL6-004).
 */
export const config = {
  apiBaseUrl: process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000",
  appName: "Web API Security Platform Dashboard",
  phase: "Phase 0 — Foundation",
};
