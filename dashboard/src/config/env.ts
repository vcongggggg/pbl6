/**
 * Centralized Frontend Configuration
 * Reads NEXT_PUBLIC_API_BASE_URL from environment or falls back to default.
 */
export const config = {
  apiBaseUrl: process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000",
  appName: "Web API Security Platform Dashboard",
  phase: "Phase 0 — Foundation",
};
