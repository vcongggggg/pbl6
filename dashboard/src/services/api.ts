import { config } from "@/config/env";
import {
  AttackDistributionItem,
  DashboardStats,
  EventsResponse,
  SimulateResult,
  TimelinePoint,
} from "@/types/dashboard";

let cachedRuntimeConfig: { backendUrl: string; adminApiKey: string } | null = null;

/**
 * Resolves API Gateway backend URL and admin key at runtime (Master Plan A6).
 * Caches result in module memory for subsequent calls.
 */
export async function getRuntimeConfig(): Promise<{ backendUrl: string; adminApiKey: string }> {
  if (cachedRuntimeConfig) {
    return cachedRuntimeConfig;
  }

  let backendUrl = config.apiBaseUrl.replace(/\/$/, "");
  let adminApiKey = config.adminApiKey;

  if (typeof window !== "undefined") {
    try {
      const res = await fetch("/api/config", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        if (data.backendUrl) {
          backendUrl = data.backendUrl.replace(/\/$/, "");
        }
        if (data.adminApiKey) {
          adminApiKey = data.adminApiKey;
        }
      }
    } catch (err) {
      console.warn("Failed to fetch /api/config, falling back to build-time config", err);
    }
  }

  cachedRuntimeConfig = { backendUrl, adminApiKey };
  return cachedRuntimeConfig;
}

export async function getApiBase(): Promise<string> {
  const conf = await getRuntimeConfig();
  return conf.backendUrl;
}

async function getAdminHeaders(): Promise<HeadersInit> {
  const conf = await getRuntimeConfig();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (conf.adminApiKey) {
    headers["X-API-Key"] = conf.adminApiKey;
  }
  return headers;
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const apiBase = await getApiBase();
  const res = await fetch(`${apiBase}/api/dashboard/stats`, {
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch stats: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchDashboardEvents(params: {
  page?: number;
  limit?: number;
  severity?: string;
  attack_type?: string;
  q?: string;
} = {}): Promise<EventsResponse> {
  const apiBase = await getApiBase();
  const query = new URLSearchParams();
  if (params.page) query.set("page", params.page.toString());
  if (params.limit) query.set("limit", params.limit.toString());
  if (params.severity && params.severity !== "ALL") query.set("severity", params.severity);
  if (params.attack_type && params.attack_type !== "ALL") query.set("attack_type", params.attack_type);
  if (params.q && params.q.trim()) query.set("q", params.q.trim());

  const url = `${apiBase}/api/dashboard/events?${query.toString()}`;
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Failed to fetch events: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchDashboardTimeline(minutes: number = 60): Promise<TimelinePoint[]> {
  const apiBase = await getApiBase();
  const res = await fetch(`${apiBase}/api/dashboard/timeline?minutes=${minutes}`, {
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch timeline: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchDashboardDistribution(): Promise<AttackDistributionItem[]> {
  const apiBase = await getApiBase();
  const res = await fetch(`${apiBase}/api/dashboard/distribution`, {
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch distribution: HTTP ${res.status}`);
  }
  return res.json();
}

export async function triggerSimulation(attackType: string): Promise<SimulateResult> {
  const apiBase = await getApiBase();
  const headers = await getAdminHeaders();
  const res = await fetch(`${apiBase}/api/dashboard/simulate`, {
    method: "POST",
    headers,
    body: JSON.stringify({ attack_type: attackType }),
  });
  if (!res.ok) {
    throw new Error(`Failed to simulate: HTTP ${res.status}`);
  }
  return res.json();
}

export async function resetDemoData(): Promise<{ status: string; message: string }> {
  const apiBase = await getApiBase();
  const headers = await getAdminHeaders();
  const res = await fetch(`${apiBase}/api/dashboard/reset-demo`, {
    method: "POST",
    headers,
  });
  if (!res.ok) {
    throw new Error(`Failed to reset demo: HTTP ${res.status}`);
  }
  return res.json();
}

export async function seedDemoData(): Promise<{ status: string; message: string }> {
  const apiBase = await getApiBase();
  const headers = await getAdminHeaders();
  const res = await fetch(`${apiBase}/api/dashboard/seed-demo`, {
    method: "POST",
    headers,
  });
  if (!res.ok) {
    throw new Error(`Failed to seed demo data: HTTP ${res.status}`);
  }
  return res.json();
}

export async function toggleWafMode(): Promise<{ status: string; waf_mode: string; message: string }> {
  const apiBase = await getApiBase();
  const headers = await getAdminHeaders();
  const res = await fetch(`${apiBase}/api/dashboard/toggle-waf-mode`, {
    method: "POST",
    headers,
  });
  if (!res.ok) {
    throw new Error(`Failed to toggle WAF mode: HTTP ${res.status}`);
  }
  return res.json();
}
