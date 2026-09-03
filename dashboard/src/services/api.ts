import { config } from "@/config/env";
import {
  AttackDistributionItem,
  DashboardStats,
  EventsResponse,
  SimulateResult,
  TimelinePoint,
} from "@/types/dashboard";

const API_BASE = config.apiBaseUrl.replace(/\/$/, "");

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const res = await fetch(`${API_BASE}/api/dashboard/stats`, {
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
  const query = new URLSearchParams();
  if (params.page) query.set("page", params.page.toString());
  if (params.limit) query.set("limit", params.limit.toString());
  if (params.severity && params.severity !== "ALL") query.set("severity", params.severity);
  if (params.attack_type && params.attack_type !== "ALL") query.set("attack_type", params.attack_type);
  if (params.q && params.q.trim()) query.set("q", params.q.trim());

  const url = `${API_BASE}/api/dashboard/events?${query.toString()}`;
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Failed to fetch events: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchDashboardTimeline(minutes: number = 60): Promise<TimelinePoint[]> {
  const res = await fetch(`${API_BASE}/api/dashboard/timeline?minutes=${minutes}`, {
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch timeline: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchDashboardDistribution(): Promise<AttackDistributionItem[]> {
  const res = await fetch(`${API_BASE}/api/dashboard/distribution`, {
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch distribution: HTTP ${res.status}`);
  }
  return res.json();
}

export async function triggerSimulation(attackType: string): Promise<SimulateResult> {
  const res = await fetch(`${API_BASE}/api/dashboard/simulate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ attack_type: attackType }),
  });
  if (!res.ok) {
    throw new Error(`Failed to simulate: HTTP ${res.status}`);
  }
  return res.json();
}

export async function resetDemoData(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/api/dashboard/reset-demo`, {
    method: "POST",
  });
  if (!res.ok) {
    throw new Error(`Failed to reset demo: HTTP ${res.status}`);
  }
  return res.json();
}
