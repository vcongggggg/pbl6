import { config } from "@/config/env";
import {
  ArenaBattleResult,
  ArenaHistoryResponse,
  AttackDistributionItem,
  ProtocolDistributionItem,
  CyberRangeTopology,
  DashboardStats,
  EventsResponse,
  SimulateResult,
  TimelinePoint,
  AttackSessionsResponse,
} from "@/types/dashboard";

let cachedRuntimeConfig: { backendUrl: string } | null = null;

/**
 * Resolves API Gateway backend URL at runtime (Master Plan A6 / SEC-PBL6-004).
 * In the browser, all dashboard requests route through the Next.js Server-Side BFF
 * proxy (/api/gateway) which attaches administrative credentials server-side,
 * eliminating client-side API key leakage.
 */
export async function getRuntimeConfig(): Promise<{ backendUrl: string }> {
  if (cachedRuntimeConfig) {
    return cachedRuntimeConfig;
  }

  cachedRuntimeConfig = { backendUrl: "/api/gateway" };
  return cachedRuntimeConfig;
}

export async function getApiBase(): Promise<string> {
  const conf = await getRuntimeConfig();
  return conf.backendUrl;
}

async function getAdminHeaders(): Promise<HeadersInit> {
  return { "Content-Type": "application/json" };
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

export async function fetchDashboardProtocols(): Promise<ProtocolDistributionItem[]> {
  const apiBase = await getApiBase();
  const res = await fetch(`${apiBase}/api/dashboard/protocols`, {
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch protocol distribution: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchCyberRangeTopology(): Promise<CyberRangeTopology> {
  const apiBase = await getApiBase();
  const res = await fetch(`${apiBase}/api/dashboard/topology`, {
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch cyber range topology: HTTP ${res.status}`);
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


export async function fetchAttackSessions(params: {
  page?: number;
  limit?: number;
  client_ip?: string;
  stage?: string;
} = {}): Promise<AttackSessionsResponse> {
  const apiBase = await getApiBase();
  const query = new URLSearchParams();
  if (params.page) query.set("page", params.page.toString());
  if (params.limit) query.set("limit", params.limit.toString());
  if (params.client_ip && params.client_ip.trim()) query.set("client_ip", params.client_ip.trim());
  if (params.stage && params.stage !== "ALL") query.set("stage", params.stage);

  const res = await fetch(`${apiBase}/api/dashboard/sessions?${query.toString()}`, {
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch attack sessions: HTTP ${res.status}`);
  }
  return res.json();
}

// -----------------------------------------------------------------------------
// AI Arena (Task 10.4) — 100% Real Server-Side BFF API (Zero Synthetic Fallback)
// -----------------------------------------------------------------------------

export async function triggerArenaBattle(
  campaign: string = "all",
  maxRounds: number = 8,
  targetMode: "waf" | "direct" = "waf"
): Promise<ArenaBattleResult> {
  const apiBase = await getApiBase();
  const headers = await getAdminHeaders();
  const res = await fetch(`${apiBase}/api/dashboard/arena/battle`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      campaign: campaign.toLowerCase(),
      max_rounds: maxRounds,
      target_mode: targetMode,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to execute arena battle: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchArenaLive(): Promise<ArenaBattleResult | null> {
  const apiBase = await getApiBase();
  const res = await fetch(`${apiBase}/api/dashboard/arena/live`, {
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch live arena battle: HTTP ${res.status}`);
  }
  const data = await res.json();
  if (!data || data.status === "idle" || !data.battle_id) {
    return null;
  }
  return data;
}

export async function fetchArenaHistory(): Promise<ArenaHistoryResponse> {
  const apiBase = await getApiBase();
  const res = await fetch(`${apiBase}/api/dashboard/arena/history`, {
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch arena history: HTTP ${res.status}`);
  }
  const data = await res.json();
  return {
    total_battles: data.total_battles ?? 0,
    red_wins: data.red_wins ?? data.red_team_wins ?? 0,
    blue_wins: data.blue_wins ?? data.blue_team_wins ?? 0,
    red_team_wins: data.red_team_wins ?? data.red_wins ?? 0,
    blue_team_wins: data.blue_team_wins ?? data.blue_wins ?? 0,
    draw_count: data.draw_count ?? 0,
    red_team_win_rate: data.red_team_win_rate ?? 0,
    blue_team_defense_rate: data.blue_team_defense_rate ?? 0,
    battles: Array.isArray(data.battles) ? data.battles : [],
  };
}

// -----------------------------------------------------------------------------
// Autonomous Pentest API (Sprint 3 & 4)
// -----------------------------------------------------------------------------

export interface PentestRunParams {
  target_url?: string;
  defense_tier?: "no_waf" | "rules_only" | "hybrid_v3";
  scope?: string;
  max_rounds?: number;
  sync_to_soc?: boolean;
}

export interface PentestQValueEntry {
  action: string;
  family: string;
  transformation?: string;
  q_value: number;
  selected?: boolean;
  masked_in?: boolean;
}

export interface PentestAttackGraphNode {
  endpoint: string;
  method: string;
  category: string;
  flaw: string;
  priority: number;
  surfaces: string[];
}

export interface PentestRoundResult {
  round: number;
  round_num: number;
  phase: string;
  event_type: string;
  endpoint: string;
  target_endpoint: string;
  method: string;
  attack_type: string;
  technique: string;
  mutation_technique: string;
  original_payload: string;
  mutated_payload: string;
  normalized_payload: string;
  response_status: number;
  http_status: number;
  waf_blocked: boolean;
  dlp_redacted?: boolean;
  waf_decision: string;
  waf_threat_score: number;
  threat_score: number;
  rule_score: number;
  matched_rules: string[];
  ml_score: number;
  anomaly_score: number;
  latency_ms: number;
  winner: "BLUE_TEAM" | "RED_TEAM" | "DRAW";
  dqn_q_values: PentestQValueEntry[];
  reasoning_vi: string;
}

export interface PentestReport {
  battle_id: string;
  timestamp?: string;
  target_url: string;
  spec_source?: string;
  defense_tier: string;
  scope: string;
  total_rounds: number;
  blocked_count: number;
  bypass_count: number;
  winner: "BLUE_TEAM" | "RED_TEAM" | "DRAW";
  avg_threat_score: number;
  avg_latency_ms: number;
  duration_ms?: number;
  rounds: PentestRoundResult[];
  attack_graph?: PentestAttackGraphNode[];
}

export async function triggerPentestRun(params: PentestRunParams = {}): Promise<PentestReport> {
  const apiBase = await getApiBase();
  const headers = await getAdminHeaders();
  const res = await fetch(`${apiBase}/api/dashboard/arena/pentest/run`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      target_url: params.target_url || "http://127.0.0.1:5000",
      defense_tier: params.defense_tier || "hybrid_v3",
      scope: params.scope || "full_pentest",
      max_rounds: params.max_rounds || 8,
      sync_to_soc: params.sync_to_soc !== undefined ? params.sync_to_soc : false,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to execute autonomous pentest: HTTP ${res.status}`);
  }
  return res.json();
}

export interface PentestStreamCallbacks {
  onRecon?: (data: any) => void;
  onAttackGraph?: (data: { nodes?: PentestAttackGraphNode[]; [k: string]: any }) => void;
  onRound?: (round: PentestRoundResult) => void;
  onVerdict?: (verdict: PentestReport) => void;
}

export async function streamPentestEvaluation(
  params: PentestRunParams,
  callbacks: PentestStreamCallbacks,
  signal?: AbortSignal
): Promise<void> {
  const apiBase = await getApiBase();
  const q = new URLSearchParams({
    target_url: params.target_url || "http://127.0.0.1:5000",
    defense_tier: params.defense_tier || "hybrid_v3",
    scope: params.scope || "full_pentest",
    max_rounds: String(params.max_rounds || 8),
    sync_to_soc: String(params.sync_to_soc !== undefined ? params.sync_to_soc : false),
  });

  const res = await fetch(`${apiBase}/api/dashboard/arena/pentest/stream?${q.toString()}`, {
    method: "GET",
    headers: { Accept: "text/event-stream" },
    cache: "no-store",
    signal,
  });

  if (!res.ok || !res.body) {
    throw new Error(`SSE stream failed: HTTP ${res.status}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const blocks = buffer.split("\n\n");
    buffer = blocks.pop() || "";

    for (const block of blocks) {
      if (!block.trim()) continue;
      let eventType = "message";
      let dataStr = "";
      for (const line of block.split("\n")) {
        if (line.startsWith("event:")) {
          eventType = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          dataStr += line.slice(5).trim();
        }
      }
      if (!dataStr) continue;
      try {
        const parsed = JSON.parse(dataStr);
        if (eventType === "recon") {
          callbacks.onRecon?.(parsed);
        } else if (eventType === "attack_graph") {
          callbacks.onAttackGraph?.(parsed);
        } else if (eventType === "round" && parsed.round_data) {
          callbacks.onRound?.(parsed.round_data as PentestRoundResult);
        } else if (eventType === "verdict") {
          callbacks.onVerdict?.(parsed as PentestReport);
        }
      } catch {
        // skip malformed frame
      }
    }
  }
}

