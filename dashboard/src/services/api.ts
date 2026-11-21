import { config } from "@/config/env";
import {
  ArenaBattleResult,
  ArenaHistoryResponse,
  ArenaRound,
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

export async function seedDemoData(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/api/dashboard/seed-demo`, {
    method: "POST",
  });
  if (!res.ok) {
    throw new Error(`Failed to seed demo data: HTTP ${res.status}`);
  }
  return res.json();
}

export async function toggleWafMode(): Promise<{ status: string; waf_mode: string; message: string }> {
  const res = await fetch(`${API_BASE}/api/dashboard/toggle-waf-mode`, {
    method: "POST",
  });
  if (!res.ok) {
    throw new Error(`Failed to toggle WAF mode: HTTP ${res.status}`);
  }
  return res.json();
}

// -------------------------------------------------------------
// AI Arena (Task 10.4) API Handlers & Fallback Generators
// -------------------------------------------------------------

// Local storage / in-memory cache for demo battles
let inMemoryBattleHistory: ArenaBattleResult[] = [
  {
    battle_id: "battle-demo-sqli-01",
    timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    campaign: "SQLI",
    total_rounds: 6,
    blocked_count: 4,
    bypass_count: 2,
    winner: "BLUE_TEAM",
    avg_threat_score: 74.5,
    rounds: [
      {
        round_num: 1,
        attack_type: "SQL_INJECTION",
        endpoint: "/api/v1/vulnerable/books/search/?q=",
        technique: "RAW_SEED_PAYLOAD",
        payload: "' OR '1'='1",
        original_payload: "' OR '1'='1",
        response_status: 403,
        waf_threat_score: 95.0,
        waf_decision: "BLOCK",
        latency_ms: 1.8,
        winner: "BLUE_TEAM",
      },
      {
        round_num: 2,
        attack_type: "SQL_INJECTION",
        endpoint: "/api/v1/vulnerable/books/search/?q=",
        technique: "SPACE_TO_COMMENT",
        payload: "'/**/OR/**/'1'='1",
        original_payload: "' OR '1'='1",
        response_status: 403,
        waf_threat_score: 89.2,
        waf_decision: "BLOCK",
        latency_ms: 2.1,
        winner: "BLUE_TEAM",
      },
      {
        round_num: 3,
        attack_type: "SQL_INJECTION",
        endpoint: "/api/v1/vulnerable/books/search/?q=",
        technique: "CASE_RANDOMIZE_HEX",
        payload: "'/**/oR/**/0x313d31--",
        original_payload: "' OR 1=1--",
        response_status: 200,
        waf_threat_score: 48.6,
        waf_decision: "ALLOW",
        latency_ms: 3.4,
        winner: "RED_TEAM",
      },
      {
        round_num: 4,
        attack_type: "SQL_INJECTION",
        endpoint: "/api/v1/vulnerable/books/author/",
        technique: "NESTED_KEYWORD_SPLIT",
        payload: "' UNunionION SELselectECT 1,version()#",
        original_payload: "' UNION SELECT 1,version()#",
        response_status: 403,
        waf_threat_score: 92.0,
        waf_decision: "BLOCK",
        latency_ms: 1.9,
        winner: "BLUE_TEAM",
      },
      {
        round_num: 5,
        attack_type: "SQL_INJECTION",
        endpoint: "/api/v1/vulnerable/books/search/?q=",
        technique: "MULTILINE_INLINE_COMMENT",
        payload: "'/*comment*/\nUNION/*comment*/\nSELECT/*comment*/1,2--",
        original_payload: "' UNION SELECT 1,2--",
        response_status: 200,
        waf_threat_score: 52.3,
        waf_decision: "ALLOW",
        latency_ms: 2.7,
        winner: "RED_TEAM",
      },
      {
        round_num: 6,
        attack_type: "SQL_INJECTION",
        endpoint: "/api/v1/vulnerable/books/search/?q=",
        technique: "CHAR_FUNCTION_ENCODING",
        payload: "' UNION SELECT CHAR(65,68,77,73,78),2--",
        original_payload: "' UNION SELECT 'ADMIN',2--",
        response_status: 403,
        waf_threat_score: 90.1,
        waf_decision: "BLOCK",
        latency_ms: 1.6,
        winner: "BLUE_TEAM",
      },
    ],
  },
];

function generateMockBattle(campaign: string = "ALL", maxRounds: number = 8): ArenaBattleResult {
  const attackScenarios = [
    {
      attack_type: "SQL_INJECTION",
      endpoint: "/api/v1/vulnerable/books/search/?q=",
      original: "' OR '1'='1",
      techniques: [
        { name: "SPACE_TO_COMMENT", payload: "'/**/OR/**/'1'='1", score: 88.5, status: 403, dec: "BLOCK", winner: "BLUE_TEAM" },
        { name: "CASE_RANDOMIZE_HEX", payload: "'/**/oR/**/0x313d31--", score: 46.2, status: 200, dec: "ALLOW", winner: "RED_TEAM" },
        { name: "NESTED_KEYWORD_UNION", payload: "' UNunionION SELselectECT 1,version()--", score: 94.0, status: 403, dec: "BLOCK", winner: "BLUE_TEAM" },
        { name: "MULTILINE_COMMENT_INJECTION", payload: "'/*pbl6*/\nOR\n'1'='1", score: 55.4, status: 200, dec: "ALLOW", winner: "RED_TEAM" },
      ],
    },
    {
      attack_type: "XSS",
      endpoint: "/api/v1/vulnerable/reviews/submit/",
      original: "<script>alert(1)</script>",
      techniques: [
        { name: "CASE_RANDOMIZE_TAG", payload: "<sCrIpT>alert(1)</ScRiPt>", score: 91.0, status: 403, dec: "BLOCK", winner: "BLUE_TEAM" },
        { name: "SVG_ONLOAD_EVENT", payload: "<svg/onload=alert(document.cookie)>", score: 87.5, status: 403, dec: "BLOCK", winner: "BLUE_TEAM" },
        { name: "HEX_ENTITY_MUTATION", payload: "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>", score: 53.0, status: 200, dec: "ALLOW", winner: "RED_TEAM" },
        { name: "DATA_URI_BASE64", payload: "<iframe src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">", score: 48.0, status: 200, dec: "ALLOW", winner: "RED_TEAM" },
      ],
    },
    {
      attack_type: "PATH_TRAVERSAL",
      endpoint: "/api/v1/vulnerable/files/download/?file=",
      original: "../../../../etc/passwd",
      techniques: [
        { name: "NESTED_TRAVERSAL", payload: "....//....//....//....//etc/passwd", score: 93.0, status: 403, dec: "BLOCK", winner: "BLUE_TEAM" },
        { name: "URL_DOUBLE_ENCODE", payload: "%252e%252e%252f%252e%252e%252fetc%252fpasswd", score: 85.0, status: 403, dec: "BLOCK", winner: "BLUE_TEAM" },
        { name: "BACKSLASH_DOT_DOT", payload: "..\\..\\..\\..\\windows\\win.ini", score: 89.0, status: 403, dec: "BLOCK", winner: "BLUE_TEAM" },
        { name: "NULL_BYTE_TERMINATION", payload: "../../etc/passwd%00.png", score: 42.5, status: 200, dec: "ALLOW", winner: "RED_TEAM" },
      ],
    },
    {
      attack_type: "COMMAND_INJECTION",
      endpoint: "/api/v1/vulnerable/admin/ping/",
      original: "127.0.0.1; whoami",
      techniques: [
        { name: "WHITESPACE_IFS_MUTATION", payload: "127.0.0.1;cat$IFS/etc/passwd", score: 96.0, status: 403, dec: "BLOCK", winner: "BLUE_TEAM" },
        { name: "PIPE_CHAINING_BASE64", payload: "127.0.0.1 | echo bHM= | base64 -d | sh", score: 88.0, status: 403, dec: "BLOCK", winner: "BLUE_TEAM" },
        { name: "BACKTICK_EVALUATION", payload: "127.0.0.1;`id`", score: 92.5, status: 403, dec: "BLOCK", winner: "BLUE_TEAM" },
        { name: "ENVIRONMENT_VAR_EXPANSION", payload: "127.0.0.1;${PATH:0:1}in${PATH:0:1}sh", score: 58.0, status: 200, dec: "ALLOW", winner: "RED_TEAM" },
      ],
    },
  ];

  // Filter scenarios if specific campaign is selected
  let candidateScenarios = attackScenarios;
  if (campaign === "SQLI") candidateScenarios = [attackScenarios[0]];
  else if (campaign === "XSS") candidateScenarios = [attackScenarios[1]];
  else if (campaign === "PATH") candidateScenarios = [attackScenarios[2]];
  else if (campaign === "CMD") candidateScenarios = [attackScenarios[3]];

  const rounds: ArenaRound[] = [];
  let blockedCount = 0;
  let bypassCount = 0;
  let totalScore = 0;

  for (let r = 1; r <= maxRounds; r++) {
    const sc = candidateScenarios[(r - 1) % candidateScenarios.length];
    const tech = sc.techniques[(r - 1) % sc.techniques.length];

    const isBlocked = tech.winner === "BLUE_TEAM";
    if (isBlocked) {
      blockedCount++;
    } else {
      bypassCount++;
    }
    totalScore += tech.score;

    rounds.push({
      round_num: r,
      attack_type: sc.attack_type,
      endpoint: sc.endpoint,
      technique: tech.name,
      payload: tech.payload,
      original_payload: sc.original,
      response_status: tech.status,
      waf_threat_score: tech.score,
      waf_decision: tech.dec,
      latency_ms: Number((1.2 + Math.random() * 2.5).toFixed(1)),
      winner: tech.winner as "RED_TEAM" | "BLUE_TEAM",
      evasion_score: Number((Math.random() * 0.4 + (isBlocked ? 0.2 : 0.7)).toFixed(3)),
    });
  }

  const avgScore = Number((totalScore / maxRounds).toFixed(1));
  const winner = blockedCount >= bypassCount ? "BLUE_TEAM" : "RED_TEAM";

  const battleResult: ArenaBattleResult = {
    battle_id: `battle-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
    timestamp: new Date().toISOString(),
    campaign,
    total_rounds: maxRounds,
    blocked_count: blockedCount,
    bypass_count: bypassCount,
    winner,
    avg_threat_score: avgScore,
    rounds,
  };

  inMemoryBattleHistory.unshift(battleResult);
  if (inMemoryBattleHistory.length > 20) {
    inMemoryBattleHistory.pop();
  }

  return battleResult;
}

export async function triggerArenaBattle(
  campaign: string = "ALL",
  maxRounds: number = 8
): Promise<ArenaBattleResult> {
  const normCampaign = campaign.toLowerCase();
  try {
    // Try primary gateway endpoint /api/dashboard/arena/battle, then /api/arena/battle
    let res = await fetch(`${API_BASE}/api/dashboard/arena/battle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ campaign: normCampaign, max_rounds: maxRounds, target_mode: "waf" }),
    });
    if (!res.ok) {
      res = await fetch(`${API_BASE}/api/arena/battle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ campaign: normCampaign, max_rounds: maxRounds, target_mode: "waf" }),
      });
    }
    if (res.ok) {
      const data = await res.json();
      inMemoryBattleHistory.unshift(data);
      return data;
    }
  } catch (err) {
    // Backend offline or endpoint not yet deployed; fall back to high-fidelity mock
    console.info("Using simulated arena battle result:", err);
  }

  return generateMockBattle(campaign, maxRounds);
}

export async function fetchArenaLive(): Promise<ArenaBattleResult | null> {
  try {
    let res = await fetch(`${API_BASE}/api/dashboard/arena/live`, { cache: "no-store" });
    if (!res.ok) {
      res = await fetch(`${API_BASE}/api/arena/live`, { cache: "no-store" });
    }
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // ignore
  }
  return inMemoryBattleHistory.length > 0 ? inMemoryBattleHistory[0] : null;
}

export async function fetchArenaHistory(): Promise<ArenaHistoryResponse> {
  try {
    let res = await fetch(`${API_BASE}/api/dashboard/arena/history`, { cache: "no-store" });
    if (!res.ok) {
      res = await fetch(`${API_BASE}/api/arena/history`, { cache: "no-store" });
    }
    if (res.ok) {
      const data = await res.json();
      return {
        total_battles: data.total_battles ?? data.battles?.length ?? 0,
        red_wins: data.red_team_wins ?? data.red_wins ?? 0,
        blue_wins: data.blue_team_wins ?? data.blue_wins ?? 0,
        battles: data.battles ?? [],
      };
    }
  } catch {
    // ignore
  }

  const redWins = inMemoryBattleHistory.filter((b) => b.winner === "RED_TEAM").length;
  const blueWins = inMemoryBattleHistory.filter((b) => b.winner === "BLUE_TEAM").length;

  return {
    total_battles: inMemoryBattleHistory.length,
    red_wins: redWins,
    blue_wins: blueWins,
    battles: inMemoryBattleHistory,
  };
}



