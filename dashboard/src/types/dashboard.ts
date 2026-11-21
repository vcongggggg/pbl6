export interface DashboardStats {
  total_requests: number;
  attacks_detected: number;
  safe_requests: number;
  safe_request_rate: number;
  avg_threat_score: number;
  avg_risk_score?: number;
  blocked_count?: number;
  rate_limited_count?: number;
  monitored_count?: number;
  family_counts: Record<string, number>;
  target_status: "ok" | "degraded" | "unreachable";
  target_latency_ms: number;
  target_url: string;
  waf_mode: string;
  active_phase: string;
}

export interface SecurityEventItem {
  event_id: string;
  request_id: string;
  timestamp: string;
  client_ip: string;
  attack_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  action: string;
  risk_score?: number;
  rule_score: number;
  ml_score?: number | null;
  anomaly_score?: number | null;
  behavior_score?: number | null;
  rule_id: string;
  rule_name: string;
  location: string;
  evidence: string;
  session_id?: string | null;
  kill_chain_stage?: string | null;
  details?: Record<string, any>;
}

export interface EventsResponse {
  items: SecurityEventItem[];
  total: number;
  page: number;
  limit: number;
}

export interface TimelinePoint {
  time: string;
  total_traffic: number;
  benign_traffic: number;
  attacks: number;
}

export interface AttackDistributionItem {
  name: string;
  key: string;
  count: number;
  percentage: number;
  color: string;
}

export interface ProtocolDistributionItem {
  name: string;
  key: string;
  count: number;
  percentage: number;
  color: string;
  description?: string;
}

export interface CyberRangeTopology {
  red_team: {
    name: string;
    ip: string;
    role: string;
    status: string;
    agent_model: string;
    attacks_generated: number;
  };
  network: {
    type: string;
    subnet: string;
    rtt_latency_ms: number;
    jitter_ms: number;
    packet_loss_pct: number;
    status: string;
  };
  blue_team: {
    name: string;
    ip: string;
    waf_port: number;
    mode: string;
    pipeline: string;
    inspected_count: number;
    blocked_count: number;
  };
  target_api: {
    name: string;
    port: number;
    url: string;
    status: string;
    flaws_monitored: string[];
  };
  soc_monitoring: {
    name: string;
    port: number;
    url: string;
    status: string;
  };
}

export interface SimulateResult {
  status: string;
  simulated: string;
  status_code?: number;
  request_id?: string;
  message: string;
}

export interface SessionEventItem {
  event_id: string;
  request_id: string;
  timestamp: string;
  attack_type: string;
  severity: string;
  action: string;
  risk_score: number;
  kill_chain_stage: string;
}

export interface AttackSessionItem {
  session_id: string;
  client_ip: string;
  start_time: string | null;
  end_time: string | null;
  duration_seconds: number;
  total_events: number;
  max_risk_score: number;
  kill_chain_stages: string[];
  attack_types: string[];
  has_blocked: boolean;
  events: SessionEventItem[];
}

export interface AttackSessionsResponse {
  total: number;
  page: number;
  limit: number;
  items: AttackSessionItem[];
}
