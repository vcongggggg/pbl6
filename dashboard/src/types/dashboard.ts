export interface DashboardStats {
  total_requests: number;
  attacks_detected: number;
  safe_requests: number;
  safe_request_rate: number;
  avg_threat_score: number;
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
  rule_score: number;
  rule_id: string;
  rule_name: string;
  location: string;
  evidence: string;
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

export interface SimulateResult {
  status: string;
  simulated: string;
  status_code?: number;
  request_id?: string;
  message: string;
}
