"use client";

import React, { useState, useEffect } from "react";
import {
  X,
  Brain,
  ShieldAlert,
  Check,
  Copy,
  Terminal,
  Layers,
  Network,
  Laptop,
  Cpu,
} from "lucide-react";
import { SecurityEventItem } from "@/types/dashboard";

interface DetectionExplainabilityModalProps {
  event: SecurityEventItem | null;
  onClose: () => void;
}

const isRfc1918LanIp = (ip: string): boolean => {
  if (!ip) return false;
  if (ip.startsWith("10.") || ip.startsWith("192.168.")) return true;
  if (ip.startsWith("172.")) {
    const octets = ip.split(".");
    if (octets.length >= 2) {
      const second = parseInt(octets[1], 10);
      return !Number.isNaN(second) && second >= 16 && second <= 31;
    }
  }
  return false;
};

export const DetectionExplainabilityModal: React.FC<DetectionExplainabilityModalProps> = ({
  event,
  onClose,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Close on Escape key press
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  if (!event) return null;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const details = event.details || {};
  const ruleMatches = details.matches || details.rule_matches || [];
  const primaryMatch = ruleMatches.length > 0 ? ruleMatches[0] : null;

  const rawInput = primaryMatch?.raw_input || event.evidence || "N/A";
  const canonicalInput = primaryMatch?.canonical_input || event.evidence || "N/A";
  const pattern = primaryMatch?.pattern || primaryMatch?.rule_id || "Signature Regex Match";

  const isLanAttacker = isRfc1918LanIp(event.client_ip);

  // 1. Layer 1: Deterministic Rule Engine (40% Weight) — Strictly genuine score
  const ruleRawScore = event.rule_score ?? 0.0;
  const ruleWeight = 0.4;
  const ruleContribution = ruleRawScore * ruleWeight;

  // 2. Layer 2: Supervised ML Score (35% Weight) — Strictly genuine telemetry, zero fabrication
  const mlInference = details.ml_inference || null;
  const mlRawScore: number | null = event.ml_score != null ? Number(event.ml_score) : null;
  const mlWeight = 0.35;
  const mlContribution = mlRawScore != null ? mlRawScore * mlWeight : 0.0;

  const rawConfidence =
    typeof mlInference?.confidence === "number" ? mlInference.confidence : null;
  const mlConfidencePct: number | null =
    rawConfidence != null
      ? Number((rawConfidence <= 1.0 ? rawConfidence * 100 : rawConfidence).toFixed(2))
      : null;

  const mlModelName: string = mlInference?.model_name || "N/A";
  const mlModelVersion: string | null = mlInference?.model_version || null;
  const mlPredictedClass: string = mlInference?.attack_type || (mlRawScore != null ? event.attack_type : "N/A");
  const mlLatencyMs: number | null =
    typeof mlInference?.latency_ms === "number" ? mlInference.latency_ms : null;

  // 3. Layer 3: Isolation Forest Anomaly Score (25% Weight) — Strictly genuine telemetry
  const anomalyInference = details.anomaly_inference || null;
  const anomalyRawScore: number | null =
    event.anomaly_score != null ? Number(event.anomaly_score) : null;
  const anomalyWeight = 0.25;
  const anomalyContribution = anomalyRawScore != null ? anomalyRawScore * anomalyWeight : 0.0;

  const anomalyIsFlagged: boolean | null =
    typeof anomalyInference?.is_anomaly === "boolean" ? anomalyInference.is_anomaly : null;
  const anomalyDecisionRaw: number | null =
    typeof anomalyInference?.raw_score === "number" ? anomalyInference.raw_score : null;

  // Final Hybrid Weighted Risk Score (0 - 100)
  const computedHybridScore = Number(
    (ruleContribution + mlContribution + anomalyContribution).toFixed(1)
  );
  const hybridScore =
    event.risk_score != null ? Number(event.risk_score.toFixed(1)) : computedHybridScore;

  // Derive decision display strictly from actual recorded event.action & details.reason
  const getActualDecision = (action: string, reason?: string) => {
    const norm = (action || "").toUpperCase();
    if (norm === "BLOCK" || norm === "BLOCKED") {
      return {
        action: "BLOCKED",
        code: 403,
        badgeColor:
          "bg-rose-500/20 text-rose-400 border-rose-500/60 shadow-[0_0_15px_rgba(244,63,94,0.35)]",
        title: "ACTIVE BLOCK (HTTP 403 FORBIDDEN)",
        desc:
          reason ||
          "Gateway đã chặn request độc hại và phản hồi HTTP 403 Forbidden để bảo vệ Target API.",
        color: "text-rose-400",
      };
    }
    if (norm === "RATE_LIMIT") {
      return {
        action: "RATE_LIMIT",
        code: 429,
        badgeColor:
          "bg-amber-500/20 text-amber-400 border-amber-500/60 shadow-[0_0_15px_rgba(245,158,11,0.35)]",
        title: "RATE LIMITED (HTTP 429 TOO MANY REQUESTS)",
        desc:
          reason ||
          "Gateway đã giới hạn tần suất request (HTTP 429) từ địa chỉ IP nguồn có mức rủi ro cao.",
        color: "text-amber-400",
      };
    }
    if (norm === "MONITOR" || norm === "DETECTED") {
      return {
        action: norm,
        code: 200,
        badgeColor:
          "bg-yellow-500/20 text-yellow-400 border-yellow-500/60 shadow-[0_0_15px_rgba(234,179,8,0.35)]",
        title: "SECURITY MONITORING (LOGGED & FORWARDED)",
        desc:
          reason ||
          "Sự kiện an ninh đã được ghi nhận vào cơ sở dữ liệu giám sát nhưng vẫn cho phép chuyển tiếp (Monitor Mode).",
        color: "text-yellow-400",
      };
    }
    return {
      action: norm || "ALLOW",
      code: 200,
      badgeColor: "bg-emerald-500/20 text-emerald-400 border-emerald-500/60",
      title: "SAFE TRAFFIC (FORWARDED)",
      desc: reason || "Lưu lượng được đánh giá an toàn và chuyển tiếp tới Target API.",
      color: "text-emerald-400",
    };
  };

  const decision = getActualDecision(event.action || details.decision, details.reason);

  // Attack classification details
  const getAttackMetadata = (type: string) => {
    switch (type.toUpperCase()) {
      case "SQL_INJECTION":
      case "SQLI":
        return {
          cwe: "CWE-89: Improper Neutralization of Special Elements in SQL Command",
          capec: "CAPEC-66: SQL Injection",
          mitre: "MITRE ATT&CK T1190 (Exploit Public-Facing Application)",
          impact: "Trích xuất trái phép CSDL, vượt qua xác thực đăng nhập, thao túng toàn bộ dữ liệu máy chủ.",
          vector: "Chèn cú pháp boolean tautology (' OR '1'='1), mệnh đề UNION SELECT, hoặc ký hiệu comment SQL (--).",
        };
      case "XSS":
        return {
          cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation",
          capec: "CAPEC-63: Cross-Site Scripting (XSS)",
          mitre: "MITRE ATT&CK T1059.007 (JavaScript Execution)",
          impact: "Đánh cắp Cookie/Session Token người dùng, chuyển hướng website giả mạo, thực thi mã độc trên trình duyệt nạn nhân.",
          vector: "Tiêm thẻ script <script>, các thuộc tính sự kiện HTML (onload, onerror) hoặc giao thức javascript:.",
        };
      case "PATH_TRAVERSAL":
      case "PATH":
        return {
          cwe: "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
          capec: "CAPEC-126: Path Traversal",
          mitre: "MITRE ATT&CK T1083 (File and Directory Discovery)",
          impact: "Đọc trộm các tệp tin hệ thống (/etc/passwd, windows/win.ini), tệp cấu hình .env hoặc mã nguồn nhạy cảm.",
          vector: "Sử dụng chuỗi điều hướng thư mục tương đối (../, ..\\, %2e%2e%2f) để vượt ra khỏi thư mục web root.",
        };
      case "COMMAND_INJECTION":
      case "CMD":
        return {
          cwe: "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
          capec: "CAPEC-88: OS Command Injection",
          mitre: "MITRE ATT&CK T1059.004 (Unix/Windows Shell)",
          impact: "Chiếm quyền điều khiển máy chủ từ xa (RCE), thực thi lệnh hệ điều hành với đặc quyền của process web server.",
          vector: "Chèn các ký tự phân tách lệnh shell (; & | ` $() &&) vào tham số truyền vào hàm thực thi dòng lệnh.",
        };
      default:
        return {
          cwe: "CWE-20: Improper Input Validation",
          capec: "CAPEC-1: Accessing/Intercepting/Modifying Web Traffic",
          mitre: "OWASP API Security Top 10",
          impact: "Gây bất ổn định dịch vụ hoặc thăm dò bề mặt tấn công của hệ thống.",
          vector: "Payload mang cấu trúc cú pháp bất thường vượt ngưỡng tin cậy.",
        };
    }
  };

  const attackMeta = getAttackMetadata(event.attack_type);

  // Full explanation report payload for 1-click export (100% real data)
  const fullExplanationJson = JSON.stringify(
    {
      explainability_version: "PBL6-Explainability-v2.0",
      standard_compliance: ["NIST SP 800-137", "ISO/IEC 27004", "IEEE TNSM 2021"],
      event_id: event.event_id,
      request_id: event.request_id,
      timestamp: event.timestamp,
      client_ip: event.client_ip,
      client_origin: isLanAttacker ? "RFC1918_LAN_HOST" : "LOCALHOST_OR_EXTERNAL",
      attack_type: event.attack_type,
      severity: event.severity,
      decision: {
        recorded_action: event.action,
        http_code: decision.code,
        reason: details.reason ?? null,
        hybrid_risk_score: hybridScore,
        formula: "0.40 * S_rule + 0.35 * S_ml + 0.25 * S_anomaly",
      },
      layers: {
        layer_1_rule_engine: {
          name: "Deterministic Pattern Matching",
          weight: ruleWeight,
          raw_score: ruleRawScore,
          weighted_points: Number(ruleContribution.toFixed(2)),
          rule_id: event.rule_id,
          rule_name: event.rule_name,
          location: event.location,
          pattern,
        },
        layer_2_supervised_ml: {
          name: "Supervised Threat Classification",
          weight: mlWeight,
          raw_score: mlRawScore,
          weighted_points: Number(mlContribution.toFixed(2)),
          predicted_class: mlPredictedClass,
          confidence_percent: mlConfidencePct,
          model_name: mlModelName,
          model_version: mlModelVersion,
          latency_ms: mlLatencyMs,
          status: mlRawScore != null ? "ACTIVE_TELEMETRY" : "UNAVAILABLE",
        },
        layer_3_isolation_forest: {
          name: "Unsupervised Anomaly Detection",
          weight: anomalyWeight,
          raw_score: anomalyRawScore,
          weighted_points: Number(anomalyContribution.toFixed(2)),
          is_anomaly: anomalyIsFlagged,
          decision_raw_score: anomalyDecisionRaw,
          status: anomalyRawScore != null ? "ACTIVE_TELEMETRY" : "UNAVAILABLE",
        },
      },
      threat_intelligence: {
        cwe: attackMeta.cwe,
        capec: attackMeta.capec,
        mitre: attackMeta.mitre,
      },
      evidence: {
        raw_input: rawInput,
        canonical_input: canonicalInput,
      },
    },
    null,
    2
  );

  return (
    <>
      {/* 1. Backdrop Overlay with Blur */}
      <div
        onClick={onClose}
        className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md transition-opacity animate-in fade-in duration-200"
      />

      {/* 2. Centered Modal Dialog */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 pointer-events-none">
        <div className="bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl w-full max-w-4xl max-h-[92vh] flex flex-col pointer-events-auto overflow-hidden animate-in zoom-in-95 duration-200">
          {/* Modal Header */}
          <div className="p-4 sm:p-5 border-b border-slate-800/90 bg-slate-900/60 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-400">
                <Brain className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                    <span>Giải Thích Quyết Định WAF (XAI &amp; Feature Attribution)</span>
                    <span className="px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-800 text-[10px] font-mono">
                      Real Telemetry
                    </span>
                  </h3>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Phân rã toán học đa tầng trọng số (Defense-in-Depth Multi-Layered Attribution) &amp; Bối cảnh tấn công chuẩn NIST SP 800-137.
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-200 p-2 rounded-lg hover:bg-slate-800/80 transition cursor-pointer"
              title="Close modal (Esc)"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Modal Scrollable Body */}
          <div className="p-4 sm:p-5 space-y-4 overflow-y-auto max-h-[calc(92vh-140px)] text-xs text-slate-300">
            {/* Quick Context Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 font-mono text-[11px]">
              <div className="flex items-center gap-3">
                <span className="text-slate-400">Event ID:</span>
                <span className="text-cyan-300 font-bold">{event.event_id.substring(0, 16)}...</span>
                <button
                  onClick={() => copyToClipboard(event.event_id, "event_id")}
                  className="text-slate-500 hover:text-slate-300 flex items-center gap-1 cursor-pointer"
                  title="Copy full Event ID"
                >
                  {copiedKey === "event_id" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>

              <div className="flex items-center gap-3">
                <span className="text-slate-400">Request ID:</span>
                <span className="text-purple-300 font-bold">{event.request_id}</span>
                <button
                  onClick={() => copyToClipboard(event.request_id, "request_id")}
                  className="text-slate-500 hover:text-slate-300 flex items-center gap-1 cursor-pointer"
                  title="Copy Request ID"
                >
                  {copiedKey === "request_id" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>

              <div className="flex items-center gap-1.5">
                {isLanAttacker ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/80">
                    <Network className="w-3 h-3 text-rose-400" />
                    <span>LAN Host ({event.client_ip})</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    <Laptop className="w-3 h-3 text-slate-400" />
                    <span>Host ({event.client_ip})</span>
                  </span>
                )}
              </div>
            </div>

            {/* Section 1: Final Decision & Hybrid Risk Score Gauge */}
            <div className="p-4 rounded-xl bg-gradient-to-br from-slate-900 via-slate-900/90 to-purple-950/20 border border-purple-500/20">
              <div className="flex flex-col md:flex-row items-center justify-between gap-4">
                {/* Score Display */}
                <div className="flex items-center gap-4">
                  <div className="relative flex items-center justify-center">
                    <div className="w-20 h-20 rounded-full border-4 border-slate-800 flex flex-col items-center justify-center bg-slate-950/90 shadow-inner">
                      <span className="text-2xl font-black font-mono text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-rose-400">
                        {hybridScore}
                      </span>
                      <span className="text-[9px] font-mono text-slate-400 uppercase">/ 100</span>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-mono text-slate-400">HYBRID WEIGHTED RISK SCORE</span>
                      <span className={`px-1.5 py-0.2 rounded border text-[9px] font-mono font-bold ${decision.badgeColor}`}>
                        {decision.action}
                      </span>
                    </div>
                    <h3 className={`text-base font-extrabold tracking-wide mt-1 ${decision.color}`}>
                      {decision.title}
                    </h3>
                    <p className="text-[11px] text-slate-300 max-w-md mt-1 leading-relaxed">
                      {decision.desc}
                    </p>
                  </div>
                </div>

                {/* Decision Policy Threshold Pill */}
                <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-[10px] font-mono space-y-1.5 shrink-0 min-w-[200px]">
                  <span className="text-slate-400 font-bold block mb-1">CHÍNH SÁCH RA QUYẾT ĐỊNH WAF:</span>
                  <div className="flex justify-between items-center text-emerald-400">
                    <span>&lt; 30 pts:</span>
                    <span className="font-bold">ALLOW (200 OK)</span>
                  </div>
                  <div className="flex justify-between items-center text-yellow-400">
                    <span>30 - 60 pts:</span>
                    <span className="font-bold">MONITOR (Logged)</span>
                  </div>
                  <div className="flex justify-between items-center text-amber-400">
                    <span>60 - 80 pts:</span>
                    <span className="font-bold">RATE LIMIT (429)</span>
                  </div>
                  <div className="flex justify-between items-center text-rose-400">
                    <span>&gt; 80 pts:</span>
                    <span className="font-bold">BLOCK (403 Drop)</span>
                  </div>
                </div>
              </div>

              {/* Formula Breakdown Bar */}
              <div className="mt-4 pt-3 border-t border-slate-800/80">
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1.5">
                  <span>Công thức hợp nhất: S_risk = (0.40 × S_rule) + (0.35 × S_ML) + (0.25 × S_anomaly)</span>
                  <span className="font-bold text-slate-200">
                    {ruleContribution.toFixed(1)} + {mlContribution.toFixed(1)} + {anomalyContribution.toFixed(1)} = {computedHybridScore} pts
                  </span>
                </div>
                {/* Stacked Progress Bar */}
                <div className="w-full h-2.5 rounded-full bg-slate-950 overflow-hidden flex border border-slate-800">
                  <div
                    style={{ width: `${Math.min(100, ruleContribution)}%` }}
                    className="h-full bg-blue-500 transition-all duration-500"
                    title={`Rule Engine: ${ruleContribution.toFixed(1)} pts (40%)`}
                  />
                  <div
                    style={{ width: `${Math.min(100, mlContribution)}%` }}
                    className="h-full bg-purple-500 transition-all duration-500"
                    title={`Supervised ML: ${mlContribution.toFixed(1)} pts (35%)`}
                  />
                  <div
                    style={{ width: `${Math.min(100, anomalyContribution)}%` }}
                    className="h-full bg-emerald-500 transition-all duration-500"
                    title={`Isolation Forest Anomaly: ${anomalyContribution.toFixed(1)} pts (25%)`}
                  />
                </div>
              </div>
            </div>

            {/* Section 2: 3-Pillar Explainability Breakdown Cards */}
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2 font-mono">
                <Layers className="w-4 h-4 text-purple-400" />
                <span>Phân Tích 3 Tầng Phòng Thủ (Defense-in-Depth Attribution)</span>
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {/* Pillar 1: Deterministic Rule Engine */}
                <div className="p-3.5 rounded-xl bg-slate-900/80 border border-blue-500/30 flex flex-col justify-between space-y-3">
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/40 text-[10px] font-mono font-bold">
                        TẦNG 1: RULE ENGINE
                      </span>
                      <span className="text-[10px] font-mono text-emerald-400 font-bold">
                        ● Active
                      </span>
                    </div>
                    <h5 className="font-bold text-slate-100 text-[13px]">{event.rule_name}</h5>
                    <div className="mt-2 space-y-1 font-mono text-[11px] text-slate-300">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Rule ID:</span>
                        <span className="text-blue-400 font-bold">{event.rule_id}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Vị trí kiểm tra:</span>
                        <span className="text-slate-200">{event.location}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Điểm thô (Raw):</span>
                        <span className="text-amber-400 font-bold">{ruleRawScore.toFixed(1)} / 100</span>
                      </div>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800">
                    <div className="flex justify-between items-center text-[11px] font-mono">
                      <span className="text-slate-400">Trọng số: 40%</span>
                      <span className="text-blue-400 font-extrabold text-sm">+{ruleContribution.toFixed(1)} pts</span>
                    </div>
                  </div>
                </div>

                {/* Pillar 2: Supervised ML (Real Telemetry) */}
                <div className="p-3.5 rounded-xl bg-slate-900/80 border border-purple-500/30 flex flex-col justify-between space-y-3">
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 text-[10px] font-mono font-bold">
                        TẦNG 2: SUPERVISED ML
                      </span>
                      <span className="inline-flex items-center gap-1 text-[10px] font-mono text-slate-300 font-semibold">
                        <Cpu className="w-3 h-3 text-purple-400" />
                        <span>{mlRawScore != null ? "Live Telemetry" : "N/A"}</span>
                      </span>
                    </div>
                    <h5 className="font-bold text-slate-100 text-[13px]">Phân loại Đa lớp Mối Đe Dọa</h5>
                    <div className="mt-2 space-y-1 font-mono text-[11px] text-slate-300">
                      <div className="flex justify-between gap-2">
                        <span className="text-slate-400 shrink-0">Mô hình:</span>
                        <span className="text-amber-300 font-semibold truncate text-right" title={mlModelName}>
                          {mlModelName}{mlModelVersion ? ` (${mlModelVersion})` : ""}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Dự đoán lớp:</span>
                        <span className="text-purple-400 font-bold">{mlPredictedClass}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Độ tin cậy:</span>
                        <span className="text-emerald-400 font-bold">
                          {mlConfidencePct != null ? `${mlConfidencePct.toFixed(1)}%` : "N/A"}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Điểm ML thực:</span>
                        <span className="text-amber-400 font-bold">
                          {mlRawScore != null ? `${mlRawScore.toFixed(1)} / 100` : "N/A"}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800">
                    <div className="flex justify-between items-center text-[11px] font-mono">
                      <span className="text-slate-400">Trọng số: 35%</span>
                      <span className="text-purple-400 font-extrabold text-sm">+{mlContribution.toFixed(1)} pts</span>
                    </div>
                  </div>
                </div>

                {/* Pillar 3: Isolation Forest Anomaly Detection (Real Telemetry) */}
                <div className="p-3.5 rounded-xl bg-slate-900/80 border border-emerald-500/30 flex flex-col justify-between space-y-3">
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-mono font-bold">
                        TẦNG 3: ISOLATION FOREST
                      </span>
                      <span className="text-[10px] font-mono text-emerald-300">
                        {anomalyRawScore != null ? "Live Telemetry" : "N/A"}
                      </span>
                    </div>
                    <h5 className="font-bold text-slate-100 text-[13px]">Phát hiện Hành vi Dị biệt</h5>
                    <div className="mt-2 space-y-1 font-mono text-[11px] text-slate-300">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Trạng thái:</span>
                        <span className={anomalyIsFlagged ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>
                          {anomalyIsFlagged === null
                            ? "N/A"
                            : anomalyIsFlagged
                            ? "ANOMALY"
                            : "NORMAL"}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Raw Decision Score:</span>
                        <span className="text-slate-200">
                          {anomalyDecisionRaw != null ? anomalyDecisionRaw.toFixed(4) : "N/A"}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Điểm Anomaly thực:</span>
                        <span className="text-amber-400 font-bold">
                          {anomalyRawScore != null ? `${anomalyRawScore.toFixed(1)} / 100` : "N/A"}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800">
                    <div className="flex justify-between items-center text-[11px] font-mono">
                      <span className="text-slate-400">Trọng số: 25%</span>
                      <span className="text-emerald-400 font-extrabold text-sm">+{anomalyContribution.toFixed(1)} pts</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Section 3: Threat Intelligence & Standards Mapping */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2 font-mono">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <span>Chuẩn An Ninh &amp; Bối Cảnh Mối Đe Dọa (Threat Context)</span>
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                <div className="space-y-2">
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <span className="text-slate-400 font-mono block text-[10px]">CWE / CAPEC / MITRE:</span>
                    <p className="text-rose-300 font-bold mt-0.5">{attackMeta.cwe}</p>
                    <p className="text-slate-400 font-mono text-[10px] mt-0.5">{attackMeta.capec} • {attackMeta.mitre}</p>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <span className="text-slate-400 font-mono block text-[10px]">HỆ QUẢ TẤN CÔNG (IMPACT):</span>
                    <p className="text-slate-200 mt-0.5 leading-relaxed">{attackMeta.impact}</p>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <span className="text-slate-400 font-mono block text-[10px]">SIGNATURE REGEX KHỚP:</span>
                    <p className="text-cyan-300 font-mono text-[10px] mt-0.5 break-all p-1.5 bg-slate-900 rounded">
                      {pattern}
                    </p>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <span className="text-slate-400 font-mono block text-[10px]">VÉCTƠ KHAI THÁC ĐIỂN HÌNH:</span>
                    <p className="text-slate-300 mt-0.5 leading-relaxed">{attackMeta.vector}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Section 4: Evidence Snippet (Raw vs Canonical) */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-slate-300 font-bold font-mono flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Bằng Chứng Khai Thác (Extracted Payload Evidence):</span>
                </span>
                <button
                  onClick={() => copyToClipboard(rawInput, "raw_snippet")}
                  className="text-slate-400 hover:text-slate-200 flex items-center gap-1 font-mono text-[10px] cursor-pointer"
                >
                  {copiedKey === "raw_snippet" ? (
                    <Check className="w-3 h-3 text-emerald-400" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                  <span>Copy Payload</span>
                </button>
              </div>
              <div className="p-2.5 bg-slate-950 rounded-lg text-rose-300 font-mono text-[11px] break-all border border-slate-800/80">
                {rawInput}
              </div>
            </div>
          </div>

          {/* Modal Footer */}
          <div className="p-4 border-t border-slate-800/90 bg-slate-900/80 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <button
                onClick={() => copyToClipboard(fullExplanationJson, "json_report")}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-950/80 hover:bg-purple-900 text-purple-200 border border-purple-800/80 text-xs font-mono transition cursor-pointer"
              >
                {copiedKey === "json_report" ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                <span>Export Full Explainability JSON</span>
              </button>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={onClose}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};
