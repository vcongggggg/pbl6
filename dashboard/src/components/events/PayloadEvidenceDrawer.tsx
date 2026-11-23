"use client";

import React, { useState, useEffect } from "react";
import {
  X,
  ShieldAlert,
  Code2,
  Binary,
  Copy,
  Check,
  Network,
  Laptop,
  Info,
  Terminal,
  Brain,
  ChevronRight,
} from "lucide-react";
import { SecurityEventItem } from "@/types/dashboard";

interface PayloadEvidenceDrawerProps {
  event: SecurityEventItem | null;
  onClose: () => void;
  onOpenExplainModal?: (event: SecurityEventItem) => void;
  onOpenSessionTimeline?: (clientIp: string) => void;
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

export const PayloadEvidenceDrawer: React.FC<PayloadEvidenceDrawerProps> = ({
  event,
  onClose,
  onOpenExplainModal,
}) => {
  const [activeTab, setActiveTab] = useState<"rule" | "vector">("rule");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

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

  const canonicalInput = primaryMatch?.canonical_input || event.evidence || "N/A";
  const rawInput = primaryMatch?.raw_input || event.evidence || "N/A";
  const pattern = primaryMatch?.pattern || primaryMatch?.rule_id || "Pattern Signature Match";

  const isLan = isRfc1918LanIp(event.client_ip);

  // Extract genuine feature vector from backend ML inference telemetry
  const mlInference = details.ml_inference || null;
  const featureVector: number[] | null = Array.isArray(mlInference?.feature_vector)
    ? mlInference.feature_vector
    : null;
  const featureNames: string[] | null = Array.isArray(mlInference?.feature_names)
    ? mlInference.feature_names
    : null;
  const vectorDim = featureVector && featureVector.length > 0 ? featureVector.length : 26;

  const getActionBadge = (action: string) => {
    const norm = (action || "").toUpperCase();
    if (norm === "BLOCK" || norm === "BLOCKED") {
      return {
        label: "BLOCKED (403 Dropped)",
        className: "text-rose-400 font-semibold px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800/60",
      };
    }
    if (norm === "RATE_LIMIT") {
      return {
        label: "RATE_LIMIT (429 Throttled)",
        className: "text-amber-400 font-semibold px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800/60",
      };
    }
    if (norm === "MONITOR" || norm === "DETECTED") {
      return {
        label: `${norm} (Logged & Forwarded)`,
        className: "text-yellow-400 font-semibold px-2 py-0.5 rounded bg-yellow-950/50 border border-yellow-800/50",
      };
    }
    if (norm === "ALLOW") {
      return {
        label: "ALLOW (Forwarded)",
        className: "text-emerald-400 font-semibold px-2 py-0.5 rounded bg-emerald-950/50 border border-emerald-800/50",
      };
    }
    return {
      label: action || "UNKNOWN",
      className: "text-slate-300 font-semibold px-2 py-0.5 rounded bg-slate-800 border border-slate-700",
    };
  };

  const actionBadge = getActionBadge(event.action);

  const getAttackExplanation = (type: string) => {
    switch (type.toUpperCase()) {
      case "SQL_INJECTION":
      case "SQLI":
        return {
          title: "SQL Injection (SQLi) Attack",
          desc: "Kẻ tấn công chèn các toán tử SQL (' OR '1'='1, UNION SELECT, --) nhằm thay đổi cấu trúc truy vấn, vượt qua bước đăng nhập hoặc trích xuất toàn bộ dữ liệu CSDL.",
          mitre: "CWE-89 / CAPEC-66 / MITRE T1190",
        };
      case "XSS":
        return {
          title: "Cross-Site Scripting (XSS)",
          desc: "Mã độc JavaScript (<script>, onerror=alert, svg polyglots) được tiêm vào tham số nhằm đánh cắp session cookies, mạo danh phiên làm việc của nạn nhân.",
          mitre: "CWE-79 / CAPEC-63 / MITRE T1059.007",
        };
      case "PATH_TRAVERSAL":
      case "PATH":
        return {
          title: "Path Traversal / Local File Inclusion (LFI)",
          desc: "Sử dụng chuỗi điều hướng thư mục (../ hoặc ..\\) để thoát khỏi thư mục ứng dụng web và đọc các tệp tin hệ thống nhạy cảm (/etc/passwd, .env, source code).",
          mitre: "CWE-22 / CAPEC-126 / MITRE T1083",
        };
      case "COMMAND_INJECTION":
      case "CMD":
        return {
          title: "Command Injection / Remote Code Execution (RCE)",
          desc: "Lợi dụng các ký tự phân tách lệnh shell (; & | ` $) để ép máy chủ backend thực thi các câu lệnh hệ điều hành ngoài ý muốn (whoami, ping, cat).",
          mitre: "CWE-78 / CAPEC-88 / MITRE T1059.004",
        };
      default:
        return {
          title: "Web Application Anomaly",
          desc: "Request chứa các ký tự nguy hiểm bất thường vượt qua ngưỡng tin cậy của WAF.",
          mitre: "OWASP Top 10 API Security",
        };
    }
  };

  const explanation = getAttackExplanation(event.attack_type);

  return (
    <>
      {/* Backdrop overlay */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 transition-opacity animate-in fade-in duration-200"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer Panel */}
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Payload Evidence Drawer"
        className="fixed inset-y-0 right-0 w-full sm:w-[500px] bg-slate-950/95 backdrop-blur-2xl border-l border-slate-800/90 shadow-2xl z-50 flex flex-col transition-all duration-300 animate-in slide-in-from-right duration-300"
      >
        {/* Drawer Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-rose-400" />
            <div>
              <h3 className="text-sm font-bold text-white font-mono flex items-center gap-1.5">
                Payload Evidence Drawer
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                Event ID: <span className="text-cyan-400">#{event.event_id.slice(0, 14)}...</span>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Đóng ngăn kéo chi tiết"
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white transition cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tabs Switcher */}
        <div className="flex border-b border-slate-800 bg-slate-900/50 p-1.5 gap-1.5 text-xs font-mono">
          <button
            onClick={() => setActiveTab("rule")}
            className={`flex-1 flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg transition cursor-pointer ${
              activeTab === "rule"
                ? "bg-slate-800 text-white font-bold border border-slate-700 shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Code2 className="w-3.5 h-3.5 text-cyan-400" />
            <span>Rule Evidence</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/40">
              Layer 1
            </span>
          </button>

          <button
            onClick={() => setActiveTab("vector")}
            className={`flex-1 flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg transition cursor-pointer ${
              activeTab === "vector"
                ? "bg-slate-800 text-white font-bold border border-slate-700 shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Binary className="w-3.5 h-3.5 text-purple-400" />
            <span>{vectorDim}-Feature Vector</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
              ML Telemetry
            </span>
          </button>
        </div>

        {/* Drawer Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs font-mono">
          {activeTab === "rule" ? (
            <div className="space-y-3.5">
              {/* Metadata Summary Card */}
              <div className="bg-slate-900/90 border border-slate-800/90 rounded-xl p-3.5 space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Client IP (Attacker):</span>
                  <span
                    className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold border ${
                      isLan
                        ? "bg-rose-950/60 text-rose-300 border-rose-800"
                        : "bg-slate-800 text-slate-200 border-slate-700"
                    }`}
                  >
                    {isLan ? (
                      <Network className="w-3 h-3 text-rose-400" />
                    ) : (
                      <Laptop className="w-3 h-3 text-slate-400" />
                    )}
                    <span>{event.client_ip}</span>
                    <button
                      onClick={() => copyToClipboard(event.client_ip, "ip-drawer")}
                      className="ml-1 text-slate-400 hover:text-white"
                    >
                      {copiedKey === "ip-drawer" ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </span>
                </div>

                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Request ID:</span>
                  <div className="inline-flex items-center gap-1">
                    <span className="text-cyan-400">{event.request_id}</span>
                    <button
                      onClick={() => copyToClipboard(event.request_id, "req-drawer")}
                      className="text-slate-400 hover:text-white"
                    >
                      {copiedKey === "req-drawer" ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                </div>

                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Location:</span>
                  <span className="text-amber-400 font-bold px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700">
                    {event.location}
                  </span>
                </div>

                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Threat Score:</span>
                  <span className="text-rose-400 font-bold px-2 py-0.5 rounded bg-rose-950/50 border border-rose-800/60">
                    {(event.rule_score ?? 0).toFixed(1)} / 100
                  </span>
                </div>

                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Action Taken:</span>
                  <span className={actionBadge.className}>
                    {actionBadge.label}
                  </span>
                </div>
              </div>

              {/* Explainability Modal Trigger Banner */}
              {onOpenExplainModal && (
                <button
                  onClick={() => onOpenExplainModal(event)}
                  className="w-full flex items-center justify-between p-3 rounded-xl bg-gradient-to-r from-purple-950/80 via-slate-900 to-purple-900/40 border border-purple-500/40 hover:border-purple-400 text-purple-200 transition group cursor-pointer shadow-lg shadow-purple-950/30"
                >
                  <div className="flex items-center gap-2.5">
                    <div className="p-1.5 rounded-lg bg-purple-900/60 border border-purple-700/60 text-purple-300 group-hover:scale-105 transition">
                      <Brain className="w-4 h-4" />
                    </div>
                    <div className="text-left">
                      <div className="text-xs font-bold text-white group-hover:text-purple-300 transition">
                        Detection Explainability Breakdown
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono">
                        Phân tích rủi ro đa tầng: Rule (40%) + Supervised ML (35%) + Isolation Forest (25%)
                      </div>
                    </div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-purple-400 group-hover:translate-x-0.5 transition" />
                </button>
              )}

              {/* Attack Explanation Box */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 space-y-1.5">
                <div className="flex items-center gap-1.5 text-amber-400 font-bold">
                  <Info className="w-3.5 h-3.5" />
                  <span>{explanation.title}</span>
                </div>
                <p className="text-slate-300 text-[11px] leading-relaxed font-sans">
                  {explanation.desc}
                </p>
                <div className="text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-800/60">
                  Standards: <span className="text-slate-400">{explanation.mitre}</span>
                </div>
              </div>

              {/* Matched Signature Rule Details */}
              <div className="bg-slate-900/90 border border-slate-800/90 rounded-xl p-3.5 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Triggered Signature:</span>
                  <span className="font-bold text-cyan-400">{event.rule_id}</span>
                </div>

                <div>
                  <span className="text-slate-500 text-[11px]">Matched Regex Pattern:</span>
                  <pre className="mt-1 p-2 bg-slate-950 rounded-lg text-emerald-400 text-[11px] overflow-x-auto border border-slate-800/80">
                    {pattern}
                  </pre>
                </div>
              </div>

              {/* Payload Comparison: Canonical vs Raw */}
              <div className="space-y-3">
                <div className="bg-slate-900/90 border border-slate-800/90 rounded-xl p-3.5">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-slate-400 font-semibold text-[11px] flex items-center gap-1">
                      <Terminal className="w-3 h-3 text-cyan-400" />
                      Canonical Normalized Input (Evaluated):
                    </span>
                    <button
                      onClick={() => copyToClipboard(canonicalInput, "canonical")}
                      className="text-slate-500 hover:text-slate-300 flex items-center gap-1 text-[10px]"
                    >
                      {copiedKey === "canonical" ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded-lg text-rose-300 text-[11px] break-all border border-rose-950/60 font-mono">
                    {canonicalInput}
                  </div>
                </div>

                <div className="bg-slate-900/90 border border-slate-800/90 rounded-xl p-3.5">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-slate-400 font-semibold text-[11px]">
                      Raw Client Request Input:
                    </span>
                    <button
                      onClick={() => copyToClipboard(rawInput, "raw")}
                      className="text-slate-500 hover:text-slate-300 flex items-center gap-1 text-[10px]"
                    >
                      {copiedKey === "raw" ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded-lg text-slate-300 text-[11px] break-all border border-slate-800/60 font-mono">
                    {rawInput}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            /* Tab 2: Genuine N-Dimensional Feature Vector captured by Gateway ML Inference */
            <div className="space-y-4">
              <div className="bg-purple-950/30 border border-purple-800/50 rounded-xl p-3.5">
                <div className="flex items-center gap-2 text-purple-400 font-bold mb-1">
                  <Binary className="w-4 h-4" />
                  <span>{vectorDim}-Feature Vector Pipeline (Real Telemetry)</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                  Vector {vectorDim} chiều số học trích xuất trực tiếp từ HTTP Request trên Gateway phục vụ phân lớp Supervised ML và phát hiện dị biệt Isolation Forest.
                </p>
              </div>

              {featureVector && featureVector.length > 0 ? (
                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  {featureVector.map((val, idx) => {
                    const name =
                      featureNames && featureNames[idx]
                        ? featureNames[idx]
                        : `f${String(idx + 1).padStart(2, "0")}`;
                    const formattedVal =
                      typeof val === "number"
                        ? Number.isInteger(val)
                          ? String(val)
                          : val.toFixed(4)
                        : String(val);

                    return (
                      <div
                        key={idx}
                        className="bg-slate-900/80 border border-slate-800 rounded-lg p-2 flex justify-between items-center gap-1.5 min-w-0"
                        title={`${name}: ${formattedVal}`}
                      >
                        <span className="text-slate-400 font-mono text-[10px] truncate">{name}</span>
                        <span className="text-cyan-400 font-bold font-mono text-[11px] shrink-0">
                          {formattedVal}
                        </span>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="bg-slate-900/70 border border-dashed border-slate-700 rounded-xl p-6 text-center space-y-2">
                  <Binary className="w-6 h-6 text-slate-500 mx-auto" />
                  <p className="text-xs font-semibold text-slate-300">
                    Feature vector not captured for this event
                  </p>
                  <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                    Sự kiện này không có telemetry vector đặc trưng đính kèm (ML inference bị tắt, model không khả dụng, hoặc sự kiện được tạo bởi rate limiter / seeder).
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Drawer Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between">
          <span className="text-[11px] text-slate-500 font-mono">
            PBL6 SOC Evidence Inspector
          </span>
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition cursor-pointer"
          >
            Close Drawer
          </button>
        </div>
      </div>
    </>
  );
};
