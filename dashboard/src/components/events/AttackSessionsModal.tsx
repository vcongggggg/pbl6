"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  X,
  ShieldAlert,
  Flame,
  Clock,
  Network,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  Lock,
  Layers,
  Activity,
  Terminal,
  Database,
  KeyRound,
  EyeOff,
  Crosshair,
  ExternalLink,
} from "lucide-react";
import { AttackSessionItem, AttackSessionsResponse } from "@/types/dashboard";
import { fetchAttackSessions } from "@/services/api";

interface AttackSessionsModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialIpFilter?: string;
}

const KILL_CHAIN_STAGES = [
  {
    key: "RECONNAISSANCE",
    label: "Reconnaissance",
    icon: Crosshair,
    desc: "Thu thập thông tin & quét bề mặt tấn công",
    color: "amber",
  },
  {
    key: "EXPLOITATION",
    label: "Exploitation",
    icon: Flame,
    desc: "Khai thác lỗ hổng (SQLi, XSS, Cmd Injection)",
    color: "red",
  },
  {
    key: "EVASION",
    label: "Defense Evasion",
    icon: EyeOff,
    desc: "Né tránh WAF, obfuscation, mã hóa payload",
    color: "purple",
  },
  {
    key: "PRIVILEGE_ABUSE",
    label: "Privilege Abuse",
    icon: KeyRound,
    desc: "Leo thang đặc quyền, chiếm session token",
    color: "rose",
  },
  {
    key: "EXFILTRATION",
    label: "Exfiltration",
    icon: Database,
    desc: "Trích xuất và đánh cắp dữ liệu nhạy cảm",
    color: "cyan",
  },
];

export const AttackSessionsModal: React.FC<AttackSessionsModalProps> = ({
  isOpen,
  onClose,
  initialIpFilter,
}) => {
  const [sessions, setSessions] = useState<AttackSessionItem[]>([]);
  const [totalSessions, setTotalSessions] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [limit] = useState<number>(6);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [selectedStage, setSelectedStage] = useState<string>("ALL");
  const [ipFilter, setIpFilter] = useState<string>(initialIpFilter || "");
  const [expandedSessionId, setExpandedSessionId] = useState<string | null>(null);

  useEffect(() => {
    if (initialIpFilter) {
      setIpFilter(initialIpFilter);
    }
  }, [initialIpFilter]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  const loadSessions = useCallback(async () => {
    if (!isOpen) return;
    setIsLoading(true);
    try {
      const data: AttackSessionsResponse = await fetchAttackSessions({
        page,
        limit,
        client_ip: ipFilter.trim() || undefined,
        stage: selectedStage !== "ALL" ? selectedStage : undefined,
      });
      setSessions(data.items || []);
      setTotalSessions(data.total || 0);
      if (data.items && data.items.length > 0 && !expandedSessionId) {
        setExpandedSessionId(data.items[0].session_id);
      }
    } catch (err) {
      console.error("Failed to load attack sessions:", err);
    } finally {
      setIsLoading(false);
    }
  }, [isOpen, page, limit, ipFilter, selectedStage, expandedSessionId]);

  useEffect(() => {
    if (isOpen) {
      loadSessions();
    }
  }, [isOpen, page, selectedStage, loadSessions]);

  if (!isOpen) return null;

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    loadSessions();
  };

  const getStageBadgeColor = (stage: string) => {
    switch (stage.toUpperCase()) {
      case "RECONNAISSANCE":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "EXPLOITATION":
        return "bg-red-500/10 text-red-400 border-red-500/30";
      case "EVASION":
        return "bg-purple-500/10 text-purple-400 border-purple-500/30";
      case "PRIVILEGE_ABUSE":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      case "EXFILTRATION":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  const totalPages = Math.ceil(totalSessions / limit) || 1;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 sm:p-6 overflow-y-auto animate-in fade-in duration-200">
      <div className="relative w-full max-w-5xl max-h-[92vh] flex flex-col bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl shadow-red-950/20 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800/80 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400">
              <Layers className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white tracking-wide">
                  Attack Session Correlation & Kill Chain Timeline
                </h2>
                <span className="px-2 py-0.5 text-[10px] font-mono uppercase bg-red-950/70 text-red-300 border border-red-800/60 rounded">
                  Master Plan B4
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Xâu chuỗi các sự kiện an ninh đơn lẻ thành Chiến dịch tấn công theo cửa sổ trượt 15 phút (Sliding Window)
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Filter and Control Bar */}
        <div className="px-6 py-3 border-b border-slate-800/60 bg-slate-900/30 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5" /> Stage:
            </span>
            <div className="flex items-center gap-1 bg-slate-900/90 p-1 rounded-lg border border-slate-800 text-xs">
              {["ALL", "RECONNAISSANCE", "EXPLOITATION", "EVASION", "PRIVILEGE_ABUSE", "EXFILTRATION"].map((st) => (
                <button
                  key={st}
                  onClick={() => {
                    setSelectedStage(st);
                    setPage(1);
                  }}
                  className={`px-2.5 py-1 rounded font-mono text-[11px] transition-colors ${
                    selectedStage === st
                      ? "bg-red-600 text-white font-semibold shadow-sm"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"
                  }`}
                >
                  {st === "ALL" ? "Tất Cả" : st.replace("_", " ")}
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleSearchSubmit} className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Lọc theo IP (e.g. 192.168...)"
                value={ipFilter}
                onChange={(e) => setIpFilter(e.target.value)}
                className="pl-8 pr-3 py-1 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500/50 w-48 sm:w-56"
              />
            </div>
            <button
              type="submit"
              className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-mono transition-colors"
            >
              Lọc
            </button>
            <button
              type="button"
              onClick={loadSessions}
              disabled={isLoading}
              className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 rounded-lg transition-colors"
              title="Làm mới"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin text-red-400" : ""}`} />
            </button>
          </form>
        </div>

        {/* Sessions Feed Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {isLoading && sessions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-slate-500">
              <RefreshCw className="w-8 h-8 animate-spin text-red-500 mb-3" />
              <p className="font-mono text-xs">Đang tải và xâu chuỗi dữ liệu Attack Sessions...</p>
            </div>
          ) : sessions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-slate-500 border border-dashed border-slate-800 rounded-xl">
              <CheckCircle2 className="w-10 h-10 text-emerald-500/60 mb-3" />
              <p className="font-semibold text-slate-300">Không tìm thấy phiên tấn công nào phù hợp</p>
              <p className="text-xs text-slate-500 font-mono mt-1">
                Chưa có sự kiện an ninh nào được gom cụm với bộ lọc hiện tại hoặc hệ thống đang an toàn.
              </p>
            </div>
          ) : (
            sessions.map((sess) => {
              const isExpanded = expandedSessionId === sess.session_id;
              const isMultiStage = sess.kill_chain_stages && sess.kill_chain_stages.length > 1;

              return (
                <div
                  key={sess.session_id}
                  className={`border rounded-xl transition-all duration-200 overflow-hidden ${
                    sess.has_blocked
                      ? "border-red-900/40 bg-slate-900/40 hover:border-red-700/60"
                      : "border-amber-900/40 bg-slate-900/30 hover:border-amber-700/60"
                  }`}
                >
                  {/* Session Header Card */}
                  <div
                    onClick={() => setExpandedSessionId(isExpanded ? null : sess.session_id)}
                    className="p-4 cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-3 select-none"
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className={`p-2 rounded-lg mt-0.5 ${
                          sess.has_blocked
                            ? "bg-red-500/10 text-red-400 border border-red-500/30"
                            : "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                        }`}
                      >
                        <ShieldAlert className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono font-semibold text-white text-sm">
                            IP: {sess.client_ip}
                          </span>
                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            {sess.session_id.slice(0, 14)}...
                          </span>
                          {sess.has_blocked ? (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 font-bold">
                              BLOCKED
                            </span>
                          ) : (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 font-bold">
                              MONITORED
                            </span>
                          )}
                          {isMultiStage && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 animate-pulse font-semibold">
                              MULTI-STAGE ATTACK
                            </span>
                          )}
                        </div>

                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 font-mono mt-1.5">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3 text-slate-500" />
                            Thời lượng: {sess.duration_seconds}s ({sess.total_events} requests)
                          </span>
                          <span>
                            Bắt đầu: {sess.start_time ? new Date(sess.start_time).toLocaleTimeString() : "N/A"}
                          </span>
                          <span>
                            Kết thúc: {sess.end_time ? new Date(sess.end_time).toLocaleTimeString() : "N/A"}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 self-end md:self-center">
                      <div className="text-right">
                        <div className="text-[11px] font-mono text-slate-400">Peak Risk</div>
                        <div
                          className={`text-base font-mono font-bold ${
                            sess.max_risk_score >= 80
                              ? "text-red-400"
                              : sess.max_risk_score >= 50
                              ? "text-amber-400"
                              : "text-emerald-400"
                          }`}
                        >
                          {sess.max_risk_score.toFixed(1)} / 100
                        </div>
                      </div>
                      <div className="p-1 text-slate-400 hover:text-white">
                        {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                      </div>
                    </div>
                  </div>

                  {/* Kill Chain Stepper Visualizer */}
                  <div className="px-4 py-3 bg-slate-950/70 border-t border-slate-800/60">
                    <div className="text-[11px] font-mono uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5">
                      <Activity className="w-3.5 h-3.5 text-red-400" />
                      Cyber Kill Chain Stage Progression:
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                      {KILL_CHAIN_STAGES.map((st, idx) => {
                        const Icon = st.icon;
                        const isHit = sess.kill_chain_stages && sess.kill_chain_stages.includes(st.key);

                        return (
                          <div
                            key={st.key}
                            className={`p-2.5 rounded-lg border text-xs flex flex-col justify-between transition-all ${
                              isHit
                                ? "bg-red-950/30 border-red-600/60 text-white shadow-lg shadow-red-950/30"
                                : "bg-slate-900/30 border-slate-800/40 text-slate-600 opacity-60"
                            }`}
                          >
                            <div className="flex items-center justify-between gap-1 mb-1">
                              <span className="font-mono text-[10px] text-slate-400 font-semibold">
                                {idx + 1}. {st.key.slice(0, 5)}
                              </span>
                              <Icon className={`w-3.5 h-3.5 ${isHit ? "text-red-400" : "text-slate-600"}`} />
                            </div>
                            <div className={`font-semibold text-[11px] leading-tight ${isHit ? "text-red-300" : "text-slate-500"}`}>
                              {st.label}
                            </div>
                            <div className="mt-1">
                              {isHit ? (
                                <span className="inline-block text-[9px] font-mono px-1.5 py-0.2 rounded bg-red-600/30 text-red-200 border border-red-500/40">
                                  ACTIVE
                                </span>
                              ) : (
                                <span className="text-[9px] font-mono text-slate-600">Idle</span>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Expanded Event Timeline */}
                  {isExpanded && sess.events && sess.events.length > 0 && (
                    <div className="p-4 bg-slate-950/90 border-t border-slate-800/80 animate-in fade-in duration-150">
                      <div className="text-xs font-mono font-bold text-slate-300 mb-3 flex items-center justify-between">
                        <span>Danh Sách Sự Kiện Theo Dòng Thời Gian ({sess.events.length} hits)</span>
                        <span className="text-[11px] text-slate-500">Cửa sổ tương quan: 15 phút</span>
                      </div>

                      <div className="relative pl-6 space-y-3 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                        {sess.events.map((ev, i) => (
                          <div key={ev.event_id || i} className="relative group">
                            {/* Dot on timeline line */}
                            <div
                              className={`absolute -left-[19px] top-1.5 w-2.5 h-2.5 rounded-full border-2 border-slate-950 ${
                                ev.action === "BLOCKED" ? "bg-red-500" : "bg-amber-400"
                              }`}
                            />

                            <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80 hover:border-slate-700 transition-colors flex flex-wrap items-center justify-between gap-2 text-xs">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-mono text-slate-400 text-[11px]">
                                  {new Date(ev.timestamp).toLocaleTimeString()}
                                </span>
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-mono border uppercase font-bold ${getStageBadgeColor(
                                    ev.kill_chain_stage
                                  )}`}
                                >
                                  {ev.kill_chain_stage}
                                </span>
                                <span className="font-semibold text-slate-200">{ev.attack_type}</span>
                                <span className="font-mono text-[10px] text-slate-500">
                                  req: {ev.request_id?.slice(0, 10)}...
                                </span>
                              </div>

                              <div className="flex items-center gap-2">
                                <span className="font-mono text-[11px] text-slate-400">
                                  Risk: <span className="font-bold text-white">{ev.risk_score}</span>
                                </span>
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                    ev.action === "BLOCKED"
                                      ? "bg-red-950 text-red-300 border border-red-800"
                                      : "bg-amber-950 text-amber-300 border border-amber-800"
                                  }`}
                                >
                                  {ev.action}
                                </span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Footer with Pagination */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-900/50 flex items-center justify-between text-xs font-mono text-slate-400">
          <div>
            Tổng số: <span className="text-white font-bold">{totalSessions}</span> attack sessions đã gom cụm
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-200 transition-colors"
            >
              Trang trước
            </button>
            <span>
              Trang {page} / {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-200 transition-colors"
            >
              Trang sau
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
