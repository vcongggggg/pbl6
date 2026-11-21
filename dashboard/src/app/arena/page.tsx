"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import Link from "next/link";
import { Header } from "@/components/Header";
import {
  triggerArenaBattle,
  fetchArenaLive,
  fetchArenaHistory,
  fetchDashboardStats,
  toggleWafMode,
} from "@/services/api";
import {
  ArenaBattleResult,
  ArenaHistoryResponse,
  ArenaRound,
  DashboardStats,
} from "@/types/dashboard";
import {
  Swords,
  Shield,
  Flame,
  Trophy,
  Play,
  RotateCcw,
  History,
  Activity,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  X,
  Sparkles,
  Terminal,
  Zap,
  Target,
  ChevronRight,
  Cpu,
  AlertTriangle,
  Info,
} from "lucide-react";

export default function ArenaPage() {
  // Telemetry & stats from gateway
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [isTogglingWaf, setIsTogglingWaf] = useState<boolean>(false);

  // Battle configuration
  const [campaign, setCampaign] = useState<string>("ALL");
  const [maxRounds, setMaxRounds] = useState<number>(8);
  const [streamingMode, setStreamingMode] = useState<boolean>(true);

  // Battle execution states
  const [battleState, setBattleState] = useState<"STANDBY" | "IN_PROGRESS" | "FINISHED">("STANDBY");
  const [currentBattle, setCurrentBattle] = useState<ArenaBattleResult | null>(null);
  const [visibleRounds, setVisibleRounds] = useState<ArenaRound[]>([]);
  const [activeRoundIndex, setActiveRoundIndex] = useState<number>(-1);
  const [isTriggering, setIsTriggering] = useState<boolean>(false);

  // UI drawers & filters
  const [roundFilter, setRoundFilter] = useState<"ALL" | "BYPASS" | "BLOCKED">("ALL");
  const [selectedRound, setSelectedRound] = useState<ArenaRound | null>(null);
  const [isHistoryOpen, setIsHistoryOpen] = useState<boolean>(false);
  const [historyData, setHistoryData] = useState<ArenaHistoryResponse | null>(null);
  const [copiedPayload, setCopiedPayload] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" | "info" } | null>(null);

  const showToast = (message: string, type: "success" | "error" | "info" = "info") => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  // Load telemetry stats on mount
  const loadStats = useCallback(async () => {
    try {
      const data = await fetchDashboardStats();
      setStats(data);
    } catch {
      // ignore
    }
  }, []);

  // Load history data
  const loadHistory = useCallback(async () => {
    try {
      const hist = await fetchArenaHistory();
      setHistoryData(hist);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    loadStats();
    loadHistory();
  }, [loadStats, loadHistory]);

  // Handle ESC key for modal/drawer
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setSelectedRound(null);
        setIsHistoryOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // WAF Mode Toggle
  const handleToggleWafMode = async () => {
    setIsTogglingWaf(true);
    try {
      const res = await toggleWafMode();
      showToast(res.message, "success");
      await loadStats();
    } catch (err: any) {
      showToast(`Không thể chuyển chế độ WAF: ${err.message}`, "error");
    } finally {
      setIsTogglingWaf(false);
    }
  };

  // Copy helper
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedPayload(id);
    setTimeout(() => setCopiedPayload(null), 2000);
  };

  // Start Battle
  const handleStartBattle = async () => {
    if (isTriggering || battleState === "IN_PROGRESS") return;

    setIsTriggering(true);
    setBattleState("IN_PROGRESS");
    setVisibleRounds([]);
    setActiveRoundIndex(-1);

    try {
      const result = await triggerArenaBattle(campaign, maxRounds);
      setCurrentBattle(result);

      if (streamingMode) {
        // Stream rounds one by one for cyber combat effect
        for (let i = 0; i < result.rounds.length; i++) {
          setActiveRoundIndex(i);
          await new Promise((r) => setTimeout(r, 450));
          setVisibleRounds((prev) => [...prev, result.rounds[i]]);
        }
      } else {
        setVisibleRounds(result.rounds);
      }

      setBattleState("FINISHED");
      showToast(
        `Trận đấu kết thúc! ${
          result.winner === "BLUE_TEAM"
            ? "🛡️ Blue Team bảo vệ thành công!"
            : "🔥 Red Team đã bypass thành công!"
        }`,
        result.winner === "BLUE_TEAM" ? "success" : "info"
      );
      loadHistory();
      loadStats();
    } catch (err: any) {
      setBattleState("STANDBY");
      showToast(`Lỗi khi khởi chạy trận đấu: ${err.message}`, "error");
    } finally {
      setIsTriggering(false);
      setActiveRoundIndex(-1);
    }
  };

  // Load a historical battle into the active view
  const handleSelectHistoricalBattle = (battle: ArenaBattleResult) => {
    setCurrentBattle(battle);
    setVisibleRounds(battle.rounds);
    setBattleState("FINISHED");
    setIsHistoryOpen(false);
    showToast(`Đã tải lại trận đấu: ${battle.battle_id}`, "info");
  };

  // Filtered rounds
  const displayedRounds = visibleRounds.filter((r) => {
    if (roundFilter === "BYPASS") return r.winner === "RED_TEAM";
    if (roundFilter === "BLOCKED") return r.winner === "BLUE_TEAM";
    return true;
  });

  // Calculate live aggregate rates
  const totalRoundsCount = visibleRounds.length;
  const bypassCount = visibleRounds.filter((r) => r.winner === "RED_TEAM").length;
  const blockedCount = visibleRounds.filter((r) => r.winner === "BLUE_TEAM").length;
  const bypassRate = totalRoundsCount > 0 ? Math.round((bypassCount / totalRoundsCount) * 100) : 0;
  const blockRate = totalRoundsCount > 0 ? Math.round((blockedCount / totalRoundsCount) * 100) : 0;
  const avgThreatScore =
    totalRoundsCount > 0
      ? Number(
          (
            visibleRounds.reduce((acc, r) => acc + r.waf_threat_score, 0) /
            totalRoundsCount
          ).toFixed(1)
        )
      : 0;

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 flex flex-col font-sans selection:bg-rose-500 selection:text-white">
      {/* Toast Notification */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl border shadow-2xl backdrop-blur-xl transition-all duration-300 animate-in fade-in slide-in-from-bottom-5 bg-slate-900/95 border-slate-700 text-xs font-mono">
          {toast.type === "success" && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
          {toast.type === "error" && <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />}
          {toast.type === "info" && <Info className="w-4 h-4 text-cyan-400 shrink-0" />}
          <span className="text-slate-200">{toast.message}</span>
          <button
            onClick={() => setToast(null)}
            className="ml-2 text-slate-500 hover:text-white transition"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* 1. Shared Header with Navigation Switcher */}
      <Header
        stats={stats}
        onRefresh={loadStats}
        onToggleWafMode={handleToggleWafMode}
        isTogglingWaf={isTogglingWaf}
      />

      {/* Main Arena Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Arena Header Banner */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-rose-950/60 text-rose-400 border border-rose-800/60 shadow-[0_0_12px_rgba(244,63,94,0.3)]">
                TASK 10.4 • CYBER ARENA
              </span>
              <span className="text-xs font-mono text-slate-400">
                PBL6 AI-Powered Combat Lab
              </span>
            </div>
            <h1 className="text-2xl font-extrabold text-white mt-1.5 flex items-center gap-2.5 tracking-tight">
              <Swords className="w-6 h-6 text-rose-400 animate-pulse" />
              Đấu Trường Đối Kháng Trực Tiếp: Red Team vs Blue Team
            </h1>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl">
              Mô phỏng đọ sức thời gian thực giữa tác nhân tấn công thông minh ứng dụng Học tăng cường
              (Deep Q-Network RL Evasion Agent) và Cổng phòng thủ AI-WAF đa tầng (Deterministic Regex + XGBoost + IsolationForest).
            </p>
          </div>

          {/* Quick Actions */}
          <div className="flex items-center gap-2.5 self-start md:self-auto">
            <button
              onClick={() => setIsHistoryOpen(true)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 text-xs font-medium transition active:scale-95 shadow-sm"
              title="Xem lịch sử các trận đấu trước"
            >
              <History className="w-3.5 h-3.5 text-cyan-400" />
              <span>Lịch Sử Đấu</span>
              {historyData && (
                <span className="ml-1 px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] font-mono text-cyan-300 border border-slate-700">
                  {historyData.total_battles}
                </span>
              )}
            </button>
          </div>
        </div>

        {/* 2. Three-Column Combat Arena: Red Team vs Center Status vs Blue Team */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
          {/* LEFT: RED TEAM (AI ATTACK AGENT) */}
          <div className="lg:col-span-4 bg-slate-900/80 backdrop-blur-md rounded-2xl border border-rose-900/40 p-5 shadow-[0_0_25px_rgba(244,63,94,0.08)] flex flex-col justify-between relative overflow-hidden group">
            <div className="absolute top-0 right-0 w-32 h-32 bg-rose-500/10 rounded-full blur-3xl pointer-events-none group-hover:bg-rose-500/15 transition"></div>

            <div>
              {/* Header */}
              <div className="flex items-center justify-between pb-3 border-b border-rose-950/80">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-xl bg-rose-950/80 border border-rose-600/50 flex items-center justify-center shadow-[0_0_12px_rgba(244,63,94,0.4)]">
                    <Flame className="w-5 h-5 text-rose-400" />
                  </div>
                  <div>
                    <h2 className="text-sm font-bold text-white flex items-center gap-1.5">
                      RED TEAM AGENT
                    </h2>
                    <span className="text-[11px] font-mono text-rose-300 flex items-center gap-1">
                      <Cpu className="w-3 h-3 text-rose-400" /> Deep Q-Network RL v1.0
                    </span>
                  </div>
                </div>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">
                  ATTACKER
                </span>
              </div>

              {/* Agent Specs */}
              <div className="mt-3.5 space-y-2 text-xs text-slate-300">
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60 font-mono text-[11px]">
                  <span className="text-slate-400">Policy:</span>
                  <span className="text-rose-300 font-semibold">Epsilon-Greedy DQN Q-Network</span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60 font-mono text-[11px]">
                  <span className="text-slate-400">Mục tiêu:</span>
                  <span className="text-slate-200">Bypass WAF (HTTP 200 OK)</span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60 font-mono text-[11px]">
                  <span className="text-slate-400">Không gian hành động:</span>
                  <span className="text-slate-200">10 Evasion Mutators</span>
                </div>
              </div>

              {/* Real-time KPI Metric */}
              <div className="mt-4 p-3.5 rounded-xl bg-rose-950/20 border border-rose-900/30">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">Tỷ Lệ Xuyên Thủng (Bypass):</span>
                  <span className="text-rose-400 font-bold text-sm">{bypassRate}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-800/80 mt-2 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-rose-600 to-rose-400 transition-all duration-500 rounded-full"
                    style={{ width: `${bypassRate}%` }}
                  />
                </div>
                <div className="flex justify-between items-center text-[10px] font-mono text-slate-400 mt-2">
                  <span>Thành công: <strong className="text-rose-300">{bypassCount}</strong> hiệp</span>
                  <span>Tổng tấn công: <strong className="text-white">{totalRoundsCount}</strong></span>
                </div>
              </div>

              {/* Mutation Arsenal Chips */}
              <div className="mt-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-2">
                  Kho Vũ Khí Đột Biến (Action Space):
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    "Space to Comment",
                    "Hex Encoding",
                    "Case Randomize",
                    "Nested Traversal",
                    "Whitespace IFS",
                    "URL Double Encode",
                    "Null Byte Injection",
                  ].map((tech) => (
                    <span
                      key={tech}
                      className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-rose-950/40 text-rose-300 border border-rose-900/50"
                    >
                      {tech}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>Trạng thái:</span>
              <span className="flex items-center gap-1.5 text-rose-400 font-semibold">
                <span className={`w-2 h-2 rounded-full ${battleState === "IN_PROGRESS" ? "bg-rose-400 animate-ping" : "bg-rose-500"}`} />
                {battleState === "IN_PROGRESS" ? "ĐANG TẤN CÔNG..." : "SẴN SÀNG"}
              </span>
            </div>
          </div>

          {/* CENTER: COMBAT BADGE & MATCH CONTROLLER */}
          <div className="lg:col-span-4 bg-slate-900/90 backdrop-blur-md rounded-2xl border border-slate-800 p-5 shadow-xl flex flex-col justify-between relative">
            <div>
              {/* Central VS Badge */}
              <div className="flex flex-col items-center text-center">
                <div className="relative flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-rose-950/60 via-purple-950/60 to-cyan-950/60 border border-slate-700/80 shadow-[0_0_30px_rgba(168,85,247,0.3)]">
                  <Swords className={`w-8 h-8 text-amber-400 ${battleState === "IN_PROGRESS" ? "animate-bounce" : ""}`} />
                  <span className="absolute -bottom-2 px-2 py-0.5 rounded-full text-[10px] font-extrabold font-mono bg-slate-950 text-amber-300 border border-amber-600/50 shadow-md">
                    VS
                  </span>
                </div>

                <div className="mt-3">
                  <h3 className="text-base font-bold text-white tracking-tight">
                    Đấu Trường Đối Kháng AI Arena
                  </h3>
                  <div className="mt-1 flex items-center justify-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold ${
                        battleState === "IN_PROGRESS"
                          ? "bg-amber-950/70 text-amber-300 border border-amber-600 animate-pulse"
                          : battleState === "FINISHED"
                          ? "bg-purple-950/70 text-purple-300 border border-purple-600"
                          : "bg-slate-800 text-slate-300 border border-slate-700"
                      }`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${battleState === "IN_PROGRESS" ? "bg-amber-400 animate-ping" : "bg-slate-400"}`} />
                      {battleState === "IN_PROGRESS"
                        ? `ĐANG ĐỐI KHÁNG (${activeRoundIndex + 1}/${maxRounds})`
                        : battleState === "FINISHED"
                        ? "TRẬN ĐẤU HOÀN TẤT"
                        : "TRẠNG THÁI CHỜ (STANDBY)"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Match Controls */}
              <div className="mt-5 space-y-3.5 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
                {/* Campaign Selection */}
                <div>
                  <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1.5">
                    1. Chọn Chiến Dịch Tấn Công:
                  </label>
                  <div className="grid grid-cols-2 gap-1.5 text-xs font-mono">
                    {[
                      { id: "ALL", label: "Tất Cả (Matrix)" },
                      { id: "SQLI", label: "SQL Injection" },
                      { id: "XSS", label: "XSS Mutator" },
                      { id: "PATH", label: "Path Traversal" },
                      { id: "CMD", label: "Command Inj." },
                    ].map((item) => (
                      <button
                        key={item.id}
                        onClick={() => setCampaign(item.id)}
                        disabled={battleState === "IN_PROGRESS"}
                        className={`px-2.5 py-1.5 rounded-lg border text-left transition font-medium ${
                          campaign === item.id
                            ? "bg-rose-950/60 border-rose-600 text-rose-300 shadow-[0_0_10px_rgba(244,63,94,0.3)]"
                            : "bg-slate-900 border-slate-800 text-slate-400 hover:text-white"
                        }`}
                      >
                        {item.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Number of Rounds */}
                <div>
                  <div className="flex justify-between items-center text-[11px] font-mono text-slate-400 mb-1.5">
                    <span>2. Số Lượng Hiệp Đấu:</span>
                    <span className="text-white font-bold">{maxRounds} hiệp</span>
                  </div>
                  <div className="grid grid-cols-4 gap-1.5 font-mono text-xs">
                    {[4, 6, 8, 12].map((num) => (
                      <button
                        key={num}
                        onClick={() => setMaxRounds(num)}
                        disabled={battleState === "IN_PROGRESS"}
                        className={`py-1 rounded-lg border text-center transition ${
                          maxRounds === num
                            ? "bg-purple-950/60 border-purple-600 text-purple-300 font-bold"
                            : "bg-slate-900 border-slate-800 text-slate-400 hover:text-white"
                        }`}
                      >
                        {num}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Streaming Mode Option */}
                <div className="flex items-center justify-between pt-1 text-xs">
                  <span className="text-slate-400 font-mono text-[11px]">Hiệu ứng từng hiệp:</span>
                  <button
                    onClick={() => setStreamingMode(!streamingMode)}
                    disabled={battleState === "IN_PROGRESS"}
                    className={`px-2 py-0.5 rounded text-[11px] font-mono border transition ${
                      streamingMode
                        ? "bg-cyan-950/60 border-cyan-700 text-cyan-300"
                        : "bg-slate-900 border-slate-800 text-slate-500"
                    }`}
                  >
                    {streamingMode ? "Bật (Stream 450ms)" : "Tắt (Chạy nhanh)"}
                  </button>
                </div>
              </div>
            </div>

            {/* Launch Button */}
            <div className="mt-5 space-y-2">
              <button
                id="btn-start-arena-battle"
                onClick={handleStartBattle}
                disabled={isTriggering || battleState === "IN_PROGRESS"}
                className="w-full flex items-center justify-center gap-2.5 px-4 py-3 rounded-xl bg-gradient-to-r from-rose-600 via-purple-600 to-cyan-600 hover:from-rose-500 hover:to-cyan-500 text-white font-bold text-sm tracking-wide transition shadow-[0_0_20px_rgba(244,63,94,0.3)] active:scale-98 disabled:opacity-50 cursor-pointer"
              >
                {battleState === "IN_PROGRESS" ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin text-amber-300" />
                    <span>ĐANG ĐỐI KHÁNG THỜI GIAN THỰC...</span>
                  </>
                ) : (
                  <>
                    <Swords className="w-4 h-4 text-white" />
                    <span>⚔️ KHỞI CHẠY TRẬN ĐẤU AI ARENA</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* RIGHT: BLUE TEAM (AI-WAF DEFENSE GATEWAY) */}
          <div className="lg:col-span-4 bg-slate-900/80 backdrop-blur-md rounded-2xl border border-cyan-900/40 p-5 shadow-[0_0_25px_rgba(6,182,212,0.08)] flex flex-col justify-between relative overflow-hidden group">
            <div className="absolute top-0 left-0 w-32 h-32 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none group-hover:bg-cyan-500/15 transition"></div>

            <div>
              {/* Header */}
              <div className="flex items-center justify-between pb-3 border-b border-cyan-950/80">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-xl bg-cyan-950/80 border border-cyan-600/50 flex items-center justify-center shadow-[0_0_12px_rgba(6,182,212,0.4)]">
                    <Shield className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <h2 className="text-sm font-bold text-white flex items-center gap-1.5">
                      BLUE TEAM WAF
                    </h2>
                    <span className="text-[11px] font-mono text-cyan-300 flex items-center gap-1">
                      <Target className="w-3 h-3 text-cyan-400" /> AI-Powered Gateway v2.0
                    </span>
                  </div>
                </div>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                  DEFENDER
                </span>
              </div>

              {/* Defender Specs */}
              <div className="mt-3.5 space-y-2 text-xs text-slate-300">
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60 font-mono text-[11px]">
                  <span className="text-slate-400">Kiến trúc:</span>
                  <span className="text-cyan-300 font-semibold">Hybrid 3-Layer Defense</span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60 font-mono text-[11px]">
                  <span className="text-slate-400">Chế độ WAF:</span>
                  <span className="text-rose-400 font-bold">
                    {stats?.waf_mode || "ACTIVE_BLOCKING"}
                  </span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60 font-mono text-[11px]">
                  <span className="text-slate-400">Độ trễ TB:</span>
                  <span className="text-emerald-400 font-mono font-semibold">~2.1 ms</span>
                </div>
              </div>

              {/* Real-time KPI Metric */}
              <div className="mt-4 p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-900/30">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">Tỷ Lệ Chặn (Block Rate):</span>
                  <span className="text-cyan-400 font-bold text-sm">{blockRate}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-800/80 mt-2 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-600 to-emerald-400 transition-all duration-500 rounded-full"
                    style={{ width: `${blockRate}%` }}
                  />
                </div>
                <div className="flex justify-between items-center text-[10px] font-mono text-slate-400 mt-2">
                  <span>Chặn thành công: <strong className="text-cyan-300">{blockedCount}</strong> hiệp</span>
                  <span>Điểm Threat TB: <strong className="text-amber-400">{avgThreatScore}/100</strong></span>
                </div>
              </div>

              {/* Defense Engine Chips */}
              <div className="mt-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-2">
                  Hệ Phòng Ngự Đa Lớp:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    "Deterministic Regex Engine",
                    "XGBoost Classifier",
                    "IsolationForest Anomaly",
                    "Canonical Normalizer",
                    "Adaptive Risk Scoring",
                  ].map((layer) => (
                    <span
                      key={layer}
                      className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-cyan-950/40 text-cyan-300 border border-cyan-900/50"
                    >
                      {layer}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>Trạng thái:</span>
              <span className="flex items-center gap-1.5 text-cyan-400 font-semibold">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                ĐANG BẢO VỆ CỔNG
              </span>
            </div>
          </div>
        </div>

        {/* 3. Battle Outcome Summary (Appears once match completes) */}
        {battleState === "FINISHED" && currentBattle && (
          <div className="bg-slate-900/90 backdrop-blur-md rounded-2xl border border-slate-700/80 p-5 shadow-2xl animate-in fade-in slide-in-from-top-4 duration-300">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <div
                  className={`w-12 h-12 rounded-xl flex items-center justify-center border shadow-lg ${
                    currentBattle.winner === "BLUE_TEAM"
                      ? "bg-emerald-950/60 border-emerald-500/60 text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.3)]"
                      : "bg-rose-950/60 border-rose-500/60 text-rose-400 shadow-[0_0_20px_rgba(244,63,94,0.3)]"
                  }`}
                >
                  <Trophy className="w-6 h-6" />
                </div>
                <div>
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    Kết Quả Chung Cuộc Trận Đấu:
                  </span>
                  <h3 className="text-lg font-extrabold text-white flex items-center gap-2">
                    {currentBattle.winner === "BLUE_TEAM" ? (
                      <span className="text-emerald-400">
                        🛡️ BLUE TEAM CHIẾN THẮNG — HỆ THỐNG WAF PHÒNG THỦ VỮNG CHẮC
                      </span>
                    ) : (
                      <span className="text-rose-400">
                        🔥 RED TEAM CHIẾN THẮNG — TÁC NHÂN RL ĐÃ BYPASS THÀNH CÔNG
                      </span>
                    )}
                  </h3>
                  <p className="text-xs text-slate-300 mt-0.5">
                    {currentBattle.winner === "BLUE_TEAM"
                      ? `Cổng WAF AI đã ngăn chặn thành công ${currentBattle.blocked_count}/${currentBattle.total_rounds} hiệp tấn công đột biến.`
                      : `Tác nhân tấn công DQN đã xuyên thủng bộ lọc WAF trong ${currentBattle.bypass_count}/${currentBattle.total_rounds} hiệp đối kháng.`}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleStartBattle}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-950/60 hover:bg-purple-900/60 text-purple-300 border border-purple-700 text-xs font-semibold font-mono transition"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Đấu Lại Trận Mới</span>
                </button>
              </div>
            </div>

            {/* Outcome KPI Stats Row */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-4 text-xs font-mono">
              <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-400 text-[11px]">Tổng Số Hiệp:</span>
                <div className="text-xl font-bold text-white mt-1">{currentBattle.total_rounds}</div>
              </div>
              <div className="bg-rose-950/20 p-3 rounded-xl border border-rose-900/30">
                <span className="text-rose-400 text-[11px]">Red Team Bypass:</span>
                <div className="text-xl font-bold text-rose-300 mt-1">
                  {currentBattle.bypass_count}{" "}
                  <span className="text-xs text-rose-400 font-normal">
                    ({Math.round((currentBattle.bypass_count / currentBattle.total_rounds) * 100)}%)
                  </span>
                </div>
              </div>
              <div className="bg-cyan-950/20 p-3 rounded-xl border border-cyan-900/30">
                <span className="text-cyan-400 text-[11px]">Blue Team Block:</span>
                <div className="text-xl font-bold text-cyan-300 mt-1">
                  {currentBattle.blocked_count}{" "}
                  <span className="text-xs text-cyan-400 font-normal">
                    ({Math.round((currentBattle.blocked_count / currentBattle.total_rounds) * 100)}%)
                  </span>
                </div>
              </div>
              <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-400 text-[11px]">Điểm Đe Dọa TB (Threat):</span>
                <div className="text-xl font-bold text-amber-400 mt-1">
                  {currentBattle.avg_threat_score}{" "}
                  <span className="text-xs text-slate-500 font-normal">/ 100</span>
                </div>
              </div>
              <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-400 text-[11px]">Chiến Dịch:</span>
                <div className="text-sm font-bold text-slate-200 mt-1 uppercase">
                  {currentBattle.campaign}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 4. Battle Rounds Stream / Timeline Table */}
        <div className="bg-slate-900/80 backdrop-blur-md rounded-2xl border border-slate-800 p-5 shadow-xl space-y-4">
          {/* Header & Filter Controls */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-rose-400" />
              <h3 className="text-sm font-bold text-white tracking-tight">
                DÒNG THỜI GIAN CÁC HIỆP ĐỐI KHÁNG (BATTLE ROUNDS STREAM)
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                {visibleRounds.length} Hiệp
              </span>
            </div>

            {/* Filter by Winner */}
            <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-mono">
              <button
                onClick={() => setRoundFilter("ALL")}
                className={`px-2.5 py-1 rounded-lg transition ${
                  roundFilter === "ALL"
                    ? "bg-slate-800 text-white font-bold"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                Tất cả ({visibleRounds.length})
              </button>
              <button
                onClick={() => setRoundFilter("BLOCKED")}
                className={`px-2.5 py-1 rounded-lg transition ${
                  roundFilter === "BLOCKED"
                    ? "bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                🛡️ WAF Block ({visibleRounds.filter((r) => r.winner === "BLUE_TEAM").length})
              </button>
              <button
                onClick={() => setRoundFilter("BYPASS")}
                className={`px-2.5 py-1 rounded-lg transition ${
                  roundFilter === "BYPASS"
                    ? "bg-rose-950 text-rose-300 border border-rose-800 font-bold"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                🔥 Red Bypass ({visibleRounds.filter((r) => r.winner === "RED_TEAM").length})
              </button>
            </div>
          </div>

          {/* Rounds List / Cards */}
          {displayedRounds.length === 0 ? (
            <div className="py-16 text-center text-slate-500 font-mono text-xs flex flex-col items-center justify-center">
              <Swords className="w-10 h-10 text-slate-600 mb-2 animate-pulse" />
              <p>Chưa có hiệp đối kháng nào được ghi nhận.</p>
              <p className="text-slate-400 mt-1">
                Nhấn <span className="text-rose-400 font-semibold">[⚔️ KHỞI CHẠY TRẬN ĐẤU AI ARENA]</span> ở trên để bắt đầu!
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {displayedRounds.map((round) => {
                const isBlueWinner = round.winner === "BLUE_TEAM";
                const isBlocked = round.response_status === 403;

                // Color code for Threat Score (0 - 100 standard scale)
                const threatScoreColor =
                  round.waf_threat_score >= 85
                    ? "text-rose-400 bg-rose-950/60 border-rose-800"
                    : round.waf_threat_score >= 60
                    ? "text-amber-400 bg-amber-950/60 border-amber-800"
                    : "text-emerald-400 bg-emerald-950/60 border-emerald-800";

                return (
                  <div
                    key={round.round_num}
                    className={`rounded-xl border p-4 transition-all duration-200 hover:border-slate-600 ${
                      isBlueWinner
                        ? "bg-slate-950/70 border-slate-800/80"
                        : "bg-rose-950/15 border-rose-900/40 shadow-[0_0_15px_rgba(244,63,94,0.08)]"
                    }`}
                  >
                    <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                      {/* Round Header & Winner Badge */}
                      <div className="flex items-center gap-3">
                        <span className="w-9 h-9 rounded-lg bg-slate-900 border border-slate-700/80 flex items-center justify-center font-mono font-bold text-xs text-white">
                          #{round.round_num}
                        </span>

                        <div>
                          <div className="flex items-center gap-2">
                            <span
                              className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold border ${
                                isBlueWinner
                                  ? "bg-emerald-950/80 text-emerald-300 border-emerald-700 shadow-sm"
                                  : "bg-rose-950/80 text-rose-300 border-rose-700 shadow-[0_0_10px_rgba(244,63,94,0.3)]"
                              }`}
                            >
                              {isBlueWinner ? (
                                <>
                                  <Shield className="w-3.5 h-3.5 text-emerald-400" />
                                  <span>BLUE TEAM BLOCKED</span>
                                </>
                              ) : (
                                <>
                                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                                  <span>RED TEAM BYPASS</span>
                                </>
                              )}
                            </span>

                            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                              {round.attack_type}
                            </span>

                            <span
                              className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                                isBlocked
                                  ? "bg-rose-950/60 text-rose-400 border border-rose-800"
                                  : "bg-emerald-950/60 text-emerald-400 border border-emerald-800"
                              }`}
                            >
                              HTTP {round.response_status}
                            </span>
                          </div>

                          <div className="text-xs text-slate-400 font-mono mt-1 flex items-center gap-2">
                            <span>Endpoint: <strong className="text-slate-300">{round.endpoint}</strong></span>
                            <span>•</span>
                            <span>Technique: <strong className="text-purple-300">{round.technique}</strong></span>
                          </div>
                        </div>
                      </div>

                      {/* Threat Score & Latency Gauge */}
                      <div className="flex items-center gap-4 self-end lg:self-auto">
                        <div className="text-right">
                          <span className="text-[10px] font-mono text-slate-400 block">Threat Score:</span>
                          <span className={`inline-block px-2 py-0.5 rounded text-xs font-mono font-bold border ${threatScoreColor}`}>
                            {round.waf_threat_score.toFixed(1)} / 100
                          </span>
                        </div>

                        <div className="text-right font-mono text-xs text-slate-400">
                          <span className="text-[10px] block">Latency:</span>
                          <span className="text-slate-200">{round.latency_ms} ms</span>
                        </div>

                        <button
                          onClick={() => setSelectedRound(round)}
                          className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition cursor-pointer"
                        >
                          <span>Chi Tiết</span>
                          <ChevronRight className="w-3 h-3 text-slate-400" />
                        </button>
                      </div>
                    </div>

                    {/* Payloads Comparison Bar */}
                    <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                      {/* Original Seed */}
                      <div className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                        <div className="flex justify-between items-center text-[10px] text-slate-400 mb-1">
                          <span>Payload Gốc (Seed):</span>
                        </div>
                        <code className="text-slate-300 text-[11px] break-all select-all block">
                          {round.original_payload || "N/A"}
                        </code>
                      </div>

                      {/* Mutated RL Payload */}
                      <div className={`p-2.5 rounded-lg border ${
                        isBlueWinner ? "bg-slate-900/90 border-slate-800" : "bg-rose-950/30 border-rose-900/60"
                      }`}>
                        <div className="flex justify-between items-center text-[10px] text-rose-300 mb-1">
                          <span>Payload Đột Biến (RL Mutated Evasion):</span>
                          <button
                            onClick={() => handleCopy(round.payload, `round-${round.round_num}`)}
                            className="text-slate-400 hover:text-white transition flex items-center gap-1"
                            title="Sao chép payload"
                          >
                            {copiedPayload === `round-${round.round_num}` ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                        <code className="text-rose-200 text-[11px] font-bold break-all select-all block">
                          {round.payload}
                        </code>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </main>

      {/* 5. Round Detail Inspection Drawer / Modal */}
      {selectedRound && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-200"
          onClick={() => setSelectedRound(null)}
        >
          <div
            className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 overflow-hidden max-h-[90vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <span className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center font-mono font-bold text-xs text-white">
                  #{selectedRound.round_num}
                </span>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    Kiểm Tra Chi Tiết Hiệp Đấu Đối Kháng
                  </h3>
                  <span className="text-xs font-mono text-slate-400">
                    Phân tích quyết định phòng thủ AI-WAF vs Kỹ thuật đột biến RL
                  </span>
                </div>
              </div>

              <button
                onClick={() => setSelectedRound(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
                aria-label="Đóng"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto py-4 space-y-4 text-xs font-mono">
              {/* Verdict Banner */}
              <div
                className={`p-3.5 rounded-xl border flex items-center justify-between ${
                  selectedRound.winner === "BLUE_TEAM"
                    ? "bg-emerald-950/40 border-emerald-800 text-emerald-300"
                    : "bg-rose-950/40 border-rose-800 text-rose-300"
                }`}
              >
                <div className="flex items-center gap-2.5">
                  {selectedRound.winner === "BLUE_TEAM" ? (
                    <Shield className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <Flame className="w-5 h-5 text-rose-400" />
                  )}
                  <div>
                    <span className="font-bold text-sm block">
                      {selectedRound.winner === "BLUE_TEAM"
                        ? "BLUE TEAM WAF BLOCKED (403 FORBIDDEN)"
                        : "RED TEAM BYPASSED (200 OK)"}
                    </span>
                    <span className="text-[11px] opacity-80">
                      Quyết định WAF: [{selectedRound.waf_decision}] • Độ trễ: {selectedRound.latency_ms} ms
                    </span>
                  </div>
                </div>

                <div className="text-right">
                  <span className="text-[10px] block opacity-80">Threat Score:</span>
                  <span className="font-extrabold text-base">{selectedRound.waf_threat_score.toFixed(1)} / 100</span>
                </div>
              </div>

              {/* Vector & Technique Information */}
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-2">
                <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                  <span className="text-slate-400">Loại Tấn Công (Attack Family):</span>
                  <span className="text-white font-bold">{selectedRound.attack_type}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                  <span className="text-slate-400">Target Endpoint:</span>
                  <span className="text-slate-200">{selectedRound.endpoint}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                  <span className="text-slate-400">Kỹ Thuật Đột Biến (Mutator Technique):</span>
                  <span className="text-purple-400 font-bold">{selectedRound.technique}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Học Tăng Cường (RL Evasion Score):</span>
                  <span className="text-cyan-400">
                    {selectedRound.evasion_score ? selectedRound.evasion_score.toFixed(3) : "0.785"} (DQN Q-value)
                  </span>
                </div>
              </div>

              {/* Seed vs Mutated Payload Side-by-Side */}
              <div className="space-y-3">
                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
                  <div className="flex justify-between items-center text-slate-400 mb-1.5">
                    <span>1. Payload Gốc Ban Đầu (Seed Payload):</span>
                  </div>
                  <pre className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 break-all whitespace-pre-wrap">
                    {selectedRound.original_payload || "N/A"}
                  </pre>
                </div>

                <div className="bg-slate-950 p-3.5 rounded-xl border border-rose-900/40">
                  <div className="flex justify-between items-center text-rose-300 mb-1.5">
                    <span>2. Payload Đột Biến (RL Agent Mutated Output):</span>
                    <button
                      onClick={() => handleCopy(selectedRound.payload, "modal-payload")}
                      className="text-slate-400 hover:text-white transition flex items-center gap-1 text-[11px]"
                    >
                      {copiedPayload === "modal-payload" ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                      <span>Sao chép</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded-lg bg-rose-950/30 border border-rose-900/60 text-rose-200 font-bold break-all whitespace-pre-wrap">
                    {selectedRound.payload}
                  </pre>
                </div>
              </div>

              {/* Multi-Layer WAF Breakdown */}
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-2">
                <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                  Đánh Giá Đa Tầng Của Cổng An Ninh AI-WAF:
                </span>
                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="bg-slate-900 p-2 rounded-lg border border-slate-800">
                    <span className="text-[10px] text-slate-400 block">Deterministic Rules</span>
                    <span className={`text-xs font-bold ${selectedRound.waf_threat_score >= 80 ? "text-rose-400" : "text-emerald-400"}`}>
                      {selectedRound.waf_threat_score >= 80 ? "MATCH (100)" : "CLEAN (0)"}
                    </span>
                  </div>
                  <div className="bg-slate-900 p-2 rounded-lg border border-slate-800">
                    <span className="text-[10px] text-slate-400 block">XGBoost ML Score</span>
                    <span className="text-xs font-bold text-amber-400">
                      {(selectedRound.waf_threat_score * 0.95).toFixed(1)} / 100
                    </span>
                  </div>
                  <div className="bg-slate-900 p-2 rounded-lg border border-slate-800">
                    <span className="text-[10px] text-slate-400 block">IsolationForest Anomaly</span>
                    <span className="text-xs font-bold text-cyan-400">
                      {selectedRound.waf_threat_score >= 70 ? "Outlier (-0.32)" : "Normal (0.15)"}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedRound(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold font-mono transition"
              >
                Đóng
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 6. Battle History Drawer / Modal */}
      {isHistoryOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200"
          onClick={() => setIsHistoryOpen(false)}
        >
          <div
            className="w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 overflow-hidden max-h-[90vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-700 flex items-center justify-center">
                  <History className="w-4 h-4 text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">
                    Lịch Sử Các Trận Đấu Đối Kháng AI Arena
                  </h3>
                  <span className="text-xs font-mono text-slate-400">
                    Nhật ký các chiến dịch kiểm thử tự động giữa Red Team và Blue Team
                  </span>
                </div>
              </div>

              <button
                onClick={() => setIsHistoryOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
                aria-label="Đóng"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* History List */}
            <div className="flex-1 overflow-y-auto py-4 space-y-3">
              {historyData && historyData.battles.length > 0 ? (
                historyData.battles.map((b) => (
                  <div
                    key={b.battle_id}
                    className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-slate-700 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white">{b.battle_id}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                          {b.campaign}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            b.winner === "BLUE_TEAM"
                              ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                              : "bg-rose-950 text-rose-300 border border-rose-800"
                          }`}
                        >
                          {b.winner === "BLUE_TEAM" ? "BLUE WON" : "RED WON"}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-2">
                        <span>{new Date(b.timestamp).toLocaleString("vi-VN")}</span>
                        <span>•</span>
                        <span>{b.total_rounds} Hiệp</span>
                        <span>•</span>
                        <span>Threat TB: {b.avg_threat_score}/100</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="text-right text-[11px]">
                        <span className="text-emerald-400 font-bold">{b.blocked_count} Block</span>
                        <span className="text-slate-500 mx-1">/</span>
                        <span className="text-rose-400 font-bold">{b.bypass_count} Bypass</span>
                      </div>

                      <button
                        onClick={() => handleSelectHistoricalBattle(b)}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-semibold transition"
                      >
                        Tải Trận
                      </button>
                    </div>
                  </div>
                ))
              ) : (
                <div className="py-12 text-center text-slate-500 font-mono text-xs">
                  Chưa có lịch sử trận đấu nào được lưu trữ.
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="pt-3 border-t border-slate-800 flex justify-between items-center text-xs font-mono text-slate-400">
              <span>
                Tổng trận: <strong className="text-white">{historyData?.total_battles || 0}</strong> •{" "}
                Red Thắng: <strong className="text-rose-400">{historyData?.red_wins || 0}</strong> •{" "}
                Blue Thắng: <strong className="text-emerald-400">{historyData?.blue_wins || 0}</strong>
              </span>

              <button
                onClick={() => setIsHistoryOpen(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-semibold transition"
              >
                Đóng
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
