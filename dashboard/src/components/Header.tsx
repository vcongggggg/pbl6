"use client";

import React, { useState, useRef, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  RefreshCw,
  Trash2,
  Activity,
  Sparkles,
  Layers,
  Swords,
  ChevronDown,
} from "lucide-react";
import { DashboardStats } from "@/types/dashboard";

interface HeaderProps {
  stats?: DashboardStats | null;
  pollingInterval?: number; // in seconds (0 = off)
  setPollingInterval?: (val: number) => void;
  onRefresh?: () => void;
  onResetDemo?: () => void;
  onSeedDemo?: () => void;
  onToggleWafMode?: () => void;
  isRefreshing?: boolean;
  isResetting?: boolean;
  isSeeding?: boolean;
  isTogglingWaf?: boolean;
  onOpenAttackSessions?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  stats,
  pollingInterval,
  setPollingInterval,
  onRefresh,
  onResetDemo,
  onSeedDemo,
  onToggleWafMode,
  isRefreshing = false,
  isResetting = false,
  isSeeding = false,
  isTogglingWaf = false,
  onOpenAttackSessions,
}) => {
  const pathname = usePathname();
  const targetReachable = stats?.target_status === "ok";
  const [isToolsOpen, setIsToolsOpen] = useState(false);
  const toolsRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (toolsRef.current && !toolsRef.current.contains(e.target as Node)) {
        setIsToolsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <header className="w-full h-14 bg-slate-900/90 backdrop-blur-md border-b border-slate-800/80 px-4 sticky top-0 z-30 flex items-center justify-between gap-3 shrink-0 whitespace-nowrap overflow-visible">
      {/* 1. Brand Logo & Name */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="relative flex items-center justify-center w-8 h-8 rounded-lg bg-purple-950/70 border border-purple-600/60 shadow-[0_0_15px_rgba(168,85,247,0.35)] shrink-0">
          <Shield className="w-4 h-4 text-purple-400 drop-shadow-[0_0_6px_rgba(168,85,247,0.5)]" />
          <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-purple-500"></span>
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm font-bold tracking-tight text-white flex items-center gap-1.5 font-sans">
            <span className="text-purple-400 font-mono text-xs font-semibold">[SHIELD]</span>
            <span>Web API Security</span>
          </span>
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-950/60 text-purple-300 border border-purple-800/50 font-mono font-semibold">
            v3.0
          </span>
        </div>
      </div>

      {/* 2. Navigation Switcher: SOC Command Center vs AI Red-vs-Blue Arena */}
      <nav aria-label="Main Navigation" className="flex items-center bg-slate-950/90 p-1 rounded-lg border border-slate-800 shrink-0 shadow-inner">
        <Link
          href="/"
          className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition ${
            pathname === "/"
              ? "bg-purple-950/90 text-purple-200 border border-purple-500/50 shadow-[0_0_10px_rgba(168,85,247,0.3)]"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
          }`}
        >
          <Shield className="w-3.5 h-3.5 text-purple-400" />
          <span>Blue Team SOC</span>
        </Link>
        <Link
          href="/arena"
          className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition ${
            pathname === "/arena"
              ? "bg-rose-950/90 text-rose-200 border border-rose-500/50 shadow-[0_0_10px_rgba(244,63,94,0.3)]"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
          }`}
        >
          <Swords className="w-3.5 h-3.5 text-rose-400" />
          <span>Red Team Pentest AI</span>
        </Link>
      </nav>

      {/* 3. Live Target Status & WAF Mode Switcher & Demo Tools */}
      <div className="flex items-center gap-2.5 shrink-0 text-xs font-mono">
        {/* Target Status Pill */}
        <div className="hidden md:flex items-center gap-1.5 px-2 py-1 rounded bg-slate-950/70 border border-slate-800/80 text-[11px]">
          <span className="text-slate-400">Target:</span>
          <span className="text-slate-300 truncate max-w-[140px] font-mono">
            {stats?.target_url?.replace("http://", "") || "vulnerable-api:5000"}
          </span>
          <span className={`inline-flex items-center gap-1 px-1.5 py-0.2 rounded text-[10px] font-semibold ${
            targetReachable
              ? "text-emerald-400 bg-emerald-950/50 border border-emerald-800/40"
              : "text-rose-400 bg-rose-950/50 border border-rose-800/40"
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${targetReachable ? "bg-emerald-400 animate-pulse" : "bg-rose-500"}`} />
            {targetReachable ? `${stats?.target_latency_ms ?? 0}ms` : "Down"}
          </span>
        </div>

        {/* Interactive WAF Mode Switcher */}
        <button
          id="btn-toggle-waf-mode"
          onClick={onToggleWafMode}
          disabled={isTogglingWaf || !onToggleWafMode}
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border transition cursor-pointer active:scale-95 disabled:opacity-50 ${
            stats?.waf_mode === "ACTIVE_BLOCKING"
              ? "text-rose-300 bg-rose-950/70 border-rose-600/80 shadow-[0_0_12px_rgba(244,63,94,0.35)]"
              : "text-amber-300 bg-amber-950/60 border-amber-600/70 hover:bg-amber-900/60"
          }`}
          title="Bấm để chuyển đổi giữa [MONITOR_ONLY] (Chỉ ghi log) và [ACTIVE_BLOCKING] (Chặn 403)"
          aria-label={`Toggle WAF Mode. Current: ${stats?.waf_mode || "ACTIVE_BLOCKING"}`}
        >
          <span
            className={`w-2 h-2 rounded-full ${
              stats?.waf_mode === "ACTIVE_BLOCKING" ? "bg-rose-400 animate-pulse" : "bg-amber-400"
            }`}
          />
          <span className="font-mono">[{stats?.waf_mode || "ACTIVE_BLOCKING"}]</span>
          <span className="text-[10px] text-slate-300 underline font-sans ml-0.5">
            {stats?.waf_mode === "ACTIVE_BLOCKING" ? "Chặn 403" : "Giám sát"}
          </span>
        </button>

        {/* Demo Tools Dropdown Menu (Consolidated to avoid wrapping) */}
        <div className="relative" ref={toolsRef}>
          <button
            onClick={() => setIsToolsOpen(!isToolsOpen)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800/90 hover:bg-slate-700/90 text-slate-200 border border-slate-700 text-xs font-medium transition active:scale-95 cursor-pointer shadow-sm"
          >
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>Công cụ Demo</span>
            <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform ${isToolsOpen ? "rotate-180" : ""}`} />
          </button>

          {isToolsOpen && (
            <div className="absolute right-0 mt-2 w-56 bg-slate-900 border border-slate-700/80 rounded-xl shadow-2xl p-2 z-50 text-xs font-mono space-y-1 backdrop-blur-xl animate-in fade-in slide-in-from-top-2">
              {/* Refresh button */}
              {onRefresh && (
                <button
                  onClick={() => {
                    onRefresh();
                    setIsToolsOpen(false);
                  }}
                  disabled={isRefreshing}
                  className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white transition cursor-pointer text-left"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-cyan-400" : "text-cyan-400"}`} />
                  <span>{isRefreshing ? "Đang tải..." : "Tải lại dữ liệu (Refresh)"}</span>
                </button>
              )}

              {/* Seed Demo */}
              {onSeedDemo && (
                <button
                  onClick={() => {
                    onSeedDemo();
                    setIsToolsOpen(false);
                  }}
                  disabled={isSeeding}
                  className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg hover:bg-emerald-950/50 text-emerald-300 hover:text-emerald-200 transition cursor-pointer text-left"
                >
                  <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{isSeeding ? "Đang nạp..." : "Nạp 125+ Data Mẫu"}</span>
                </button>
              )}

              {/* Attack Sessions */}
              {onOpenAttackSessions && (
                <button
                  onClick={() => {
                    onOpenAttackSessions();
                    setIsToolsOpen(false);
                  }}
                  className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg hover:bg-red-950/50 text-red-300 hover:text-red-200 transition cursor-pointer text-left"
                >
                  <Layers className="w-3.5 h-3.5 text-red-400" />
                  <span>Kill Chain Sessions</span>
                </button>
              )}

              {/* Reset Demo */}
              {onResetDemo && (
                <button
                  onClick={() => {
                    onResetDemo();
                    setIsToolsOpen(false);
                  }}
                  disabled={isResetting}
                  className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg hover:bg-rose-950/50 text-rose-300 hover:text-rose-200 transition cursor-pointer text-left"
                >
                  <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                  <span>Dọn log dữ liệu test</span>
                </button>
              )}

              {/* Smart Polling Select */}
              {pollingInterval !== undefined && setPollingInterval && (
                <div className="pt-1 mt-1 border-t border-slate-800 px-2 py-1 flex items-center justify-between">
                  <span className="text-[11px] text-slate-400">Polling:</span>
                  <div className="flex items-center gap-1">
                    {[3, 5, 0].map((sec) => (
                      <button
                        key={sec}
                        onClick={() => setPollingInterval(sec)}
                        className={`px-1.5 py-0.5 rounded text-[10px] ${
                          pollingInterval === sec
                            ? "bg-cyan-500 text-slate-950 font-bold"
                            : "bg-slate-800 text-slate-400 hover:text-white"
                        }`}
                      >
                        {sec === 0 ? "Off" : `${sec}s`}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
