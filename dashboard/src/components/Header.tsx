"use client";

import React from "react";
import { Shield, RefreshCw, Trash2, Activity } from "lucide-react";
import { DashboardStats } from "@/types/dashboard";

interface HeaderProps {
  stats: DashboardStats | null;
  pollingInterval: number; // in seconds (0 = off)
  setPollingInterval: (val: number) => void;
  onRefresh: () => void;
  onResetDemo: () => void;
  isRefreshing: boolean;
  isResetting: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  stats,
  pollingInterval,
  setPollingInterval,
  onRefresh,
  onResetDemo,
  isRefreshing,
  isResetting,
}) => {
  const targetReachable = stats?.target_status === "ok";

  return (
    <header className="w-full bg-slate-900/80 backdrop-blur-md border-b border-slate-800/80 px-6 py-3.5 sticky top-0 z-30 flex flex-wrap items-center justify-between gap-4">
      {/* Brand & App Title */}
      <div className="flex items-center gap-3.5">
        <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-purple-950/60 border border-purple-600/50 shadow-[0_0_20px_rgba(168,85,247,0.3)]">
          <Shield className="w-6 h-6 text-purple-400 drop-shadow-[0_0_8px_rgba(168,85,247,0.5)]" />
          <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-purple-500"></span>
          </span>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              <span className="text-purple-400 font-mono text-sm">[SHIELD]</span> Web API Security Platform
            </h1>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-mono">
              SOC v2.0
            </span>
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-400 mt-0.5 font-mono">
            {/* Target Status */}
            <span className="flex items-center gap-1.5">
              Target: <span className="text-slate-300">{stats?.target_url || "http://juice-shop:3000"}</span>
              <span className={`inline-flex items-center gap-1 px-1.5 py-0.2 rounded text-[11px] font-semibold ${
                targetReachable
                  ? "text-emerald-400 bg-emerald-950/50 border border-emerald-800/40"
                  : "text-rose-400 bg-rose-950/50 border border-rose-800/40"
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${targetReachable ? "bg-emerald-400 animate-pulse" : "bg-rose-500"}`} />
                {targetReachable ? `${stats?.target_latency_ms || 12}ms` : "Unreachable"}
              </span>
            </span>

            <span className="text-slate-600">|</span>

            {/* WAF Mode */}
            <span className="flex items-center gap-1.5">
              Mode:
              <span className="text-amber-400 bg-amber-950/40 border border-amber-800/40 px-2 py-0.2 rounded text-[11px] font-semibold">
                [{stats?.waf_mode || "MONITOR_ONLY"}]
              </span>
            </span>
          </div>
        </div>
      </div>

      {/* Header Actions & Smart Polling Controls */}
      <div className="flex items-center gap-3">
        {/* Manual Refresh */}
        <button
          id="btn-refresh"
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/80 text-xs font-medium transition active:scale-95 disabled:opacity-50 shadow-sm cursor-pointer"
          title="Tải lại số liệu ngay lập tức"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-cyan-400" : "text-slate-400"}`} />
          <span>Refresh</span>
        </button>

        {/* Reset Demo Button */}
        <button
          id="btn-reset-demo"
          onClick={onResetDemo}
          disabled={isResetting}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/50 text-xs font-medium transition active:scale-95 disabled:opacity-50 shadow-sm cursor-pointer"
          title="Dọn sạch log dữ liệu test để chuẩn bị demo mới"
        >
          <Trash2 className="w-3.5 h-3.5 text-rose-400" />
          <span>Reset Demo</span>
        </button>

        {/* Smart Polling Pill */}
        <div className="flex items-center gap-1.5 bg-slate-950/80 border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono">
          <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span className="text-slate-400">Polling:</span>
          <div className="flex items-center bg-slate-900 rounded p-0.5 border border-slate-800 text-[11px]">
            {[3, 5, 0].map((sec) => (
              <button
                key={sec}
                onClick={() => setPollingInterval(sec)}
                className={`px-2 py-0.5 rounded transition ${
                  pollingInterval === sec
                    ? "bg-cyan-500 text-slate-950 font-bold shadow-sm"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {sec === 0 ? "Off" : `${sec}s`}
              </button>
            ))}
          </div>
        </div>
      </div>
    </header>
  );
};
