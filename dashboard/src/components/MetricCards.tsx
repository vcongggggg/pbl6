"use client";

import React from "react";
import {
  ArrowUpDown,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Flame,
  FolderTree,
  Terminal,
  CheckCircle2,
} from "lucide-react";
import { DashboardStats } from "@/types/dashboard";

interface MetricCardsProps {
  stats: DashboardStats | null;
  onSimulate: (type: string) => void;
  isSimulating: boolean;
  activeSimulation: string | null;
}

export const MetricCards: React.FC<MetricCardsProps> = ({
  stats,
  onSimulate,
  isSimulating,
  activeSimulation,
}) => {
  const totalRequests = stats?.total_requests ?? 0;
  const attacksDetected = stats?.attacks_detected ?? 0;
  const threatScore = stats?.avg_threat_score ?? 0;
  const safeRate = stats?.safe_request_rate ?? 100;

  // Derive estimated RPS
  const rps = totalRequests > 0 ? Math.max(1, Math.round(totalRequests / 90)) : 0;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
      {/* 1. TOTAL TRAFFIC */}
      <div className="bg-slate-900/70 backdrop-blur-md border border-slate-800/80 rounded-xl p-4.5 flex flex-col justify-between hover:border-slate-700 transition shadow-lg relative overflow-hidden group">
        <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 rounded-full blur-2xl group-hover:bg-cyan-500/10 transition"></div>
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold tracking-wider text-slate-400 uppercase flex items-center gap-1.5 font-mono">
            <ArrowUpDown className="w-3.5 h-3.5 text-cyan-400" />
            Total Traffic
          </span>
          <span className="text-[11px] px-2 py-0.5 rounded-full bg-cyan-950/60 text-cyan-400 border border-cyan-800/50 font-mono">
            RPS: {rps} req/s
          </span>
        </div>
        <div className="mt-3">
          <div className="text-3xl font-extrabold text-white font-mono tracking-tight">
            {totalRequests.toLocaleString()}
          </div>
          <p className="text-xs text-slate-400 mt-1 flex items-center gap-1">
            <span className="text-cyan-400 font-semibold">Proxied</span> requests via Gateway
          </p>
        </div>
      </div>

      {/* 2. ATTACKS DETECTED */}
      <div className="bg-slate-900/70 backdrop-blur-md border border-slate-800/80 rounded-xl p-4.5 flex flex-col justify-between hover:border-rose-900/50 transition shadow-lg relative overflow-hidden group">
        <div className="absolute top-0 right-0 w-24 h-24 bg-rose-500/5 rounded-full blur-2xl group-hover:bg-rose-500/10 transition"></div>
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold tracking-wider text-slate-400 uppercase flex items-center gap-1.5 font-mono">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            Attacks Detected
          </span>
          <span className="text-[11px] px-2 py-0.5 rounded-full bg-rose-950/60 text-rose-400 border border-rose-800/50 font-mono">
            Phase 2
          </span>
        </div>
        <div className="mt-3">
          <div className="text-3xl font-extrabold text-white font-mono tracking-tight flex items-baseline gap-2">
            <span>{attacksDetected.toLocaleString()}</span>
            <span className="text-xs text-rose-400 font-normal">incidents</span>
          </div>
          <p className="text-xs text-slate-400 mt-1 truncate">
            SQLi, XSS, Path, Cmd...
          </p>
        </div>
      </div>

      {/* 3. THREAT SCORE */}
      <div className="bg-slate-900/70 backdrop-blur-md border border-slate-800/80 rounded-xl p-4.5 flex flex-col justify-between hover:border-amber-900/50 transition shadow-lg relative overflow-hidden group">
        <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/5 rounded-full blur-2xl group-hover:bg-amber-500/10 transition"></div>
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold tracking-wider text-slate-400 uppercase flex items-center gap-1.5 font-mono">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            Threat Score
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-950/60 text-amber-300 border border-amber-800/50 font-mono">
            Phase Progression
          </span>
        </div>
        <div className="mt-3">
          <div className="text-3xl font-extrabold text-white font-mono tracking-tight flex items-baseline gap-2">
            <span className={threatScore > 50 ? "text-amber-400" : "text-emerald-400"}>
              {threatScore.toFixed(1)}
            </span>
            <span className="text-xs text-slate-500">/ 100</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1 font-mono">
            Rule Engine Phase 2
          </p>
        </div>
      </div>

      {/* 4. SAFE REQUEST RATE */}
      <div className="bg-slate-900/70 backdrop-blur-md border border-slate-800/80 rounded-xl p-4.5 flex flex-col justify-between hover:border-emerald-900/50 transition shadow-lg relative overflow-hidden group">
        <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-500/5 rounded-full blur-2xl group-hover:bg-emerald-500/10 transition"></div>
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold tracking-wider text-slate-400 uppercase flex items-center gap-1.5 font-mono">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            Safe Request Rate
          </span>
          <span className="text-[11px] px-2 py-0.5 rounded-full bg-emerald-950/60 text-emerald-400 border border-emerald-800/50 font-mono">
            Forwarded
          </span>
        </div>
        <div className="mt-3">
          <div className="text-3xl font-extrabold text-emerald-400 font-mono tracking-tight">
            {safeRate.toFixed(1)}%
          </div>
          <p className="text-xs text-slate-400 mt-1 flex items-center gap-1">
            Forwarded <span className="text-emerald-400 font-mono font-semibold">200 OK</span>
          </p>
        </div>
      </div>

      {/* 5. QUICK SIMULATOR PANEL */}
      <div className="bg-slate-900/70 backdrop-blur-md border border-slate-800/80 rounded-xl p-3 flex flex-col justify-between hover:border-purple-800/60 transition shadow-lg relative">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold tracking-wider text-purple-300 uppercase flex items-center gap-1 font-mono">
            <Zap className="w-3.5 h-3.5 text-purple-400" />
            Quick Simulator
          </span>
          <span className="text-[10px] text-slate-500 font-mono">1-Click Test</span>
        </div>

        <div className="grid grid-cols-2 gap-1.5 text-[11px] font-mono">
          {/* SQLi Button */}
          <button
            id="sim-sqli"
            onClick={() => onSimulate("SQLI")}
            disabled={isSimulating}
            className="flex items-center justify-center gap-1 py-1.5 px-2 rounded-lg bg-rose-950/50 hover:bg-rose-900/80 text-rose-300 border border-rose-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer shadow-sm"
          >
            <Flame className="w-3 h-3 text-rose-400" />
            <span>{activeSimulation === "SQLI" ? "Firing..." : "SQLi Test"}</span>
          </button>

          {/* XSS Button */}
          <button
            id="sim-xss"
            onClick={() => onSimulate("XSS")}
            disabled={isSimulating}
            className="flex items-center justify-center gap-1 py-1.5 px-2 rounded-lg bg-amber-950/50 hover:bg-amber-900/80 text-amber-300 border border-amber-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer shadow-sm"
          >
            <Zap className="w-3 h-3 text-amber-400" />
            <span>{activeSimulation === "XSS" ? "Firing..." : "XSS Test"}</span>
          </button>

          {/* Path Traversal Button */}
          <button
            id="sim-path"
            onClick={() => onSimulate("PATH")}
            disabled={isSimulating}
            className="flex items-center justify-center gap-1 py-1.5 px-2 rounded-lg bg-teal-950/50 hover:bg-teal-900/80 text-teal-300 border border-teal-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer shadow-sm"
          >
            <FolderTree className="w-3 h-3 text-teal-400" />
            <span>{activeSimulation === "PATH" ? "Firing..." : "PathTrav"}</span>
          </button>

          {/* Cmd Injection Button */}
          <button
            id="sim-cmd"
            onClick={() => onSimulate("CMD")}
            disabled={isSimulating}
            className="flex items-center justify-center gap-1 py-1.5 px-2 rounded-lg bg-indigo-950/50 hover:bg-indigo-900/80 text-indigo-300 border border-indigo-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer shadow-sm"
          >
            <Terminal className="w-3 h-3 text-indigo-400" />
            <span>{activeSimulation === "CMD" ? "Firing..." : "CmdInject"}</span>
          </button>
        </div>

        {/* Benign Traffic Button (Full width) */}
        <button
          id="sim-benign"
          onClick={() => onSimulate("BENIGN")}
          disabled={isSimulating}
          className="mt-1.5 flex items-center justify-center gap-1 py-1.5 px-2 rounded-lg bg-emerald-950/40 hover:bg-emerald-900/70 text-emerald-300 border border-emerald-800/40 text-[11px] font-mono transition active:scale-95 disabled:opacity-50 cursor-pointer shadow-sm w-full"
        >
          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
          <span>{activeSimulation === "BENIGN" ? "Firing Benign..." : "🍏 Benign Traffic Test"}</span>
        </button>
      </div>
    </div>
  );
};
