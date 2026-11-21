"use client";

import React from "react";
import { CyberRangeTopology } from "@/types/dashboard";
import {
  Server,
  Shield,
  Radio,
  Zap,
  ArrowRight,
  Terminal,
  Activity,
} from "lucide-react";

interface NetworkTopologyMapProps {
  topology?: CyberRangeTopology | null;
}

export const NetworkTopologyMap: React.FC<NetworkTopologyMapProps> = ({ topology }) => {
  if (!topology) {
    return (
      <div className="bg-slate-900/70 backdrop-blur-md border border-slate-800/80 rounded-xl p-6 shadow-lg flex flex-col items-center justify-center min-h-[160px] text-center space-y-2">
        <Radio className="w-5 h-5 text-cyan-400 animate-pulse" />
        <h3 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider">
          Connecting to Distributed Cyber Range Topology...
        </h3>
        <p className="text-[11px] text-slate-500 font-mono">
          Probing physical LAN route: Máy 2 (Red Team) ➔ Mạng LAN (RTT) ➔ Máy 1 (WAF :8000) ➔ Target API (:5000)
        </p>
      </div>
    );
  }

  const redTeam = topology.red_team;
  const network = topology.network;
  const blueTeam = topology.blue_team;
  const targetApp = topology.target_api;

  const isUpstreamHealthy = targetApp.status === "ok" || targetApp.status === "healthy";
  const rttDisplay = network.rtt_latency_ms != null ? network.rtt_latency_ms.toFixed(2) : "N/A";
  const lossDisplay = network.packet_loss_pct != null ? network.packet_loss_pct.toFixed(1) : "N/A";

  return (
    <div className="bg-slate-900/70 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-lg flex flex-col space-y-4">
      {/* Header Info */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800/70 gap-2">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Radio className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold tracking-wider uppercase text-slate-100 font-mono">
                Distributed Cyber Range Topology
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-800/60">
                Ref 17 Elsevier 2020
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans">
              Non-localhost physically routed testbed: Machine 2 (Adversary) ➔ LAN Ethernet ➔ Machine 1 (WAF + Bookie API)
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-800/60 border border-slate-700/50 text-slate-300">
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
            <span>RTT:</span>
            <span className="font-bold text-emerald-300">
              {rttDisplay === "N/A" ? "N/A" : `${rttDisplay} ms`}
            </span>
          </div>
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-800/60 border border-slate-700/50 text-slate-300">
            <span>Loss:</span>
            <span className="font-bold text-emerald-400">
              {lossDisplay === "N/A" ? "N/A" : `${lossDisplay}%`}
            </span>
          </div>
        </div>
      </div>

      {/* Visual Pipeline Grid */}
      <div className="grid grid-cols-1 md:grid-cols-11 gap-3 items-center">
        {/* Node 1: Red Team (Máy 2) - 3 cols */}
        <div className="md:col-span-3 bg-slate-950/70 border border-rose-900/40 hover:border-rose-700/60 transition-all rounded-lg p-3.5 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-16 h-16 bg-rose-500/5 rounded-full blur-xl group-hover:bg-rose-500/10 transition-all" />
          <div className="flex items-center justify-between mb-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1">
              <Terminal className="w-3 h-3 text-rose-400" />
              MÁY 2 (RED TEAM)
            </span>
            <span className="text-[11px] font-mono text-slate-400 truncate max-w-[130px]">{redTeam.ip}</span>
          </div>
          <h3 className="text-xs font-bold text-slate-100 font-mono tracking-tight">{redTeam.name}</h3>
          <p className="text-[11px] text-slate-400 font-sans mt-0.5 line-clamp-1">{redTeam.role}</p>

          <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-400 truncate max-w-[140px]" title={redTeam.agent_model}>
              Agent: {redTeam.agent_model || "N/A"}
            </span>
            <span className="text-rose-400 font-semibold shrink-0 ml-1">
              {(redTeam.attacks_generated ?? 0).toLocaleString()} attacks
            </span>
          </div>
        </div>

        {/* LAN Connector Link - 1 col */}
        <div className="md:col-span-1 flex flex-col items-center justify-center py-1">
          <div className="w-full flex items-center justify-center relative">
            <div className="hidden md:block w-full h-0.5 bg-gradient-to-r from-rose-500/50 via-cyan-500/50 to-blue-500/50 relative">
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#22d3ee] animate-ping" />
            </div>
            <div className="md:hidden flex items-center gap-1 text-slate-500 my-1">
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-[10px] font-mono">LAN ({network.subnet || "N/A"})</span>
            </div>
          </div>
          <span className="hidden md:block text-[9px] font-mono text-cyan-400 font-bold mt-1 tracking-tighter">
            {rttDisplay === "N/A" ? "LAN RTT N/A" : `LAN RTT ${rttDisplay}ms`}
          </span>
        </div>

        {/* Node 2: Blue Team WAF (Máy 1) - 4 cols */}
        <div className="md:col-span-4 bg-slate-950/70 border border-blue-900/40 hover:border-blue-700/60 transition-all rounded-lg p-3.5 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-20 h-20 bg-blue-500/5 rounded-full blur-xl group-hover:bg-blue-500/10 transition-all" />
          <div className="flex items-center justify-between mb-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/30 flex items-center gap-1">
              <Shield className="w-3 h-3 text-blue-400" />
              MÁY 1 (BLUE TEAM WAF)
            </span>
            <span className="text-[11px] font-mono text-cyan-300 font-bold">
              {blueTeam.ip}:{blueTeam.waf_port}
            </span>
          </div>
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-xs font-bold text-slate-100 font-mono tracking-tight truncate">{blueTeam.name}</h3>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-slate-800 text-cyan-300 border border-slate-700 shrink-0">
              {blueTeam.mode || "UNKNOWN"}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 font-sans mt-0.5">{blueTeam.pipeline}</p>

          <div className="mt-3 pt-2.5 border-t border-slate-800/80 grid grid-cols-2 gap-2 text-[11px] font-mono">
            <div>
              <span className="text-slate-400">Inspected: </span>
              <span className="text-white font-bold">{(blueTeam.inspected_count ?? 0).toLocaleString()}</span>
            </div>
            <div className="text-right">
              <span className="text-slate-400">Blocked: </span>
              <span className="text-rose-400 font-bold">{(blueTeam.blocked_count ?? 0).toLocaleString()}</span>
            </div>
          </div>
        </div>

        {/* Internal Forward Connector - 1 col */}
        <div className="md:col-span-1 flex flex-col items-center justify-center py-1">
          <div className="w-full flex items-center justify-center">
            <div className="hidden md:block w-full h-0.5 bg-gradient-to-r from-blue-500/50 to-emerald-500/50 relative">
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399]" />
            </div>
            <ArrowRight className="md:hidden w-4 h-4 text-emerald-400 my-1" />
          </div>
          <span className="hidden md:block text-[9px] font-mono text-emerald-400 font-semibold mt-1">
            {isUpstreamHealthy ? "200 OK" : "DEGRADED"}
          </span>
        </div>

        {/* Node 3: Target API & Upstream - 2 cols */}
        <div className="md:col-span-2 bg-slate-950/70 border border-emerald-900/40 hover:border-emerald-700/60 transition-all rounded-lg p-3.5 relative overflow-hidden group">
          <div className="flex items-center justify-between mb-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
              <Server className="w-3 h-3 text-emerald-400" />
              UPSTREAM
            </span>
            {isUpstreamHealthy ? (
              <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399]" />
            ) : (
              <span className="w-2 h-2 rounded-full bg-rose-400 shadow-[0_0_6px_#f43f5e]" />
            )}
          </div>
          <h3 className="text-xs font-bold text-slate-100 font-mono truncate">{targetApp.name}</h3>
          <p className="text-[10px] font-mono text-emerald-400 mt-0.5">Port {targetApp.port} (Target API)</p>

          <div className="mt-3 pt-2.5 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 flex items-center justify-between">
            <span>OWASP API 1-10</span>
            <span className={isUpstreamHealthy ? "text-emerald-400 font-bold" : "text-rose-400 font-bold"}>
              {targetApp.status ? targetApp.status.toUpperCase() : "UNKNOWN"}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
