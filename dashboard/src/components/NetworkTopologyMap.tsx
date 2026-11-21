"use client";

import React from "react";
import { CyberRangeTopology } from "@/types/dashboard";
import {
  Server,
  Shield,
  Radio,
  Zap,
  Globe,
  Database,
  ArrowRight,
  Terminal,
  Activity,
  CheckCircle2,
} from "lucide-react";

interface NetworkTopologyMapProps {
  topology?: CyberRangeTopology | null;
}

export const NetworkTopologyMap: React.FC<NetworkTopologyMapProps> = ({ topology }) => {
  const redTeam = topology?.red_team || {
    name: "Red Team Host (Máy 2)",
    ip: "192.168.1.50",
    role: "Autonomous Offensive AI Agent",
    status: "active",
    agent_model: "PyTorch DQN + OpenAPI Recon Parser",
    attacks_generated: 1240,
  };

  const network = topology?.network || {
    type: "Physical LAN Boundary (802.3 / 802.11)",
    subnet: "192.168.1.0/24",
    rtt_latency_ms: 1.84,
    jitter_ms: 0.32,
    packet_loss_pct: 0.0,
    status: "optimal",
  };

  const blueTeam = topology?.blue_team || {
    name: "Blue Team Host (Máy 1)",
    ip: "192.168.1.10",
    waf_port: 8000,
    mode: "ACTIVE_DEFENSE",
    pipeline: "Dual-Stage Fast Path + Deep ML Inference",
    inspected_count: 1240,
    blocked_count: 982,
  };

  const targetApp = topology?.target_api || {
    name: "Bookie Bookstore (Target API)",
    port: 5000,
    url: "http://192.168.1.10:5000",
    status: "healthy",
    flaws_monitored: ["SQLi", "XSS", "Path Traversal", "Command Injection", "BOLA"],
  };

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
            <span className="font-bold text-emerald-300">{network.rtt_latency_ms.toFixed(2)} ms</span>
          </div>
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-800/60 border border-slate-700/50 text-slate-300">
            <span>Loss:</span>
            <span className="font-bold text-emerald-400">{network.packet_loss_pct}%</span>
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
            <span className="text-[11px] font-mono text-slate-400">{redTeam.ip}</span>
          </div>
          <h3 className="text-xs font-bold text-slate-100 font-mono tracking-tight">{redTeam.name}</h3>
          <p className="text-[11px] text-slate-400 font-sans mt-0.5 line-clamp-1">{redTeam.role}</p>

          <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-400">Agent: PyTorch DQN</span>
            <span className="text-rose-400 font-semibold">{redTeam.attacks_generated.toLocaleString()} attacks</span>
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
              <span className="text-[10px] font-mono">Physical LAN (192.168.1.0/24)</span>
            </div>
          </div>
          <span className="hidden md:block text-[9px] font-mono text-cyan-400 font-bold mt-1 tracking-tighter">
            LAN RTT 1.8ms
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
            <span className="text-[11px] font-mono text-cyan-300 font-bold">{blueTeam.ip}:{blueTeam.waf_port}</span>
          </div>
          <h3 className="text-xs font-bold text-slate-100 font-mono tracking-tight">{blueTeam.name}</h3>
          <p className="text-[11px] text-slate-400 font-sans mt-0.5">{blueTeam.pipeline}</p>

          <div className="mt-3 pt-2.5 border-t border-slate-800/80 grid grid-cols-2 gap-2 text-[11px] font-mono">
            <div>
              <span className="text-slate-400">Inspected: </span>
              <span className="text-white font-bold">{blueTeam.inspected_count.toLocaleString()}</span>
            </div>
            <div className="text-right">
              <span className="text-slate-400">Blocked: </span>
              <span className="text-rose-400 font-bold">{blueTeam.blocked_count.toLocaleString()}</span>
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
            200 OK
          </span>
        </div>

        {/* Node 3: Target API & SOC - 2 cols */}
        <div className="md:col-span-2 bg-slate-950/70 border border-emerald-900/40 hover:border-emerald-700/60 transition-all rounded-lg p-3.5 relative overflow-hidden group">
          <div className="flex items-center justify-between mb-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
              <Server className="w-3 h-3 text-emerald-400" />
              UPSTREAM
            </span>
            <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399]" />
          </div>
          <h3 className="text-xs font-bold text-slate-100 font-mono truncate">{targetApp.name}</h3>
          <p className="text-[10px] font-mono text-emerald-400 mt-0.5">Port {targetApp.port} (Bookstore)</p>

          <div className="mt-3 pt-2.5 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 flex items-center justify-between">
            <span>OWASP API 1-10</span>
            <span className="text-emerald-400 font-bold">HEALTHY</span>
          </div>
        </div>
      </div>
    </div>
  );
};
