"use client";

import React from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";
import { TimelinePoint } from "@/types/dashboard";
import { Activity } from "lucide-react";

interface ThreatTimelineChartProps {
  data: TimelinePoint[];
  compact?: boolean;
}

export const ThreatTimelineChart: React.FC<ThreatTimelineChartProps> = ({ data, compact = false }) => {
  const hasData = data && data.length > 0;

  return (
    <div
      className={
        compact
          ? "w-full h-full flex flex-col min-h-0 overflow-hidden"
          : "bg-slate-900/70 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-lg flex flex-col h-[340px]"
      }
    >
      <div className={`flex items-center justify-between ${compact ? "mb-1.5" : "mb-4"}`}>
        <div className="flex items-center gap-1.5 min-w-0">
          <Activity className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <h2
            className={`${
              compact ? "text-xs" : "text-sm"
            } font-bold tracking-wider uppercase text-slate-200 font-mono truncate`}
          >
            {compact ? "60m Traffic & Threat" : "Real-time Traffic & Threat Timeline"}
          </h2>
        </div>
        <div className="flex items-center gap-2.5 text-[10px] font-mono shrink-0">
          <span className="flex items-center gap-1 text-cyan-400">
            <span className="w-2 h-2 rounded-full bg-cyan-400"></span> Benign
          </span>
          <span className="flex items-center gap-1 text-rose-400">
            <span className="w-2 h-2 rounded-full bg-rose-500"></span> Attacks
          </span>
        </div>
      </div>

      <div className={compact ? "flex-1 w-full min-h-0" : "flex-1 w-full min-h-[220px]"}>
        {hasData ? (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorBenign" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorAttacks" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.5} />
                  <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" stroke="#64748b" fontSize={11} fontStyle="italic" />
              <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#090d16",
                  borderColor: "#334155",
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: "#f8fafc",
                }}
              />
              <Area
                type="monotone"
                dataKey="benign_traffic"
                name="Benign Traffic"
                stroke="#06b6d4"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorBenign)"
              />
              <Area
                type="monotone"
                dataKey="attacks"
                name="Attacks Detected"
                stroke="#f43f5e"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorAttacks)"
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="w-full h-full flex flex-col items-center justify-center text-center p-6 border border-dashed border-slate-800 rounded-lg">
            <Activity className="w-8 h-8 text-slate-600 mb-2 animate-pulse" />
            <p className="text-xs text-slate-400 font-mono">No traffic records in the current time window.</p>
            <p className="text-[11px] text-slate-500 mt-1">
              Click buttons on <span className="text-purple-400 font-semibold">Quick Simulator</span> to generate live traffic.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
