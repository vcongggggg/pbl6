"use client";

import React from "react";
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts";
import { ProtocolDistributionItem } from "@/types/dashboard";
import { Layers, Share2, FileCode2, Cpu, Globe, Network } from "lucide-react";

interface ProtocolDistributionChartProps {
  data: ProtocolDistributionItem[];
}

export const ProtocolDistributionChart: React.FC<ProtocolDistributionChartProps> = ({ data }) => {
  const totalTraffic = data.reduce((acc, curr) => acc + curr.count, 0);

  const getProtocolIcon = (key: string) => {
    switch (key.toUpperCase()) {
      case "REST":
        return <Layers className="w-3.5 h-3.5 text-blue-400" />;
      case "GRAPHQL":
        return <Share2 className="w-3.5 h-3.5 text-pink-400" />;
      case "SOAP_XML":
        return <FileCode2 className="w-3.5 h-3.5 text-amber-400" />;
      case "JSON_RPC":
        return <Cpu className="w-3.5 h-3.5 text-emerald-400" />;
      default:
        return <Globe className="w-3.5 h-3.5 text-purple-400" />;
    }
  };

  return (
    <div className="bg-slate-900/70 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-lg flex flex-col h-[340px]">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-bold tracking-wider uppercase text-slate-200 font-mono">
            Web API Protocols
          </h2>
        </div>
        <span className="text-xs text-slate-400 font-mono">
          Total: <span className="text-cyan-300 font-bold">{totalTraffic.toLocaleString()}</span> reqs
        </span>
      </div>

      <div className="flex-1 w-full flex items-center justify-center min-h-[190px]">
        {totalTraffic > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={80}
                paddingAngle={4}
                dataKey="count"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-proto-${index}`} fill={entry.color} stroke="#090d16" strokeWidth={2} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "#090d16",
                  borderColor: "#334155",
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: "#f8fafc",
                }}
                formatter={(val: any, name: any, item: any) => [
                  `${val} requests (${item.payload.percentage}%)`,
                  item.payload.name,
                ]}
              />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <div className="text-center p-4">
            <div className="w-24 h-24 rounded-full border-4 border-dashed border-slate-800 flex items-center justify-center mx-auto mb-2 text-slate-600 font-mono text-xs">
              0 Traffic
            </div>
            <p className="text-xs text-slate-400 font-mono">No multi-protocol requests captured yet.</p>
          </div>
        )}
      </div>

      {/* Legend Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-2.5 gap-y-1.5 mt-2 pt-2.5 border-t border-slate-800/60 text-[11px] font-mono">
        {data.map((item) => (
          <div key={item.key} className="flex items-center justify-between min-w-0 pr-1" title={item.description || item.name}>
            <span className="flex items-center gap-1.5 text-slate-300 min-w-0">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
              <span className="truncate font-medium text-[11px]">{item.name}</span>
            </span>
            <span className="text-slate-400 font-semibold shrink-0 ml-1">
              {item.percentage}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
