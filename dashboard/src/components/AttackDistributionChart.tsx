"use client";

import React from "react";
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts";
import { AttackDistributionItem } from "@/types/dashboard";
import { PieChart as PieIcon } from "lucide-react";

interface AttackDistributionChartProps {
  data: AttackDistributionItem[];
}

export const AttackDistributionChart: React.FC<AttackDistributionChartProps> = ({ data }) => {
  const totalAttacks = data.reduce((acc, curr) => acc + curr.count, 0);

  return (
    <div className="bg-slate-900/70 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-lg flex flex-col h-[340px]">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <PieIcon className="w-4 h-4 text-purple-400" />
          <h2 className="text-sm font-bold tracking-wider uppercase text-slate-200 font-mono">
            Attack Distribution
          </h2>
        </div>
        <span className="text-xs text-slate-400 font-mono">
          Total: <span className="text-white font-bold">{totalAttacks}</span>
        </span>
      </div>

      <div className="flex-1 w-full flex items-center justify-center min-h-[190px]">
        {totalAttacks > 0 ? (
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
                  <Cell key={`cell-${index}`} fill={entry.color} stroke="#090d16" strokeWidth={2} />
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
                  `${val} (${item.payload.percentage}%)`,
                  item.payload.name,
                ]}
              />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <div className="text-center p-4">
            <div className="w-24 h-24 rounded-full border-4 border-dashed border-slate-800 flex items-center justify-center mx-auto mb-2 text-slate-600 font-mono text-xs">
              0 Attacks
            </div>
            <p className="text-xs text-slate-400 font-mono">No attack incidents detected yet.</p>
          </div>
        )}
      </div>

      {/* Legend Badges */}
      <div className="grid grid-cols-2 gap-2 mt-2 pt-2 border-t border-slate-800/60 text-xs font-mono">
        {data.map((item) => (
          <div key={item.key} className="flex items-center justify-between pr-2">
            <span className="flex items-center gap-1.5 text-slate-300 truncate">
              <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ backgroundColor: item.color }} />
              <span className="truncate">{item.name}</span>
            </span>
            <span className="text-slate-400 font-semibold shrink-0">
              {item.percentage}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
