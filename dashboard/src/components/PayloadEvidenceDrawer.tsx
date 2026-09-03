"use client";

import React, { useState } from "react";
import { X, ShieldAlert, Code2, Binary, CheckCircle } from "lucide-react";
import { SecurityEventItem } from "@/types/dashboard";

interface PayloadEvidenceDrawerProps {
  event: SecurityEventItem | null;
  onClose: () => void;
}

export const PayloadEvidenceDrawer: React.FC<PayloadEvidenceDrawerProps> = ({
  event,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<"rule" | "vector">("rule");

  if (!event) return null;

  const details = event.details || {};
  const ruleMatches = details.rule_matches || [];
  const primaryMatch = ruleMatches.length > 0 ? ruleMatches[0] : null;

  const canonicalInput = primaryMatch?.canonical_input || event.evidence || "N/A";
  const rawInput = primaryMatch?.raw_input || event.evidence || "N/A";
  const pattern = primaryMatch?.pattern || primaryMatch?.rule_id || "Regex Match";

  return (
    <div className="fixed inset-y-0 right-0 w-full sm:w-[480px] bg-slate-950/95 backdrop-blur-xl border-l border-slate-800 shadow-2xl z-50 flex flex-col transition-all duration-300">
      {/* Drawer Header */}
      <div className="p-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-rose-400" />
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-1.5">
              Payload Evidence Drawer
            </h3>
            <p className="text-[11px] text-slate-400 font-mono">
              Event ID: <span className="text-cyan-400">#{event.event_id.slice(0, 14)}...</span>
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white transition cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Tabs Switcher */}
      <div className="flex border-b border-slate-800 bg-slate-900/50 p-1 gap-1 text-xs font-mono">
        <button
          onClick={() => setActiveTab("rule")}
          className={`flex-1 flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg transition ${
            activeTab === "rule"
              ? "bg-slate-800 text-white font-bold border border-slate-700 shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Code2 className="w-3.5 h-3.5 text-cyan-400" />
          <span>Rule Evidence</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/40">
            Phase 2: Active
          </span>
        </button>

        <button
          onClick={() => setActiveTab("vector")}
          className={`flex-1 flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg transition ${
            activeTab === "vector"
              ? "bg-slate-800 text-white font-bold border border-slate-700 shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Binary className="w-3.5 h-3.5 text-purple-400" />
          <span>17-Feature Vector</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
            Phase 3: Reserved
          </span>
        </button>
      </div>

      {/* Drawer Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs font-mono">
        {activeTab === "rule" ? (
          <div className="space-y-3.5">
            {/* Metadata Summary */}
            <div className="bg-slate-900/80 border border-slate-800/80 rounded-lg p-3 space-y-1.5">
              <div className="flex justify-between">
                <span className="text-slate-500">Client IP:</span>
                <span className="text-slate-200">{event.client_ip}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Request ID:</span>
                <span className="text-cyan-400">{event.request_id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Detection Location:</span>
                <span className="text-amber-400 font-bold">{event.location}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Rule Score:</span>
                <span className="text-rose-400 font-bold">{event.rule_score.toFixed(1)} / 100</span>
              </div>
            </div>

            {/* Canonical vs Raw Input */}
            <div className="space-y-1">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1">
                <CheckCircle className="w-3 h-3 text-emerald-400" />
                Normalized Canonical Input (De-obfuscated)
              </span>
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-emerald-300 break-all select-all">
                {canonicalInput}
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                Raw Input Received
              </span>
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-slate-300 break-all select-all">
                {rawInput}
              </div>
            </div>

            {/* Rule Trigger Details */}
            <div className="bg-rose-950/20 border border-rose-900/40 rounded-lg p-3 space-y-2">
              <div className="flex items-center justify-between text-rose-300 font-bold">
                <span>Triggered: {event.rule_id}</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-rose-900/60 text-rose-200">
                  {event.severity}
                </span>
              </div>
              <p className="text-slate-400 text-[11px]">{event.rule_name}</p>
              <div className="pt-1">
                <span className="text-slate-500 text-[10px]">Regex Pattern:</span>
                <p className="text-purple-300 text-[11px] bg-slate-950/80 p-1.5 rounded border border-purple-950 break-all mt-0.5">
                  {pattern}
                </p>
              </div>
            </div>

            {/* Extracted Evidence */}
            {event.evidence && (
              <div className="space-y-1">
                <span className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                  Extracted Evidence Snippet
                </span>
                <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800 text-rose-300 break-all">
                  &quot;{event.evidence}&quot;
                </div>
              </div>
            )}
          </div>
        ) : (
          /* 17-Feature Vector Tab */
          <div className="space-y-4">
            <div className="bg-purple-950/30 border border-purple-800/40 rounded-lg p-3">
              <div className="flex items-center gap-2 text-purple-300 font-bold mb-1">
                <Binary className="w-4 h-4 text-purple-400" />
                <span>Phase 3 Feature Pipeline</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Khi <span className="text-white font-semibold">Phase 3 (Feature Engineering)</span> hoàn tất, vector 17 đặc trưng sẽ tự động hiển thị số liệu phân tích của request này tại đây.
              </p>
            </div>

            {/* Mock layout of the 17 features */}
            <div className="space-y-2">
              <h4 className="text-[11px] font-bold uppercase text-slate-400 tracking-wider">
                1. Morphological Features (5)
              </h4>
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">url_length:</span> <span className="text-cyan-400">42</span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">body_length:</span> <span className="text-cyan-400">0</span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">shannon_entropy:</span> <span className="text-purple-400">3.84</span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">special_char_ratio:</span> <span className="text-rose-400">0.24</span>
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="text-[11px] font-bold uppercase text-slate-400 tracking-wider">
                2. Attack Keyword Frequencies (6)
              </h4>
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">sqli_keywords:</span> <span className="text-amber-400">2</span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">xss_tags:</span> <span className="text-slate-400">0</span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">path_traversal_depth:</span> <span className="text-slate-400">0</span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">cmd_tokens:</span> <span className="text-slate-400">0</span>
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="text-[11px] font-bold uppercase text-slate-400 tracking-wider">
                3. HTTP Context & Behavior (6)
              </h4>
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">is_post:</span> <span className="text-slate-400">0</span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">is_get:</span> <span className="text-emerald-400">1</span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">param_count:</span> <span className="text-cyan-400">1</span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500">query_ratio:</span> <span className="text-cyan-400">0.52</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
