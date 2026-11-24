"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Header } from "@/components/Header";
import {
  triggerPentestRun,
  streamPentestEvaluation,
  fetchArenaHistory,
  fetchDashboardStats,
  toggleWafMode,
  PentestAttackGraphNode,
  PentestQValueEntry,
  PentestReport,
  PentestRoundResult,
} from "@/services/api";
import { ArenaHistoryResponse, DashboardStats } from "@/types/dashboard";
import {
  Swords,
  Shield,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Target,
  ChevronRight,
  Cpu,
  History,
  X,
  Globe,
} from "lucide-react";

const INITIAL_OPENAPI_SURFACES: PentestAttackGraphNode[] = [
  {
    endpoint: "/api/v1/vulnerable/books/search/",
    method: "GET",
    category: "Injection",
    flaw: "SQL_INJECTION (q)",
    priority: 1,
    surfaces: ["q"],
  },
  {
    endpoint: "/api/v1/vulnerable/reviews/",
    method: "POST",
    category: "Injection",
    flaw: "XSS (comment)",
    priority: 2,
    surfaces: ["comment"],
  },
  {
    endpoint: "/api/v1/vulnerable/files/download/",
    method: "GET",
    category: "Injection",
    flaw: "PATH_TRAVERSAL (file)",
    priority: 3,
    surfaces: ["file"],
  },
  {
    endpoint: "/api/v1/vulnerable/admin/ping/",
    method: "POST",
    category: "Injection",
    flaw: "COMMAND_INJECTION (host)",
    priority: 4,
    surfaces: ["host"],
  },
  {
    endpoint: "/api/v1/vulnerable/books/fetch-cover/",
    method: "GET",
    category: "API Logic",
    flaw: "SSRF (url)",
    priority: 5,
    surfaces: ["url"],
  },
  {
    endpoint: "/api/v1/vulnerable/orders/{order_id}/",
    method: "GET",
    category: "API Logic",
    flaw: "BOLA_IDOR (order_id)",
    priority: 6,
    surfaces: ["order_id"],
  },
  {
    endpoint: "/api/v1/vulnerable/users/profile/update/",
    method: "POST",
    category: "API Logic",
    flaw: "MASS_ASSIGNMENT (role)",
    priority: 7,
    surfaces: ["role"],
  },
  {
    endpoint: "/api/v1/vulnerable/users/list/",
    method: "GET",
    category: "API Logic",
    flaw: "EXCESSIVE_DATA_EXPOSURE",
    priority: 8,
    surfaces: ["users"],
  },
];

function normalizeQEntries(raw: unknown): PentestQValueEntry[] {
  if (Array.isArray(raw)) {
    return raw.map((item: any, idx: number) => ({
      action: String(item?.action ?? `action_${idx}`),
      family: String(item?.family ?? "GENERAL"),
      transformation: item?.transformation ? String(item.transformation) : undefined,
      q_value: typeof item?.q_value === "number" && Number.isFinite(item.q_value) ? item.q_value : 0,
      selected: Boolean(item?.selected ?? idx === 0),
    }));
  }
  if (raw && typeof raw === "object") {
    return Object.entries(raw as Record<string, unknown>).map(([k, v], idx) => ({
      action: k,
      family: "GENERAL",
      q_value: typeof v === "number" && Number.isFinite(v) ? v : 0,
      selected: idx === 0,
    }));
  }
  return [];
}

export default function ArenaPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [isTogglingWaf, setIsTogglingWaf] = useState<boolean>(false);

  // Pentest Configuration
  const [defenseTier, setDefenseTier] = useState<"no_waf" | "rules_only" | "hybrid_v3">("hybrid_v3");
  const [scope, setScope] = useState<string>("full_pentest");
  const [targetUrl, setTargetUrl] = useState<string>("http://127.0.0.1:5000");
  const [syncToSoc, setSyncToSoc] = useState<boolean>(true);
  const [maxRounds] = useState<number>(8);

  // Execution & Live SSE Trace States
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [currentPhase, setCurrentPhase] = useState<number>(0);
  const [specSource, setSpecSource] = useState<string>("OpenAPI Ready");
  const [surfaceNodes, setSurfaceNodes] = useState<PentestAttackGraphNode[]>(INITIAL_OPENAPI_SURFACES);
  const [report, setReport] = useState<PentestReport | null>(null);
  const [traceRounds, setTraceRounds] = useState<PentestRoundResult[]>([]);
  const [selectedRound, setSelectedRound] = useState<PentestRoundResult | null>(null);
  const [filterEndpoint, setFilterEndpoint] = useState<string>("ALL");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // History Drawer
  const [isHistoryOpen, setIsHistoryOpen] = useState<boolean>(false);
  const [historyData, setHistoryData] = useState<ArenaHistoryResponse | null>(null);

  const loadStats = useCallback(async () => {
    try {
      const data = await fetchDashboardStats();
      if (data) {
        setStats(data);
      }
    } catch {
      // ignore offline
    }
  }, []);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  const loadHistory = async () => {
    setIsHistoryOpen(true);
    try {
      const hist = await fetchArenaHistory();
      setHistoryData(hist);
    } catch {
      // ignore
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text || "");
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleToggleWafMode = async () => {
    setIsTogglingWaf(true);
    try {
      await toggleWafMode();
      await loadStats();
    } catch {
      // ignore
    } finally {
      setIsTogglingWaf(false);
    }
  };

  const handleRunPentest = async () => {
    if (isRunning) return;
    setIsRunning(true);
    setErrorMsg(null);
    setReport(null);
    setTraceRounds([]);
    setSelectedRound(null);
    setFilterEndpoint("ALL");
    setCurrentPhase(1);

    const runParams = {
      target_url: targetUrl.trim() || "http://127.0.0.1:5000",
      defense_tier: defenseTier,
      scope,
      max_rounds: maxRounds,
      sync_to_soc: syncToSoc,
    };

    try {
      const streamedRounds: PentestRoundResult[] = [];
      let receivedVerdict = false;

      await streamPentestEvaluation(runParams, {
        onRecon: (evt) => {
          setCurrentPhase(1);
          if (evt?.spec_source) setSpecSource(String(evt.spec_source));
        },
        onAttackGraph: (evt) => {
          setCurrentPhase(2);
          if (Array.isArray(evt?.nodes) && evt.nodes.length > 0) {
            setSurfaceNodes(evt.nodes);
          }
        },
        onRound: (rd) => {
          streamedRounds.push(rd);
          setCurrentPhase(streamedRounds.length === 1 ? 3 : 4);
          setTraceRounds([...streamedRounds]);
          setSelectedRound(rd);
        },
        onVerdict: (verdict) => {
          receivedVerdict = true;
          if (Array.isArray(verdict.attack_graph) && verdict.attack_graph.length > 0) {
            setSurfaceNodes(verdict.attack_graph);
          }
          setReport({
            ...verdict,
            rounds: verdict.rounds && verdict.rounds.length > 0 ? verdict.rounds : streamedRounds,
          });
          setCurrentPhase(5);
        },
      });

      if (!receivedVerdict) {
        const fallback = await triggerPentestRun(runParams);
        if (Array.isArray(fallback.attack_graph) && fallback.attack_graph.length > 0) {
          setSurfaceNodes(fallback.attack_graph);
        }
        setReport(fallback);
        setTraceRounds(fallback.rounds || []);
        if (fallback.rounds && fallback.rounds.length > 0) {
          setSelectedRound(fallback.rounds[fallback.rounds.length - 1]);
        }
        setCurrentPhase(5);
      }

      if (syncToSoc) {
        await loadStats();
      }
    } catch (err: any) {
      try {
        const fallback = await triggerPentestRun(runParams);
        if (Array.isArray(fallback.attack_graph) && fallback.attack_graph.length > 0) {
          setSurfaceNodes(fallback.attack_graph);
        }
        setReport(fallback);
        setTraceRounds(fallback.rounds || []);
        if (fallback.rounds && fallback.rounds.length > 0) {
          setSelectedRound(fallback.rounds[fallback.rounds.length - 1]);
        }
        setCurrentPhase(5);
      } catch (innerErr: any) {
        setErrorMsg(innerErr?.message || err?.message || "Không thể kết nối máy chủ Arena.");
        setCurrentPhase(0);
      }
    } finally {
      setIsRunning(false);
    }
  };

  const matchEndpoint = (roundEp: string, nodeEp: string) => {
    if (roundEp === nodeEp) return true;
    if (nodeEp.includes("{")) {
      const prefix = nodeEp.split("{")[0];
      return Boolean(prefix && roundEp.startsWith(prefix));
    }
    return false;
  };

  const displayedRounds =
    filterEndpoint === "ALL"
      ? traceRounds
      : traceRounds.filter((r) => matchEndpoint(r.target_endpoint || r.endpoint, filterEndpoint));

  const stepperPhases = [
    { num: 1, name: "Recon (OpenAPI)" },
    { num: 2, name: "Attack Graph" },
    { num: 3, name: "Baseline Probe" },
    { num: 4, name: "DQN Mutate & Pivot" },
    { num: 5, name: "Verdict & SOC" },
  ];

  const qEntries = selectedRound ? normalizeQEntries(selectedRound.dqn_q_values) : [];
  const qValuesNumeric = qEntries.map((e) => e.q_value);
  const qMin = qValuesNumeric.length > 0 ? Math.min(...qValuesNumeric) : 0;
  const qMax = qValuesNumeric.length > 0 ? Math.max(...qValuesNumeric) : 1;
  const qSpan = Math.max(qMax - qMin, 0.25);

  return (
    <div className="h-screen w-screen flex flex-col overflow-hidden bg-[#07090e] text-slate-100 font-sans selection:bg-rose-500 selection:text-white">
      <Header
        stats={stats}
        onRefresh={loadStats}
        onToggleWafMode={handleToggleWafMode}
        isTogglingWaf={isTogglingWaf}
      />

      {/* Command Strip & 5-Phase Stepper */}
      <div className="h-16 shrink-0 bg-slate-900/80 border-b border-slate-800/80 px-4 flex items-center justify-between gap-3 text-xs font-mono whitespace-nowrap overflow-x-auto">
        <div className="flex items-center gap-2">
          {/* Editable Target API URL */}
          <div className="flex items-center gap-1.5 bg-slate-950/90 px-2.5 py-1 rounded-lg border border-slate-800">
            <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="text-[11px] text-slate-400">Target:</span>
            <input
              id="input-target-url"
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              disabled={isRunning}
              placeholder="http://127.0.0.1:5000"
              className="w-40 bg-transparent text-slate-200 focus:outline-none text-xs font-mono"
            />
          </div>

          {/* 3-Tier Progressive Defense Switch */}
          <div className="flex items-center bg-slate-950/90 p-1 rounded-lg border border-slate-800">
            <span className="text-[11px] text-slate-400 px-1.5 font-semibold">Cấp độ:</span>
            <button
              onClick={() => setDefenseTier("no_waf")}
              disabled={isRunning}
              className={`px-2 py-1 rounded text-xs transition cursor-pointer font-semibold ${
                defenseTier === "no_waf"
                  ? "bg-rose-950/90 text-rose-300 border border-rose-600/60 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              1. No WAF
            </button>
            <button
              onClick={() => setDefenseTier("rules_only")}
              disabled={isRunning}
              className={`px-2 py-1 rounded text-xs transition cursor-pointer font-semibold ${
                defenseTier === "rules_only"
                  ? "bg-amber-950/90 text-amber-300 border border-amber-600/60 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              2. Rules Only
            </button>
            <button
              onClick={() => setDefenseTier("hybrid_v3")}
              disabled={isRunning}
              className={`px-2 py-1 rounded text-xs transition cursor-pointer font-semibold ${
                defenseTier === "hybrid_v3"
                  ? "bg-purple-950/90 text-purple-200 border border-purple-500/60 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              3. Hybrid v3.0
            </button>
          </div>

          {/* Scope Selector */}
          <div className="flex items-center bg-slate-950/90 px-2.5 py-1 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[11px] mr-1">Phạm vi:</span>
            <select
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              disabled={isRunning}
              className="bg-transparent text-slate-200 focus:outline-none text-xs cursor-pointer font-mono"
            >
              <option value="full_pentest" className="bg-slate-900">Full Pentest (8/8)</option>
              <option value="injection" className="bg-slate-900">OWASP Injections</option>
              <option value="api_logic" className="bg-slate-900">OWASP API Logic</option>
            </select>
          </div>

          {/* Sync SOC */}
          <label className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-slate-950/90 border border-slate-800 cursor-pointer">
            <input
              type="checkbox"
              checked={syncToSoc}
              onChange={(e) => setSyncToSoc(e.target.checked)}
              disabled={isRunning}
              className="accent-purple-500 rounded cursor-pointer"
            />
            <span className="text-[11px] text-slate-300">Sync -&gt; SOC</span>
          </label>

          {/* Run Button */}
          <button
            id="btn-run-pentest"
            onClick={handleRunPentest}
            disabled={isRunning}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold transition active:scale-95 disabled:opacity-50 cursor-pointer shadow-[0_0_15px_rgba(244,63,94,0.4)]"
          >
            {isRunning ? (
              <>
                <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                <span>Đang Chạy...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-white" />
                <span>Chạy Pentest AI</span>
              </>
            )}
          </button>

          {/* History Button */}
          <button
            onClick={loadHistory}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-950/90 hover:bg-slate-800 border border-slate-800 text-slate-300 transition cursor-pointer"
            title="Xem lịch sử đối kháng"
          >
            <History className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-[11px]">Lịch sử</span>
          </button>
        </div>

        {/* 5-Phase Stepper */}
        <div className="flex items-center gap-1 bg-slate-950/90 px-2.5 py-1.5 rounded-lg border border-slate-800 shrink-0">
          {stepperPhases.map((phase, idx) => {
            const isActive = currentPhase === phase.num;
            const isDone = currentPhase > phase.num;
            return (
              <React.Fragment key={phase.num}>
                {idx > 0 && <ChevronRight className="w-3 h-3 text-slate-600" />}
                <div
                  className={`flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold transition ${
                    isActive
                      ? "bg-rose-950/90 text-rose-300 border border-rose-500/60 animate-pulse"
                      : isDone
                      ? "text-emerald-400 bg-emerald-950/40 border border-emerald-800/40"
                      : "text-slate-500"
                  }`}
                >
                  <span>{phase.num}.</span>
                  <span>{phase.name}</span>
                </div>
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Main 3-Column Zero-Scroll Body */}
      <main className="flex-1 min-h-0 p-3 grid grid-cols-12 gap-3 overflow-hidden">
        {/* COLUMN 1: DYNAMIC OPENAPI ATTACK SURFACE */}
        <div className="col-span-12 lg:col-span-3 h-full min-h-0 bg-slate-900/70 border border-slate-800/80 rounded-xl p-3 shadow flex flex-col overflow-hidden">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 text-xs font-mono">
            <div className="flex items-center gap-1.5">
              <Target className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-white uppercase tracking-wider">OpenAPI Surface</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                {surfaceNodes.length} nodes
              </span>
            </div>
            {filterEndpoint !== "ALL" && (
              <button
                onClick={() => setFilterEndpoint("ALL")}
                className="text-[10px] text-cyan-400 hover:underline cursor-pointer"
              >
                Hiện tất cả
              </button>
            )}
          </div>

          <div className="flex-1 overflow-y-auto mt-2 space-y-1.5 pr-1">
            {surfaceNodes.map((node, nIdx) => {
              const isFiltered = filterEndpoint === node.endpoint;
              const matchesInTrace = traceRounds.filter((r) =>
                matchEndpoint(r.target_endpoint || r.endpoint, node.endpoint)
              );
              const hasBypass = matchesInTrace.some((r) => !r.waf_blocked);
              const hasBlock = matchesInTrace.some((r) => r.waf_blocked);

              return (
                <div
                  key={`${node.method}-${node.endpoint}-${nIdx}`}
                  onClick={() => setFilterEndpoint(isFiltered ? "ALL" : node.endpoint)}
                  className={`p-2 rounded-lg border transition cursor-pointer text-xs font-mono ${
                    isFiltered
                      ? "bg-purple-950/70 border-purple-500/80 shadow-[0_0_10px_rgba(168,85,247,0.25)]"
                      : "bg-slate-950/70 border-slate-800/70 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-slate-800 text-slate-300">
                      {node.method}
                    </span>
                    <span className="text-[10px] text-slate-400 truncate font-semibold">
                      P{node.priority} • {node.category}
                    </span>
                  </div>

                  <div className="font-bold text-slate-200 truncate" title={node.endpoint}>
                    {node.endpoint}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between gap-1">
                    <span className="truncate">{node.flaw}</span>
                    {hasBypass ? (
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-950/70 text-rose-300 border border-rose-800 font-bold shrink-0">
                        Bypass 200
                      </span>
                    ) : hasBlock ? (
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950/70 text-emerald-300 border border-emerald-800 font-bold shrink-0">
                        Đã Chặn
                      </span>
                    ) : (
                      <span className="text-[10px] text-slate-500 shrink-0">Chờ probe</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pt-2 mt-2 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 space-y-0.5">
            <div className="flex items-center justify-between">
              <span>Target:</span>
              <span className="text-slate-200 font-bold truncate max-w-[160px]">{targetUrl}</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Spec Source:</span>
              <span className="text-cyan-400 truncate max-w-[160px]">{specSource}</span>
            </div>
          </div>
        </div>

        {/* COLUMN 2: REAL-TIME SSE LIVE TRACE */}
        <div className="col-span-12 lg:col-span-5 h-full min-h-0 bg-slate-900/70 border border-slate-800/80 rounded-xl p-3 shadow flex flex-col overflow-hidden">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 text-xs font-mono">
            <div className="flex items-center gap-1.5">
              <Swords className="w-4 h-4 text-rose-400" />
              <span className="font-bold text-white uppercase tracking-wider">SSE Pentest Trace</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                {displayedRounds.length} rounds
              </span>
            </div>

            {report && (
              <div className="flex items-center gap-2">
                <span className="text-emerald-400 font-bold text-[11px]">
                  Chặn: {report.blocked_count}
                </span>
                <span className="text-rose-400 font-bold text-[11px]">
                  Lọt: {report.bypass_count}
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    report.winner === "BLUE_TEAM"
                      ? "bg-emerald-950/80 text-emerald-300 border border-emerald-600"
                      : report.winner === "RED_TEAM"
                      ? "bg-rose-950/80 text-rose-300 border border-rose-600"
                      : "bg-amber-950/80 text-amber-300 border border-amber-600"
                  }`}
                >
                  {report.winner}
                </span>
              </div>
            )}
          </div>

          {errorMsg && (
            <div className="mt-2 p-2 rounded bg-rose-950/70 border border-rose-700 text-rose-200 text-xs font-mono">
              {errorMsg}
            </div>
          )}

          <div className="flex-1 overflow-y-auto mt-2 space-y-2 pr-1">
            {displayedRounds.length > 0 ? (
              displayedRounds.map((r, idx) => {
                const rNum = r.round ?? r.round_num ?? idx + 1;
                const selNum = selectedRound ? selectedRound.round ?? selectedRound.round_num : -1;
                const isSelected = selNum === rNum;
                const isBlocked = Boolean(r.waf_blocked);
                const statusCode = r.http_status ?? r.response_status ?? 200;
                const epLabel = r.target_endpoint || r.endpoint;
                const techLabel = r.mutation_technique || r.technique;

                return (
                  <div
                    key={rNum}
                    onClick={() => setSelectedRound(r)}
                    className={`p-2.5 rounded-lg border transition cursor-pointer text-xs font-mono ${
                      isSelected
                        ? "bg-purple-950/60 border-purple-500 shadow-[0_0_12px_rgba(168,85,247,0.3)]"
                        : "bg-slate-950/70 border-slate-800/70 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <span className="w-5 h-5 rounded-full bg-slate-800 text-slate-200 flex items-center justify-center text-[10px] font-bold shrink-0">
                          {rNum}
                        </span>
                        <span className="px-1.5 py-0.2 rounded bg-rose-950/60 text-rose-300 border border-rose-800/50 font-bold text-[10px] shrink-0">
                          {r.attack_type}
                        </span>
                        <span className="text-slate-400 text-[11px] truncate" title={epLabel}>
                          {epLabel}
                        </span>
                      </div>

                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold flex items-center gap-1 shrink-0 ${
                          isBlocked
                            ? "bg-emerald-950/80 text-emerald-300 border border-emerald-700"
                            : "bg-rose-950/80 text-rose-300 border border-rose-700"
                        }`}
                      >
                        {isBlocked ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                        <span>{r.dlp_redacted ? "DLP SCRUB" : `HTTP ${statusCode}`}</span>
                      </span>
                    </div>

                    <div className="text-[11px] text-slate-300 flex items-center justify-between gap-2 mb-1">
                      <span className="text-cyan-400 font-semibold truncate">{techLabel}</span>
                      <span className="text-slate-400 shrink-0">
                        Risk {(r.waf_threat_score ?? r.threat_score ?? 0).toFixed(1)} • {(r.latency_ms ?? 0).toFixed(2)} ms
                      </span>
                    </div>

                    <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-400 truncate">
                      <code>{r.mutated_payload || r.original_payload || "(GET probe)"}</code>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="py-20 text-center text-slate-500 text-xs font-mono">
                <Swords className="w-8 h-8 text-slate-700 mx-auto mb-2" />
                <p>Sẵn sàng kiểm thử xâm nhập tự động 5 pha (OpenAPI -&gt; Dueling-DQN -&gt; WAF).</p>
                <p className="text-[11px] text-slate-600 mt-1">
                  Chọn cấp độ phòng thủ (<span className="text-rose-400">No WAF</span> /{" "}
                  <span className="text-amber-400">Rules Only</span> /{" "}
                  <span className="text-purple-400">Hybrid v3.0</span>) rồi bấm{" "}
                  <span className="text-rose-400 font-bold">[Chạy Pentest AI]</span>.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* COLUMN 3: DUAL-BRAIN INSPECTOR */}
        <div className="col-span-12 lg:col-span-4 h-full min-h-0 flex flex-col gap-3 overflow-hidden">
          {/* Top Half: Trained 64-D Dueling-DQN Brain */}
          <div className="flex-1 min-h-0 bg-slate-900/70 border border-slate-800/80 rounded-xl p-3 shadow flex flex-col overflow-hidden">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 text-xs font-mono">
              <span className="font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-rose-400" />
                Bộ Não Red Team Dueling-DQN
              </span>
              <span className="text-[10px] text-slate-400">64-D State -&gt; 26 Actions</span>
            </div>

            <div className="flex-1 overflow-y-auto mt-2 space-y-2 pr-1 text-xs font-mono">
              {selectedRound ? (
                <>
                  <div>
                    <span className="text-[11px] text-slate-400 mb-1 block font-semibold">
                      Trained Action Q(s, a) Ranking:
                    </span>
                    <div className="space-y-1">
                      {qEntries.map((entry, idx) => {
                        const normPct = Math.min(
                          100,
                          Math.max(12, Math.round(((entry.q_value - qMin) / qSpan) * 88 + 12))
                        );
                        const isChosen = Boolean(entry.selected ?? idx === 0);
                        return (
                          <div key={`${entry.action}-${idx}`} className="space-y-0.5">
                            <div className="flex justify-between text-[10px] gap-2">
                              <span className={`truncate ${isChosen ? "text-rose-300 font-bold" : "text-slate-400"}`}>
                                {isChosen ? `★ ${entry.action}` : entry.action}
                              </span>
                              <span className="text-slate-300 font-bold shrink-0">
                                {entry.q_value.toFixed(3)}
                              </span>
                            </div>
                            <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                              <div
                                className={`h-full rounded-full ${isChosen ? "bg-rose-500" : "bg-slate-600"}`}
                                style={{ width: `${normPct}%` }}
                              />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="p-2 rounded-lg bg-rose-950/40 border border-rose-900/50 text-[11px] text-rose-200">
                    <span className="font-bold text-rose-300 block mb-0.5">Phân tích đối kháng:</span>
                    <p className="leading-relaxed">{selectedRound.reasoning_vi}</p>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1 text-[11px]">
                      <span className="text-slate-400 font-semibold">Payload Gốc -&gt; Đột Biến:</span>
                      <button
                        onClick={() =>
                          copyToClipboard(selectedRound.mutated_payload || selectedRound.original_payload, "mutated")
                        }
                        className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
                      >
                        {copiedKey === "mutated" ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                        <span>Copy</span>
                      </button>
                    </div>
                    {selectedRound.original_payload &&
                      selectedRound.mutated_payload &&
                      selectedRound.original_payload !== selectedRound.mutated_payload && (
                        <div className="p-1.5 mb-1 rounded bg-slate-950/80 border border-slate-800 text-[10px] text-slate-500 break-all">
                          Baseline: {selectedRound.original_payload}
                        </div>
                      )}
                    <pre className="p-2 rounded bg-slate-950 border border-slate-800 text-[10px] text-amber-300 whitespace-pre-wrap break-all max-h-20 overflow-y-auto">
                      {selectedRound.mutated_payload || selectedRound.original_payload || "(Path / Query Probe)"}
                    </pre>
                  </div>
                </>
              ) : (
                <div className="py-12 text-center text-slate-500 text-xs">
                  Chọn một vòng bên Trace để xem Q-values thực từ mạng Dueling-DQN.
                </div>
              )}
            </div>
          </div>

          {/* Bottom Half: Blue Team v3.0 Anatomy */}
          <div className="flex-1 min-h-0 bg-slate-900/70 border border-slate-800/80 rounded-xl p-3 shadow flex flex-col overflow-hidden">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 text-xs font-mono">
              <span className="font-bold text-purple-400 uppercase tracking-wider flex items-center gap-1.5">
                <Shield className="w-4 h-4 text-purple-400" />
                Giải Phẫu Blue Team v3.0
              </span>
              <span className="text-[10px] text-slate-400">Rules + 26-D ML + API Guards</span>
            </div>

            <div className="flex-1 overflow-y-auto mt-2 space-y-2 pr-1 text-xs font-mono">
              {selectedRound ? (
                <>
                  <div>
                    <span className="text-[11px] text-slate-400 font-semibold block mb-0.5">
                      InputNormalizer Canonical Output:
                    </span>
                    <div className="p-1.5 rounded bg-slate-950 border border-slate-800 text-[10px] text-slate-300 break-all max-h-14 overflow-y-auto">
                      {selectedRound.normalized_payload || selectedRound.mutated_payload || "(Empty)"}
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 text-center">
                      <div className="text-[10px] text-slate-400">Rule / API</div>
                      <div className="text-sm font-bold text-rose-400 mt-0.5">
                        {(selectedRound.rule_score ?? 0).toFixed(1)}
                      </div>
                    </div>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 text-center">
                      <div className="text-[10px] text-slate-400">XGBoost 26-D</div>
                      <div className="text-sm font-bold text-cyan-400 mt-0.5">
                        {(selectedRound.ml_score ?? 0).toFixed(1)}
                      </div>
                    </div>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 text-center">
                      <div className="text-[10px] text-slate-400">IForest 26-D</div>
                      <div className="text-sm font-bold text-emerald-400 mt-0.5">
                        {(selectedRound.anomaly_score ?? 0).toFixed(1)}
                      </div>
                    </div>
                  </div>

                  {selectedRound.matched_rules && selectedRound.matched_rules.length > 0 && (
                    <div>
                      <span className="text-[10px] text-slate-400 block mb-1">Chữ ký &amp; Lá chắn kích hoạt:</span>
                      <div className="flex flex-wrap gap-1">
                        {selectedRound.matched_rules.map((rule, rIdx) => (
                          <span
                            key={rIdx}
                            className="px-1.5 py-0.2 rounded bg-rose-950/70 text-rose-300 border border-rose-800 text-[10px] font-bold"
                          >
                            {rule}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="text-[10px] text-slate-400 block">Phán quyết WAF ({selectedRound.waf_decision}):</span>
                      <span
                        className={`font-bold text-xs ${
                          selectedRound.waf_blocked ? "text-emerald-400" : "text-rose-400"
                        }`}
                      >
                        {selectedRound.dlp_redacted
                          ? "CHE GIẤU DỮ LIỆU NHẠY CẢM (DLP)"
                          : selectedRound.waf_blocked
                          ? "CHẶN ĐỨNG 403 FORBIDDEN"
                          : "LỌT LƯỚI 200 OK (BYPASS)"}
                      </span>
                    </div>
                    <div className="text-right">
                      <span className="text-[10px] text-slate-400 block">Hybrid Risk / Latency:</span>
                      <span className="text-slate-200 font-bold">
                        {(selectedRound.waf_threat_score ?? selectedRound.threat_score ?? 0).toFixed(1)} •{" "}
                        {(selectedRound.latency_ms ?? 0).toFixed(2)} ms
                      </span>
                    </div>
                  </div>
                </>
              ) : (
                <div className="py-12 text-center text-slate-500 text-xs">
                  Chọn một vòng bên Trace để giải phẫu các tầng phòng thủ Blue Team v3.0.
                </div>
              )}
            </div>
          </div>
        </div>
      </main>

      {/* Battle History Drawer */}
      {isHistoryOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-md h-full bg-slate-900 border-l border-slate-800 p-4 flex flex-col font-mono text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-purple-400" />
                <span className="font-bold text-white text-sm">Lịch Sử Phiên Pentest &amp; Arena</span>
              </div>
              <button
                onClick={() => setIsHistoryOpen(false)}
                className="text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {historyData && (
              <div className="grid grid-cols-3 gap-2 my-3 text-center">
                <div className="p-2 rounded bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-400">Tổng phiên</div>
                  <div className="text-sm font-bold text-white">{historyData.total_battles}</div>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-emerald-900/50">
                  <div className="text-[10px] text-slate-400">Blue Thắng</div>
                  <div className="text-sm font-bold text-emerald-400">{historyData.blue_wins}</div>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-rose-900/50">
                  <div className="text-[10px] text-slate-400">Red Thắng</div>
                  <div className="text-sm font-bold text-rose-400">{historyData.red_wins}</div>
                </div>
              </div>
            )}

            <div className="flex-1 overflow-y-auto space-y-2 pr-1">
              {historyData && historyData.battles.length > 0 ? (
                historyData.battles.map((b: any, idx: number) => (
                  <div
                    key={b.battle_id || idx}
                    className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between"
                  >
                    <div>
                      <div className="font-bold text-slate-200">{b.battle_id}</div>
                      <div className="text-[10px] text-slate-400">
                        Tier: {b.defense_tier || b.target_mode} • Scope: {b.scope || b.campaign}
                      </div>
                    </div>
                    <div className="text-right">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          b.winner === "BLUE_TEAM"
                            ? "bg-emerald-950 text-emerald-300 border border-emerald-700"
                            : "bg-rose-950 text-rose-300 border border-rose-700"
                        }`}
                      >
                        {b.winner}
                      </span>
                      <div className="text-[10px] text-slate-400 mt-1">
                        403: {b.blocked_count} | 200: {b.bypass_count}
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="py-12 text-center text-slate-500">Chưa có phiên lịch sử nào.</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="w-full h-7 shrink-0 border-t border-slate-900 bg-slate-950/90 px-4 text-[11px] font-mono text-slate-500 flex items-center justify-between whitespace-nowrap">
        <div className="flex items-center gap-3">
          <span>AI Arena Autonomous Pentest Cockpit</span>
          <span>•</span>
          <span className="text-rose-400">PyTorch Dueling-DQN v2.0 (64-D) vs Blue Team Hybrid v3.0</span>
          <span>•</span>
          <span className="text-slate-400">Live SSE Stream</span>
        </div>
        <div>
          <span>
            BFF Proxy: <span className="text-emerald-400 font-bold">CONNECTED (/api/gateway)</span>
          </span>
        </div>
      </footer>
    </div>
  );
}
