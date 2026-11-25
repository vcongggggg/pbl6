"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Header } from "@/components/Header";
import {
  triggerPentestRun,
  streamPentestEvaluation,
  fetchPentestCatalog,
  triggerPentestReplay,
  exportPentestEvidence,
  triggerBenchmarkReplay,
  fetchArenaHistory,
  fetchDashboardStats,
  toggleWafMode,
  BenchmarkReplayResponse,
  PentestAttackGraphNode,
  PentestCatalogFamily,
  PentestExportResponse,
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
  Repeat,
  Download,
  FileCheck2,
  Zap,
  Printer,
  FlaskConical,
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
  const [executionMode, setExecutionMode] = useState<"live_http" | "in_process">("live_http");
  const [scope, setScope] = useState<string>("full_pentest");
  const [customPayload, setCustomPayload] = useState<string>("");
  const [catalogFamilies, setCatalogFamilies] = useState<PentestCatalogFamily[]>([]);
  const [targetUrl, setTargetUrl] = useState<string>("http://127.0.0.1:5000");
  const [syncToSoc, setSyncToSoc] = useState<boolean>(false);
  const [maxRounds] = useState<number>(8);

  // Execution & Live SSE Trace States
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [isReplaying, setIsReplaying] = useState<boolean>(false);
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [currentPhase, setCurrentPhase] = useState<number>(0);
  const [specSource, setSpecSource] = useState<string>("OpenAPI Ready");
  const [surfaceNodes, setSurfaceNodes] = useState<PentestAttackGraphNode[]>(INITIAL_OPENAPI_SURFACES);
  const [report, setReport] = useState<PentestReport | null>(null);
  const [replayReport, setReplayReport] = useState<PentestReport | null>(null);
  const [exportResult, setExportResult] = useState<PentestExportResponse | null>(null);
  const [traceRounds, setTraceRounds] = useState<PentestRoundResult[]>([]);
  const [selectedRound, setSelectedRound] = useState<PentestRoundResult | null>(null);
  const [filterEndpoint, setFilterEndpoint] = useState<string>("ALL");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // History Drawer
  const [isHistoryOpen, setIsHistoryOpen] = useState<boolean>(false);
  const [historyData, setHistoryData] = useState<ArenaHistoryResponse | null>(null);

  // 100-Request Benchmark Replay Drawer (F1a)
  const [isBenchmarkOpen, setIsBenchmarkOpen] = useState<boolean>(false);
  const [isBenchmarkRunning, setIsBenchmarkRunning] = useState<boolean>(false);
  const [benchmarkDataset, setBenchmarkDataset] = useState<"csic2010" | "benchmark_1000">("csic2010");
  const [benchmarkMode, setBenchmarkMode] = useState<"balanced_100" | "benign_100">("balanced_100");
  const [benchmarkResult, setBenchmarkResult] = useState<BenchmarkReplayResponse | null>(null);

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
    fetchPentestCatalog()
      .then((cat) => {
        if (Array.isArray(cat?.families)) {
          setCatalogFamilies(cat.families);
        }
      })
      .catch(() => {
        // ignore offline catalog fetch
      });
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

  const triggerJsonDownload = (filename: string, payload: unknown) => {
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
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

  const isSingleFamilyScope = catalogFamilies.some((f) => f.family === scope);
  const activeFamilySample =
    catalogFamilies.find((f) => f.family === scope)?.baseline_payload || "";

  const handleRunPentest = async () => {
    if (isRunning || isReplaying) return;
    setIsRunning(true);
    setErrorMsg(null);
    setReport(null);
    setReplayReport(null);
    setExportResult(null);
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
      execution_mode: executionMode,
      custom_payload: customPayload.trim() ? customPayload : undefined,
      selected_families: isSingleFamilyScope ? [scope] : undefined,
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

  const handleReplayTraffic = async (sourceBattle?: { battle_id?: string; rounds?: PentestRoundResult[] }) => {
    if (isRunning || isReplaying) return;
    const roundsToReplay = sourceBattle?.rounds ?? (traceRounds.length > 0 ? traceRounds : null);
    const battleIdToReplay = sourceBattle?.battle_id ?? report?.battle_id ?? null;
    if (!battleIdToReplay && (!roundsToReplay || roundsToReplay.length === 0)) return;

    setIsReplaying(true);
    setErrorMsg(null);
    setExportResult(null);
    try {
      const replayed = await triggerPentestReplay({
        battle_id: battleIdToReplay,
        rounds: roundsToReplay,
        defense_tier: defenseTier,
        execution_mode: executionMode,
        target_url: targetUrl.trim() || "http://127.0.0.1:5000",
      });
      setReplayReport(replayed);
      setReport(replayed);
      setTraceRounds(replayed.rounds || []);
      if (replayed.rounds && replayed.rounds.length > 0) {
        setSelectedRound(replayed.rounds[0]);
      }
      setCurrentPhase(5);
      setIsHistoryOpen(false);
    } catch (err: any) {
      setErrorMsg(err?.message || "Không thể Replay traffic.");
    } finally {
      setIsReplaying(false);
    }
  };

  const handleExportEvidence = async (
    targetReport?: PentestReport | null,
    targetBattleId?: string | null
  ) => {
    if (isRunning || isExporting) return;
    const effectiveReport = targetReport ?? report;
    const effectiveBattleId = targetBattleId ?? effectiveReport?.battle_id ?? null;
    if (!effectiveReport && !effectiveBattleId) return;

    setIsExporting(true);
    setErrorMsg(null);
    try {
      const exported = await exportPentestEvidence({
        battle_id: effectiveBattleId,
        report: effectiveReport ?? null,
        replay_report: targetReport ? null : replayReport,
      });
      setExportResult(exported);
      triggerJsonDownload(exported.filename, exported.evidence);
    } catch (err: any) {
      setErrorMsg(err?.message || "Không thể xuất bằng chứng D4.");
    } finally {
      setIsExporting(false);
    }
  };

  const handleRunBenchmarkReplay = async (
    overrideDataset?: "csic2010" | "benchmark_1000",
    overrideMode?: "balanced_100" | "benign_100"
  ) => {
    if (isBenchmarkRunning) return;
    const ds = overrideDataset ?? benchmarkDataset;
    const md = overrideMode ?? benchmarkMode;
    setIsBenchmarkOpen(true);
    setIsBenchmarkRunning(true);
    setErrorMsg(null);
    try {
      const res = await triggerBenchmarkReplay({
        dataset: ds,
        sample_count: 100,
        mode: md,
        execution_mode: "in_process",
        defense_tier: defenseTier,
      });
      setBenchmarkResult(res);
    } catch (err: any) {
      setErrorMsg(err?.message || "Không thể chạy Benchmark Replay 100 requests.");
    } finally {
      setIsBenchmarkRunning(false);
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
    <>
      <div className="h-screen w-screen flex flex-col overflow-hidden bg-[#07090e] text-slate-100 font-sans selection:bg-rose-500 selection:text-white print:hidden">
      <Header
        stats={stats}
        onRefresh={loadStats}
        onToggleWafMode={handleToggleWafMode}
        isTogglingWaf={isTogglingWaf}
      />

      {/* Command Strip & 5-Phase Stepper */}
      <div className="min-h-14 shrink-0 bg-slate-900/80 border-b border-slate-800/80 px-4 py-1.5 flex flex-wrap items-center justify-between gap-2 text-xs font-mono whitespace-nowrap">
        <div className="flex flex-wrap items-center gap-2">
          {/* Editable Target API URL */}
          <div className="flex items-center gap-1.5 bg-slate-950/90 px-2.5 py-1 rounded-lg border border-slate-800">
            <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="text-[11px] text-slate-400">Target:</span>
            <input
              id="input-target-url"
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              disabled={isRunning || isReplaying}
              placeholder="http://127.0.0.1:5000"
              className="w-36 bg-transparent text-slate-200 focus:outline-none text-xs font-mono"
            />
          </div>

          {/* Execution Mode Toggle */}
          <div className="flex items-center bg-slate-950/90 p-1 rounded-lg border border-slate-800">
            <span className="text-[11px] text-slate-400 px-1.5 font-semibold flex items-center gap-1">
              <Zap className="w-3 h-3 text-cyan-400" />
              Mode:
            </span>
            <button
              id="btn-mode-live-http"
              onClick={() => setExecutionMode("live_http")}
              disabled={isRunning || isReplaying}
              className={`px-2 py-0.5 rounded text-[11px] transition cursor-pointer font-semibold ${
                executionMode === "live_http"
                  ? "bg-cyan-950/90 text-cyan-300 border border-cyan-500/60 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Live HTTP (/api/proxy)
            </button>
            <button
              id="btn-mode-in-process"
              onClick={() => setExecutionMode("in_process")}
              disabled={isRunning || isReplaying}
              className={`px-2 py-0.5 rounded text-[11px] transition cursor-pointer font-semibold ${
                executionMode === "in_process"
                  ? "bg-slate-800 text-slate-200 border border-slate-600 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              In-Process
            </button>
          </div>

          {/* 3-Tier Progressive Defense Switch */}
          <div className="flex items-center bg-slate-950/90 p-1 rounded-lg border border-slate-800">
            <span className="text-[11px] text-slate-400 px-1.5 font-semibold">Cấp độ:</span>
            <button
              onClick={() => setDefenseTier("no_waf")}
              disabled={isRunning || isReplaying}
              className={`px-2 py-0.5 rounded text-xs transition cursor-pointer font-semibold ${
                defenseTier === "no_waf"
                  ? "bg-rose-950/90 text-rose-300 border border-rose-600/60 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              1. No WAF
            </button>
            <button
              onClick={() => setDefenseTier("rules_only")}
              disabled={isRunning || isReplaying}
              className={`px-2 py-0.5 rounded text-xs transition cursor-pointer font-semibold ${
                defenseTier === "rules_only"
                  ? "bg-amber-950/90 text-amber-300 border border-amber-600/60 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              2. Rules Only
            </button>
            <button
              onClick={() => setDefenseTier("hybrid_v3")}
              disabled={isRunning || isReplaying}
              className={`px-2 py-0.5 rounded text-xs transition cursor-pointer font-semibold ${
                defenseTier === "hybrid_v3"
                  ? "bg-purple-950/90 text-purple-200 border border-purple-500/60 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              3. Hybrid v3.4
            </button>
          </div>

          {/* Scope / Selectable Family Selector */}
          <div className="flex items-center bg-slate-950/90 px-2.5 py-1 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[11px] mr-1">Phạm vi:</span>
            <select
              id="select-pentest-scope"
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              disabled={isRunning || isReplaying}
              className="bg-transparent text-slate-200 focus:outline-none text-xs cursor-pointer font-mono"
            >
              <option value="full_pentest" className="bg-slate-900">Full Pentest (8/8)</option>
              <option value="injection" className="bg-slate-900">OWASP Injections</option>
              <option value="api_logic" className="bg-slate-900">OWASP API Logic</option>
              {catalogFamilies.map((fam) => (
                <option key={fam.family} value={fam.family} className="bg-slate-900">
                  {fam.family} ({fam.method})
                </option>
              ))}
            </select>
          </div>

          {/* Optional Custom Payload Input */}
          <div className="flex items-center gap-1.5 bg-slate-950/90 px-2.5 py-1 rounded-lg border border-slate-800">
            <span className="text-[11px] text-slate-400">Payload:</span>
            <input
              id="input-custom-payload"
              type="text"
              value={customPayload}
              onChange={(e) => setCustomPayload(e.target.value)}
              disabled={isRunning || isReplaying}
              placeholder={activeFamilySample || "Custom payload (tuỳ chọn)..."}
              className="w-40 bg-transparent text-amber-300 placeholder:text-slate-600 focus:outline-none text-xs font-mono"
            />
          </div>

          {/* Sync SOC */}
          <label className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-slate-950/90 border border-slate-800 cursor-pointer">
            <input
              type="checkbox"
              checked={syncToSoc}
              onChange={(e) => setSyncToSoc(e.target.checked)}
              disabled={isRunning || isReplaying}
              className="accent-purple-500 rounded cursor-pointer"
            />
            <span className="text-[11px] text-slate-300">Sync -&gt; SOC</span>
          </label>

          {/* Run Button */}
          <button
            id="btn-run-pentest"
            onClick={handleRunPentest}
            disabled={isRunning || isReplaying}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold transition active:scale-95 disabled:opacity-50 cursor-pointer shadow-[0_0_15px_rgba(244,63,94,0.4)]"
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

          {/* Replay Traffic Button */}
          <button
            id="btn-replay-traffic"
            onClick={() => handleReplayTraffic()}
            disabled={isRunning || isReplaying || (!report && traceRounds.length === 0)}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-cyan-950/90 hover:bg-cyan-900/90 border border-cyan-600/60 text-cyan-200 font-semibold transition disabled:opacity-40 cursor-pointer"
            title="Phát lại tuần tự các request đã ghi nhận để kiểm chứng tính nhất quán"
          >
            <Repeat className={`w-3.5 h-3.5 ${isReplaying ? "animate-spin" : ""}`} />
            <span className="text-[11px]">{isReplaying ? "Đang Replay..." : "Replay Traffic"}</span>
          </button>

          {/* Export Evidence (D4) Button */}
          <button
            id="btn-export-evidence"
            onClick={() => handleExportEvidence()}
            disabled={isRunning || isExporting || !report}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-emerald-950/90 hover:bg-emerald-900/90 border border-emerald-600/60 text-emerald-200 font-semibold transition disabled:opacity-40 cursor-pointer"
            title="Xuất gói bằng chứng D4 bất biến kèm SHA-256"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="text-[11px]">{isExporting ? "Đang Xuất..." : "Export Evidence (D4)"}</span>
          </button>

          {/* Replay 100 Benchmark Button (F1a) */}
          <button
            id="btn-replay-benchmark"
            onClick={() => handleRunBenchmarkReplay()}
            disabled={isRunning || isReplaying || isBenchmarkRunning}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-amber-950/90 hover:bg-amber-900/90 border border-amber-600/60 text-amber-200 font-semibold transition disabled:opacity-40 cursor-pointer"
            title="Phát lại 100 request chuẩn (CSIC-2010 / Benchmark-1000) và đối chiếu Operational FPR"
          >
            <FlaskConical className={`w-3.5 h-3.5 ${isBenchmarkRunning ? "animate-pulse" : ""}`} />
            <span className="text-[11px]">
              {isBenchmarkRunning ? "Đang Replay 100..." : "Replay 100 Benchmark"}
            </span>
          </button>

          {/* Print A4 Report Button (F1b) */}
          <button
            id="btn-print-a4"
            onClick={() => window.print()}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-100 font-semibold transition cursor-pointer"
            title="In báo cáo chứng cứ A4 (window.print)"
          >
            <Printer className="w-3.5 h-3.5 text-cyan-300" />
            <span className="text-[11px]">In Báo Cáo A4</span>
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
        <div className="flex items-center gap-1 bg-slate-950/90 px-2.5 py-1 rounded-lg border border-slate-800 shrink-0">
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

          {report?.replay_comparison && (
            <div className="mt-2 p-2 rounded-lg bg-cyan-950/60 border border-cyan-600/70 text-cyan-200 text-xs font-mono flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 min-w-0">
                <Repeat className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span className="truncate">
                  Replay of <span className="font-bold">{report.replay_comparison.replay_of || "recorded"}</span>:{" "}
                  <span className="font-bold text-white">
                    {report.replay_comparison.matched_verdicts}/{report.replay_comparison.total_replayed}
                  </span>{" "}
                  verdicts matched
                </span>
              </div>
              <span className="px-2 py-0.5 rounded bg-cyan-900/80 border border-cyan-500/50 text-[10px] font-bold shrink-0">
                {report.replay_comparison.match_rate_pct.toFixed(1)}%
              </span>
            </div>
          )}

          {exportResult && (
            <div className="mt-2 p-2 rounded-lg bg-emerald-950/60 border border-emerald-600/70 text-emerald-200 text-xs font-mono flex items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 font-bold text-emerald-300">
                  <FileCheck2 className="w-3.5 h-3.5 shrink-0" />
                  <span className="truncate">D4 Saved: {exportResult.filename}</span>
                </div>
                <div className="text-[10px] text-emerald-400/90 truncate" title={exportResult.artifact_path}>
                  {exportResult.artifact_path}
                </div>
              </div>
              <button
                onClick={() => copyToClipboard(exportResult.sha256, "sha256")}
                className="px-2 py-0.5 rounded bg-emerald-900/80 border border-emerald-500/50 text-[10px] font-bold flex items-center gap-1 shrink-0 cursor-pointer"
                title={`SHA-256: ${exportResult.sha256}`}
              >
                {copiedKey === "sha256" ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                <span>SHA256: {exportResult.sha256.slice(0, 10)}...</span>
              </button>
            </div>
          )}

          {benchmarkResult && (
            <div
              onClick={() => setIsBenchmarkOpen(true)}
              className="mt-2 p-2 rounded-lg bg-amber-950/50 border border-amber-600/70 text-amber-100 text-xs font-mono flex items-center justify-between gap-2 cursor-pointer hover:bg-amber-950/70 transition"
              title="Nhấn để mở bảng 100 verdicts Benchmark Replay"
            >
              <div className="flex items-center gap-1.5 min-w-0">
                <FlaskConical className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                <span className="truncate">
                  {benchmarkResult.dataset} ({benchmarkResult.total_requests} req): TP={benchmarkResult.tp_count}, FP=
                  {benchmarkResult.fp_count}
                </span>
              </div>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 border ${
                  benchmarkResult.matches_fp_measurement
                    ? "bg-emerald-950/80 text-emerald-300 border-emerald-500/60"
                    : "bg-rose-950/80 text-rose-300 border-rose-500/60"
                }`}
              >
                Op FPR: {benchmarkResult.operational_fpr_pct.toFixed(3)}% (
                {benchmarkResult.matches_fp_measurement
                  ? "Matches fp_v3_measurement.json"
                  : `Ref: ${benchmarkResult.reference_operational_fpr_pct.toFixed(3)}%`}
                )
              </span>
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
                  <span className="text-purple-400">Hybrid v3.4</span>) rồi bấm{" "}
                  <span className="text-rose-400 font-bold">[Chạy Pentest AI]</span>.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* COLUMN 3: DUAL-BRAIN INSPECTOR */}
        <div className="col-span-12 lg:col-span-4 h-full min-h-0 flex flex-col gap-3 overflow-hidden">
          {/* Top Half: Trained 74-D Dueling-DQN Brain */}
          <div className="flex-1 min-h-0 bg-slate-900/70 border border-slate-800/80 rounded-xl p-3 shadow flex flex-col overflow-hidden">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 text-xs font-mono">
              <span className="font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-rose-400" />
                Bộ Não Red Team Dueling-DQN
              </span>
              <span className="text-[10px] text-slate-400">74-D State -&gt; 36 Actions</span>
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
                    className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="font-bold text-slate-200 truncate">{b.battle_id}</div>
                        <div className="text-[10px] text-slate-400 truncate">
                          Tier: {b.defense_tier || b.target_mode} • Scope: {b.scope || b.campaign}
                          {b.execution_mode ? ` • ${b.execution_mode}` : ""}
                        </div>
                      </div>
                      <div className="text-right shrink-0">
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

                    <div className="flex items-center justify-end gap-1.5 pt-1 border-t border-slate-800/80">
                      <button
                        onClick={() => handleReplayTraffic({ battle_id: b.battle_id, rounds: b.rounds })}
                        disabled={isRunning || isReplaying}
                        className="px-2 py-1 rounded bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-200 text-[10px] font-semibold flex items-center gap-1 disabled:opacity-40 cursor-pointer"
                      >
                        <Repeat className="w-3 h-3" />
                        <span>Replay</span>
                      </button>
                      <button
                        onClick={() => handleExportEvidence(b, b.battle_id)}
                        disabled={isRunning || isExporting}
                        className="px-2 py-1 rounded bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/60 text-emerald-200 text-[10px] font-semibold flex items-center gap-1 disabled:opacity-40 cursor-pointer"
                      >
                        <Download className="w-3 h-3" />
                        <span>Export (D4)</span>
                      </button>
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

      {/* 100-Request Benchmark Replay Modal / Drawer (F1a) */}
      {isBenchmarkOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-5xl max-h-[88vh] bg-slate-900 border border-slate-700 rounded-xl p-4 flex flex-col font-mono text-xs shadow-2xl">
            <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FlaskConical className="w-4 h-4 text-amber-400" />
                <span className="font-bold text-white text-sm">
                  Replay 100 Benchmark Corpus (In-Process Engine) &amp; Operational FPR Reconciliation
                </span>
                {benchmarkResult && (
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      benchmarkResult.matches_fp_measurement
                        ? "bg-emerald-950/90 text-emerald-300 border-emerald-600/70"
                        : "bg-rose-950/90 text-rose-300 border-rose-600/70"
                    }`}
                  >
                    Op FPR: {benchmarkResult.operational_fpr_pct.toFixed(3)}% (
                    {benchmarkResult.matches_fp_measurement
                      ? "Matches fp_v3_measurement.json"
                      : `Ref: ${benchmarkResult.reference_operational_fpr_pct.toFixed(3)}%`}
                    )
                  </span>
                )}
              </div>

              <div className="flex items-center gap-2">
                <select
                  value={benchmarkDataset}
                  onChange={(e) => {
                    const nextDs = e.target.value as "csic2010" | "benchmark_1000";
                    setBenchmarkDataset(nextDs);
                    handleRunBenchmarkReplay(nextDs, benchmarkMode);
                  }}
                  disabled={isBenchmarkRunning}
                  className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs"
                >
                  <option value="csic2010">CSIC 2010</option>
                  <option value="benchmark_1000">Benchmark 1000</option>
                </select>
                <select
                  value={benchmarkMode}
                  onChange={(e) => {
                    const nextMode = e.target.value as "balanced_100" | "benign_100";
                    setBenchmarkMode(nextMode);
                    handleRunBenchmarkReplay(benchmarkDataset, nextMode);
                  }}
                  disabled={isBenchmarkRunning}
                  className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs"
                >
                  <option value="balanced_100">Balanced 100 (50/50)</option>
                  <option value="benign_100">Benign 100 (100% Benign)</option>
                </select>
                <button
                  onClick={() => handleRunBenchmarkReplay()}
                  disabled={isBenchmarkRunning}
                  className="px-2.5 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white font-bold disabled:opacity-50 cursor-pointer"
                >
                  {isBenchmarkRunning ? "Đang chạy..." : "Chạy lại 100 req"}
                </button>
                <button
                  onClick={() => setIsBenchmarkOpen(false)}
                  className="text-slate-400 hover:text-white cursor-pointer p-1"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {isBenchmarkRunning && !benchmarkResult ? (
              <div className="py-16 text-center text-slate-400">
                Đang phát lại 100 request qua Hybrid WAF v3.0...
              </div>
            ) : benchmarkResult ? (
              <>
                <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 my-3 text-center">
                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Total Requests</div>
                    <div className="text-sm font-bold text-white">{benchmarkResult.total_requests}</div>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Benign / Attack</div>
                    <div className="text-sm font-bold text-cyan-300">
                      {benchmarkResult.benign_count} / {benchmarkResult.attack_count}
                    </div>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-emerald-900/50">
                    <div className="text-[10px] text-slate-400">TP / TN</div>
                    <div className="text-sm font-bold text-emerald-400">
                      {benchmarkResult.tp_count} / {benchmarkResult.tn_count}
                    </div>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-rose-900/50">
                    <div className="text-[10px] text-slate-400">FP / FN</div>
                    <div className="text-sm font-bold text-rose-400">
                      {benchmarkResult.fp_count} / {benchmarkResult.fn_count}
                    </div>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Detection Rate</div>
                    <div className="text-sm font-bold text-amber-300">
                      {benchmarkResult.detection_rate_pct.toFixed(1)}%
                    </div>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Avg Latency</div>
                    <div className="text-sm font-bold text-slate-200">
                      {benchmarkResult.avg_latency_ms.toFixed(2)} ms
                    </div>
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto border border-slate-800 rounded-lg">
                  <table className="w-full text-left border-collapse text-[11px]">
                    <thead className="bg-slate-950 text-slate-400 sticky top-0">
                      <tr>
                        <th className="p-2 border-b border-slate-800">#</th>
                        <th className="p-2 border-b border-slate-800">Method</th>
                        <th className="p-2 border-b border-slate-800">Path</th>
                        <th className="p-2 border-b border-slate-800">Ground Truth</th>
                        <th className="p-2 border-b border-slate-800">HTTP</th>
                        <th className="p-2 border-b border-slate-800">Decision</th>
                        <th className="p-2 border-b border-slate-800">Risk</th>
                        <th className="p-2 border-b border-slate-800">Latency</th>
                        <th className="p-2 border-b border-slate-800">Matched Rules</th>
                      </tr>
                    </thead>
                    <tbody>
                      {benchmarkResult.verdicts.map((v) => (
                        <tr
                          key={v.index}
                          className="border-b border-slate-800/60 hover:bg-slate-800/40"
                        >
                          <td className="p-1.5 text-slate-400">{v.index}</td>
                          <td className="p-1.5 font-bold text-slate-300">{v.method}</td>
                          <td className="p-1.5 text-slate-200 max-w-[220px] truncate" title={v.path}>
                            {v.path}
                          </td>
                          <td className="p-1.5">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                v.label === 0
                                  ? "bg-slate-800 text-slate-300"
                                  : "bg-rose-950/70 text-rose-300 border border-rose-800/60"
                              }`}
                            >
                              {v.attack_type}
                            </span>
                          </td>
                          <td className="p-1.5 text-slate-300">{v.http_status}</td>
                          <td className="p-1.5">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                v.waf_blocked
                                  ? "bg-emerald-950/80 text-emerald-300"
                                  : "bg-slate-800 text-slate-300"
                              }`}
                            >
                              {v.waf_decision}
                            </span>
                          </td>
                          <td className="p-1.5 text-slate-300">{v.threat_score.toFixed(1)}</td>
                          <td className="p-1.5 text-slate-400">{v.latency_ms.toFixed(2)} ms</td>
                          <td className="p-1.5 text-amber-300 truncate max-w-[140px]">
                            {v.matched_rules.length > 0 ? v.matched_rules.join(", ") : "-"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              <div className="py-12 text-center text-slate-500">Chưa có dữ liệu benchmark.</div>
            )}
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="w-full h-7 shrink-0 border-t border-slate-900 bg-slate-950/90 px-4 text-[11px] font-mono text-slate-500 flex items-center justify-between whitespace-nowrap">
        <div className="flex items-center gap-3">
          <span>AI Arena Autonomous Pentest Cockpit</span>
          <span>•</span>
          <span className="text-rose-400">PyTorch Dueling-DQN v2.0 (74-D) vs Blue Team Hybrid v3.4</span>
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

      {/* F1b: Printable A4 Evidence Report */}
      <section id="arena-print-report" className="hidden print:block bg-white text-slate-900 p-4 text-xs font-sans">
        <div className="border-b-2 border-slate-800 pb-3 mb-4 flex items-start justify-between gap-4">
          <div>
            <h1 className="text-lg font-bold text-slate-900">
              PBL6 AI Arena — Autonomous Pentest &amp; Hybrid WAF v3.0 Evidence Report
            </h1>
            <p className="text-[11px] text-slate-600 mt-0.5">
              Immutable Evaluation Summary, Replay Reconciliation &amp; Operational FPR Verification (A4 Portrait)
            </p>
          </div>
          <div className="text-right text-[10px] font-mono text-slate-700">
            <div>Battle ID: <span className="font-bold">{report?.battle_id || "N/A"}</span></div>
            <div>Timestamp: {report?.timestamp || benchmarkResult?.timestamp || "N/A"}</div>
            <div>Mode / Tier: {report?.execution_mode || executionMode} / {report?.defense_tier || defenseTier}</div>
          </div>
        </div>

        {/* Cryptographic Provenance */}
        <div className="border border-slate-300 rounded p-2.5 mb-4 bg-slate-50 text-[10px] font-mono space-y-1">
          <div>
            <span className="font-bold">Target URL:</span> {report?.target_url || targetUrl} •{" "}
            <span className="font-bold">Scope:</span> {report?.scope || scope}
          </div>
          <div>
            <span className="font-bold">git_head_sha:</span>{" "}
            {exportResult?.evidence?.metadata?.git_head_sha || "Chưa export D4"}
          </div>
          <div className="break-all">
            <span className="font-bold">sha256_digest:</span>{" "}
            {exportResult?.sha256 || exportResult?.evidence?.metadata?.sha256_digest || "Chưa export D4"}
          </div>
        </div>

        {/* KPI Summary */}
        <div className="grid grid-cols-4 gap-2 mb-4">
          <div className="border border-slate-300 rounded p-2 text-center">
            <div className="text-[10px] text-slate-500 uppercase">Blocked / Total</div>
            <div className="text-sm font-bold text-slate-900">
              {report ? `${report.blocked_count} / ${report.total_rounds}` : "0 / 0"}
            </div>
          </div>
          <div className="border border-slate-300 rounded p-2 text-center">
            <div className="text-[10px] text-slate-500 uppercase">Winner</div>
            <div className="text-sm font-bold text-slate-900">{report?.winner || "N/A"}</div>
          </div>
          <div className="border border-slate-300 rounded p-2 text-center">
            <div className="text-[10px] text-slate-500 uppercase">Avg Threat Score</div>
            <div className="text-sm font-bold text-slate-900">
              {report ? `${report.avg_threat_score.toFixed(1)} / 100` : "0.0 / 100"}
            </div>
          </div>
          <div className="border border-slate-300 rounded p-2 text-center">
            <div className="text-[10px] text-slate-500 uppercase">Avg Latency</div>
            <div className="text-sm font-bold text-slate-900">
              {report ? `${report.avg_latency_ms.toFixed(2)} ms` : "0.00 ms"}
            </div>
          </div>
        </div>

        {/* Replay Comparison */}
        {(report?.replay_comparison || replayReport?.replay_comparison) && (
          <div className="border border-slate-300 rounded p-2.5 mb-4 text-[11px]">
            <h2 className="font-bold text-slate-900 mb-1">Deterministic Traffic Replay Comparison</h2>
            {(() => {
              const comp = report?.replay_comparison || replayReport?.replay_comparison;
              if (!comp) return null;
              return (
                <div className="font-mono text-[10px]">
                  Replay Of: <span className="font-bold">{comp.replay_of || "recorded"}</span> | Matched:{" "}
                  <span className="font-bold">
                    {comp.matched_verdicts}/{comp.total_replayed}
                  </span>{" "}
                  ({comp.match_rate_pct.toFixed(1)}%) | Mismatches: {comp.mismatches.length}
                </div>
              );
            })()}
          </div>
        )}

        {/* 100-Request Benchmark FP Reconciliation */}
        {benchmarkResult && (
          <div className="border border-slate-300 rounded p-2.5 mb-4 text-[11px]">
            <h2 className="font-bold text-slate-900 mb-1">
              100-Request Benchmark Corpus FP Reconciliation ({benchmarkResult.dataset} / {benchmarkResult.mode})
            </h2>
            <div className="grid grid-cols-4 gap-2 font-mono text-[10px]">
              <div>
                Requests: <span className="font-bold">{benchmarkResult.total_requests}</span> (B=
                {benchmarkResult.benign_count}, A={benchmarkResult.attack_count})
              </div>
              <div>
                TP={benchmarkResult.tp_count}, TN={benchmarkResult.tn_count}, FP={benchmarkResult.fp_count}, FN=
                {benchmarkResult.fn_count}
              </div>
              <div>
                Op FPR: <span className="font-bold">{benchmarkResult.operational_fpr_pct.toFixed(3)}%</span> (Ref:{" "}
                {benchmarkResult.reference_operational_fpr_pct.toFixed(3)}%)
              </div>
              <div>
                Matches fp_v3_measurement:{" "}
                <span className="font-bold">{benchmarkResult.matches_fp_measurement ? "YES" : "NO"}</span> | Avg:{" "}
                {benchmarkResult.avg_latency_ms.toFixed(2)} ms
              </div>
            </div>
          </div>
        )}

        {/* Per-Round Verdict Table */}
        <div>
          <h2 className="font-bold text-slate-900 mb-1.5 text-xs">Per-Round Verdict Trace</h2>
          <table className="w-full border-collapse border border-slate-300 text-[10px] font-mono">
            <thead className="bg-slate-100">
              <tr>
                <th className="border border-slate-300 p-1 text-left">#</th>
                <th className="border border-slate-300 p-1 text-left">Attack Type</th>
                <th className="border border-slate-300 p-1 text-left">Endpoint</th>
                <th className="border border-slate-300 p-1 text-left">Technique</th>
                <th className="border border-slate-300 p-1 text-left">HTTP</th>
                <th className="border border-slate-300 p-1 text-left">Decision</th>
                <th className="border border-slate-300 p-1 text-left">Risk</th>
                <th className="border border-slate-300 p-1 text-left">R/ML/IF</th>
                <th className="border border-slate-300 p-1 text-left">Latency</th>
                <th className="border border-slate-300 p-1 text-left">Rules</th>
              </tr>
            </thead>
            <tbody>
              {(report?.rounds ?? traceRounds).length > 0 ? (
                (report?.rounds ?? traceRounds).map((r, idx) => (
                  <tr key={r.round_num ?? r.round ?? idx} className="break-inside-avoid">
                    <td className="border border-slate-300 p-1">{r.round_num ?? r.round ?? idx + 1}</td>
                    <td className="border border-slate-300 p-1">{r.attack_type}</td>
                    <td className="border border-slate-300 p-1 break-all">
                      {r.method} {r.target_endpoint || r.endpoint}
                    </td>
                    <td className="border border-slate-300 p-1">{r.mutation_technique || r.technique}</td>
                    <td className="border border-slate-300 p-1">{r.http_status ?? r.response_status}</td>
                    <td className="border border-slate-300 p-1 font-bold">{r.waf_decision}</td>
                    <td className="border border-slate-300 p-1">
                      {(r.waf_threat_score ?? r.threat_score ?? 0).toFixed(1)}
                    </td>
                    <td className="border border-slate-300 p-1">
                      {(r.rule_score ?? 0).toFixed(0)}/{(r.ml_score ?? 0).toFixed(0)}/
                      {(r.anomaly_score ?? 0).toFixed(0)}
                    </td>
                    <td className="border border-slate-300 p-1">{(r.latency_ms ?? 0).toFixed(2)} ms</td>
                    <td className="border border-slate-300 p-1">
                      {r.matched_rules && r.matched_rules.length > 0 ? r.matched_rules.join(", ") : "-"}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={10} className="border border-slate-300 p-2 text-center text-slate-500">
                    Chưa có vòng đối kháng Pentest nào được ghi nhận.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
