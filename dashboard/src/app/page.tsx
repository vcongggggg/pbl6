"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { Header } from "@/components/Header";
import { ThreatTimelineChart } from "@/components/ThreatTimelineChart";
import { AttackDistributionChart } from "@/components/AttackDistributionChart";
import { ProtocolDistributionChart } from "@/components/ProtocolDistributionChart";
import { NetworkTopologyMap } from "@/components/NetworkTopologyMap";
import { LiveEventsTable, PayloadEvidenceDrawer, AttackSessionsModal } from "@/components/events";
import { DetectionExplainabilityModal } from "@/components/explain";
import {
  fetchDashboardStats,
  fetchDashboardEvents,
  fetchDashboardTimeline,
  fetchDashboardDistribution,
  fetchDashboardProtocols,
  fetchCyberRangeTopology,
  triggerSimulation,
  resetDemoData,
  seedDemoData,
  toggleWafMode,
  fetchAttackSessions,
} from "@/services/api";
import {
  AttackDistributionItem,
  ProtocolDistributionItem,
  CyberRangeTopology,
  DashboardStats,
  SecurityEventItem,
  TimelinePoint,
  AttackSessionItem,
} from "@/types/dashboard";
import {
  CheckCircle2,
  AlertCircle,
  Info,
  X,
  Shield,
  BarChart3,
  Network,
  Zap,
  Flame,
  FolderTree,
  Terminal,
  Globe,
  UserCheck,
  KeyRound,
  FileCode,
  Layers,
  ArrowUpDown,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";

export default function SOCDashboard() {
  // Navigation view inside Cockpit
  const [activeView, setActiveView] = useState<"live" | "analytics" | "topology">("live");

  // Telemetry states
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [distribution, setDistribution] = useState<AttackDistributionItem[]>([]);
  const [protocols, setProtocols] = useState<ProtocolDistributionItem[]>([]);
  const [topology, setTopology] = useState<CyberRangeTopology | null>(null);
  const [sessions, setSessions] = useState<AttackSessionItem[]>([]);

  // UI & Table filter states
  const [page, setPage] = useState<number>(1);
  const limit = 12;
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [attackTypeFilter, setAttackTypeFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);
  const [explainingEvent, setExplainingEvent] = useState<SecurityEventItem | null>(null);
  const [isAttackSessionsOpen, setIsAttackSessionsOpen] = useState<boolean>(false);
  const [sessionIpFilter, setSessionIpFilter] = useState<string>("");

  // Operation states
  const [pollingInterval, setPollingInterval] = useState<number>(3); // 3s default
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isResetting, setIsResetting] = useState<boolean>(false);
  const [isSeeding, setIsSeeding] = useState<boolean>(false);
  const [isTogglingWaf, setIsTogglingWaf] = useState<boolean>(false);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [activeSimulation, setActiveSimulation] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" | "info" } | null>(null);

  // Debounce search query
  const [debouncedQuery, setDebouncedQuery] = useState<string>("");
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(searchQuery), 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  const showToast = (message: string, type: "success" | "error" | "info" = "info") => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  // Main data loader
  const loadData = useCallback(async (showLoadingSpinner: boolean = false) => {
    if (showLoadingSpinner) setIsRefreshing(true);
    try {
      const [statsData, eventsData, timelineData, distData, protoData, topoData, sessionsData] = await Promise.all([
        fetchDashboardStats().catch(() => null),
        fetchDashboardEvents({
          page,
          limit,
          severity: severityFilter,
          attack_type: attackTypeFilter,
          q: debouncedQuery,
        }).catch(() => ({ items: [], total: 0, page: 1, limit })),
        fetchDashboardTimeline(60).catch(() => []),
        fetchDashboardDistribution().catch(() => []),
        fetchDashboardProtocols().catch(() => []),
        fetchCyberRangeTopology().catch(() => null),
        fetchAttackSessions({ limit: 10 }).catch(() => ({ items: [], total: 0, page: 1, limit: 10 })),
      ]);

      if (statsData) setStats(statsData);
      setEvents(eventsData.items);
      setTotalEvents(eventsData.total);
      setTimeline(timelineData);
      setDistribution(distData);
      setProtocols(protoData);
      if (topoData) setTopology(topoData);
      if (sessionsData && Array.isArray(sessionsData.items)) {
        setSessions(sessionsData.items);
      }
    } catch (err: any) {
      console.error("Dashboard data load error:", err);
    } finally {
      if (showLoadingSpinner) setIsRefreshing(false);
    }
  }, [page, limit, severityFilter, attackTypeFilter, debouncedQuery]);

  useEffect(() => {
    loadData(false);
  }, [loadData]);

  // Smart Polling
  const isInspectorOpen = selectedEvent !== null || explainingEvent !== null;
  const isInspectorOpenRef = useRef(isInspectorOpen);
  isInspectorOpenRef.current = isInspectorOpen;

  useEffect(() => {
    if (pollingInterval <= 0) return;
    const interval = setInterval(() => {
      if (!isInspectorOpenRef.current) {
        loadData(false);
      }
    }, pollingInterval * 1000);
    return () => clearInterval(interval);
  }, [pollingInterval, loadData]);

  // Quick Simulator Trigger
  const handleSimulate = async (type: string) => {
    setIsSimulating(true);
    setActiveSimulation(type);
    try {
      const res = await triggerSimulation(type);
      showToast(res.message, "success");
      await loadData(false);
    } catch (err: any) {
      showToast(`Mô phỏng thất bại: ${err.message}`, "error");
    } finally {
      setIsSimulating(false);
      setActiveSimulation(null);
    }
  };

  // Reset Demo Action
  const handleResetDemo = async () => {
    if (!window.confirm("Bạn có chắc chắn muốn dọn sạch toàn bộ log thử nghiệm để bắt đầu demo mới?")) {
      return;
    }
    setIsResetting(true);
    try {
      await resetDemoData();
      showToast("Đã dọn sạch toàn bộ log thử nghiệm trong cơ sở dữ liệu!", "info");
      setSelectedEvent(null);
      await loadData(true);
    } catch (err: any) {
      showToast(`Reset failed: ${err.message}`, "error");
    } finally {
      setIsResetting(false);
    }
  };

  // Seed Demo Action
  const handleSeedDemo = async () => {
    setIsSeeding(true);
    try {
      const res = await seedDemoData();
      showToast(res.message || "Đã nạp thành công bộ dữ liệu mẫu!", "success");
      setSelectedEvent(null);
      await loadData(true);
    } catch (err: any) {
      showToast(`Seed demo failed: ${err.message}`, "error");
    } finally {
      setIsSeeding(false);
    }
  };

  // Toggle WAF Mode Action
  const handleToggleWafMode = async () => {
    setIsTogglingWaf(true);
    try {
      const res = await toggleWafMode();
      showToast(res.message, "success");
      await loadData(false);
    } catch (err: any) {
      showToast(`Không thể chuyển chế độ WAF: ${err.message}`, "error");
    } finally {
      setIsTogglingWaf(false);
    }
  };

  // Calculated KPI numbers
  const totalRequests = stats?.total_requests ?? 0;
  const attacksDetected = stats?.attacks_detected ?? 0;
  const threatScore = stats?.avg_threat_score ?? 0;
  const riskScore = stats?.avg_risk_score ?? threatScore;
  const blockedCount = stats?.blocked_count ?? 0;
  const rateLimitedCount = stats?.rate_limited_count ?? 0;
  const safeRate = stats?.safe_request_rate ?? 100;
  const rps = stats?.current_rps ?? 0;

  return (
    <div className="h-screen w-screen flex flex-col overflow-hidden bg-[#07090e] text-slate-100 font-sans selection:bg-purple-500 selection:text-white">
      {/* Toast Notification Banner */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl border shadow-2xl backdrop-blur-xl transition-all duration-300 animate-in fade-in slide-in-from-bottom-5 bg-slate-900/95 border-slate-700 text-xs font-mono">
          {toast.type === "success" && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
          {toast.type === "error" && <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />}
          {toast.type === "info" && <Info className="w-4 h-4 text-cyan-400 shrink-0" />}
          <span className="text-slate-200">{toast.message}</span>
          <button onClick={() => setToast(null)} className="ml-2 text-slate-500 hover:text-white transition">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* 1. Header (h-14, 56px) */}
      <Header
        stats={stats}
        pollingInterval={pollingInterval}
        setPollingInterval={setPollingInterval}
        onRefresh={() => loadData(true)}
        onResetDemo={handleResetDemo}
        onSeedDemo={handleSeedDemo}
        onToggleWafMode={handleToggleWafMode}
        isRefreshing={isRefreshing}
        isResetting={isResetting}
        isSeeding={isSeeding}
        isTogglingWaf={isTogglingWaf}
        onOpenAttackSessions={() => { setSessionIpFilter(""); setIsAttackSessionsOpen(true); }}
      />

      {/* 2. Slim KPI Strip & Cockpit View Switcher (h-12, 48px) */}
      <div className="h-12 shrink-0 bg-slate-900/70 border-b border-slate-800/80 px-4 flex items-center justify-between gap-3 text-xs font-mono whitespace-nowrap overflow-x-auto">
        {/* Left: 5 Slim Metric Chips */}
        <div className="flex items-center gap-2">
          {/* Total Traffic */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-950/70 border border-slate-800">
            <ArrowUpDown className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">Traffic:</span>
            <span className="text-white font-bold">{totalRequests.toLocaleString()}</span>
            <span className="text-[10px] text-cyan-400">({rps.toFixed(1)} rps)</span>
          </div>

          {/* Attacks / Blocked */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-950/70 border border-rose-900/40">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            <span className="text-slate-400">Attacks:</span>
            <span className="text-rose-300 font-bold">{attacksDetected.toLocaleString()}</span>
            <span className="text-[10px] text-rose-400 font-semibold">(403: {blockedCount})</span>
          </div>

          {/* Rate/BOLA 429 */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-950/70 border border-amber-900/40">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            <span className="text-slate-400">429 Limited:</span>
            <span className="text-amber-300 font-bold">{rateLimitedCount}</span>
          </div>

          {/* Safe Rate */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-950/70 border border-emerald-900/40">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-slate-400">Safe:</span>
            <span className="text-emerald-400 font-bold">{safeRate.toFixed(1)}%</span>
          </div>

          {/* Hybrid Risk */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-950/70 border border-purple-900/40">
            <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-slate-400">Risk:</span>
            <span className={`font-bold ${riskScore > 50 ? "text-amber-400" : "text-emerald-400"}`}>
              {riskScore.toFixed(1)}/100
            </span>
          </div>
        </div>

        {/* Right: 3 Cockpit View Switcher Tabs */}
        <div className="flex items-center bg-slate-950/90 p-0.5 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveView("live")}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition cursor-pointer ${
              activeView === "live"
                ? "bg-purple-950/90 text-purple-200 border border-purple-500/50 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Shield className="w-3.5 h-3.5 text-purple-400" />
            <span>1. Live SOC (Default)</span>
          </button>

          <button
            onClick={() => setActiveView("analytics")}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition cursor-pointer ${
              activeView === "analytics"
                ? "bg-purple-950/90 text-purple-200 border border-purple-500/50 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <BarChart3 className="w-3.5 h-3.5 text-cyan-400" />
            <span>2. Phân Tích &amp; Kill Chain</span>
          </button>

          <button
            onClick={() => setActiveView("topology")}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition cursor-pointer ${
              activeView === "topology"
                ? "bg-purple-950/90 text-purple-200 border border-purple-500/50 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Network className="w-3.5 h-3.5 text-emerald-400" />
            <span>3. Cyber Range Topology</span>
          </button>
        </div>
      </div>

      {/* 3. Main Body Area (Zero-Scroll Locked Height) */}
      <main className="flex-1 min-h-0 p-3 overflow-hidden">
        {/* VIEW 1: LIVE SOC COCKPIT (66% Left / 34% Right) */}
        {activeView === "live" && (
          <div className="h-full grid grid-cols-12 gap-3 min-h-0">
            {/* Left Column (8 cols ~ 66%): Live Security Events Table */}
            <div className="col-span-12 lg:col-span-8 h-full min-h-0 flex flex-col">
              <LiveEventsTable
                events={events}
                totalEvents={totalEvents}
                page={page}
                limit={limit}
                setPage={setPage}
                severityFilter={severityFilter}
                setSeverityFilter={setSeverityFilter}
                attackTypeFilter={attackTypeFilter}
                setAttackTypeFilter={setAttackTypeFilter}
                searchQuery={searchQuery}
                setSearchQuery={setSearchQuery}
                onSelectEvent={(ev) => setSelectedEvent(ev)}
                onExplainEvent={(ev) => setExplainingEvent(ev)}
                selectedEventId={selectedEvent?.event_id ?? null}
                className="h-full min-h-0"
              />
            </div>

            {/* Right Column (4 cols ~ 34%): Compact Telemetry & 1-Click Simulator */}
            <div className="col-span-12 lg:col-span-4 h-full min-h-0 flex flex-col gap-2.5 overflow-hidden">
              {/* Top: 60s Threat Timeline Chart (Compact) */}
              <div className="h-[190px] shrink-0 bg-slate-900/70 border border-slate-800/80 rounded-xl p-3 shadow flex flex-col min-h-0 overflow-hidden">
                <ThreatTimelineChart data={timeline} compact />
              </div>

              {/* Middle: Compact Zero-Clipping Horizontal Attack & Protocol Mix Bars */}
              <div className="h-[168px] shrink-0 bg-slate-900/70 border border-slate-800/80 rounded-xl p-3 shadow flex flex-col justify-between min-h-0 overflow-hidden">
                <div className="flex items-center justify-between pb-1.5 border-b border-slate-800/80 text-xs font-mono shrink-0">
                  <span className="text-slate-300 font-semibold flex items-center gap-1.5">
                    <BarChart3 className="w-3.5 h-3.5 text-purple-400" />
                    Attack &amp; Protocol Mix
                  </span>
                  <button
                    onClick={() => setActiveView("analytics")}
                    className="text-[10px] text-cyan-400 hover:underline cursor-pointer"
                  >
                    Biểu đồ đầy đủ -&gt;
                  </button>
                </div>
                <div className="flex-1 grid grid-cols-2 gap-3 mt-1.5 min-h-0 overflow-hidden text-[10px] font-mono">
                  {/* Left: Top 3 Attack Families */}
                  <div className="space-y-1.5 overflow-hidden">
                    <div className="text-slate-400 font-semibold uppercase tracking-wider text-[9px]">
                      Top Attack Vectors
                    </div>
                    {distribution.length > 0 ? (
                      distribution.slice(0, 3).map((item, idx) => {
                        const pct = Math.min(100, Math.max(6, Number(item.percentage ?? 0)));
                        return (
                          <div key={idx} className="space-y-0.5">
                            <div className="flex justify-between gap-1">
                              <span className="text-slate-200 truncate">{item.name}</span>
                              <span className="text-rose-300 font-bold shrink-0">{item.count}</span>
                            </div>
                            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                              <div className="h-full bg-rose-500 rounded-full" style={{ width: `${pct}%` }} />
                            </div>
                          </div>
                        );
                      })
                    ) : (
                      <div className="text-slate-500 pt-3">0 incidents</div>
                    )}
                  </div>

                  {/* Right: Top 3 API Protocols */}
                  <div className="space-y-1.5 overflow-hidden border-l border-slate-800/70 pl-3">
                    <div className="text-slate-400 font-semibold uppercase tracking-wider text-[9px]">
                      API Protocols
                    </div>
                    {protocols.length > 0 ? (
                      protocols.slice(0, 3).map((p, idx) => {
                        const pct = Math.min(100, Math.max(6, Number(p.percentage ?? 0)));
                        return (
                          <div key={idx} className="space-y-0.5">
                            <div className="flex justify-between gap-1">
                              <span className="text-slate-200 truncate">{p.name}</span>
                              <span className="text-cyan-300 font-bold shrink-0">{pct.toFixed(0)}%</span>
                            </div>
                            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                              <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${pct}%` }} />
                            </div>
                          </div>
                        );
                      })
                    ) : (
                      <div className="text-slate-500 pt-3">REST Ready</div>
                    )}
                  </div>
                </div>
              </div>

              {/* Bottom: Quick Live Attack Simulator (OWASP Top 10 + API Guard Probes) */}
              <div className="flex-1 min-h-0 bg-slate-900/70 border border-slate-800/80 rounded-xl p-3 shadow flex flex-col justify-between overflow-y-auto">
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold uppercase tracking-wider text-purple-300 flex items-center gap-1.5 font-mono">
                      <Zap className="w-3.5 h-3.5 text-purple-400" />
                      Quick Live Simulator (11 Vectors)
                    </span>
                    <span className="text-[10px] text-emerald-400 font-mono bg-emerald-950/60 border border-emerald-800/50 px-1.5 py-0.2 rounded">
                      Real HTTP Probes
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mb-2">
                    Bắn request thực qua WAF Gateway — bảng bên trái sẽ cập nhật tức thì:
                  </p>

                  {/* 10 Attack Buttons Grid (2x5) + 1 Benign = 11 Vectors */}
                  <div className="grid grid-cols-2 gap-1.5 text-[11px] font-mono">
                    <button
                      id="sim-sqli"
                      onClick={() => handleSimulate("SQLI")}
                      disabled={isSimulating}
                      className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-rose-950/50 hover:bg-rose-900/70 text-rose-300 border border-rose-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer"
                      title="SQL Injection: ' OR 1=1--"
                    >
                      <Flame className="w-3 h-3 text-rose-400 shrink-0" />
                      <span className="truncate">{activeSimulation === "SQLI" ? "Firing..." : "SQLi Probe"}</span>
                    </button>

                    <button
                      id="sim-xss"
                      onClick={() => handleSimulate("XSS")}
                      disabled={isSimulating}
                      className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-amber-950/50 hover:bg-amber-900/70 text-amber-300 border border-amber-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer"
                      title="XSS: <script>alert(1)</script>"
                    >
                      <Zap className="w-3 h-3 text-amber-400 shrink-0" />
                      <span className="truncate">{activeSimulation === "XSS" ? "Firing..." : "XSS Probe"}</span>
                    </button>

                    <button
                      id="sim-path"
                      onClick={() => handleSimulate("PATH")}
                      disabled={isSimulating}
                      className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-teal-950/50 hover:bg-teal-900/70 text-teal-300 border border-teal-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer"
                      title="Path Traversal: ../../../../etc/passwd"
                    >
                      <FolderTree className="w-3 h-3 text-teal-400 shrink-0" />
                      <span className="truncate">{activeSimulation === "PATH" ? "Firing..." : "Path Trav"}</span>
                    </button>

                    <button
                      id="sim-cmd"
                      onClick={() => handleSimulate("CMD")}
                      disabled={isSimulating}
                      className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-indigo-950/50 hover:bg-indigo-900/70 text-indigo-300 border border-indigo-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer"
                      title="Command Injection: 127.0.0.1; whoami"
                    >
                      <Terminal className="w-3 h-3 text-indigo-400 shrink-0" />
                      <span className="truncate">{activeSimulation === "CMD" ? "Firing..." : "Cmd Inject"}</span>
                    </button>

                    <button
                      id="sim-ssrf"
                      onClick={() => handleSimulate("SSRF")}
                      disabled={isSimulating}
                      className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-blue-950/50 hover:bg-blue-900/70 text-blue-300 border border-blue-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer"
                      title="SSRF: http://169.254.169.254/latest/meta-data/"
                    >
                      <Globe className="w-3 h-3 text-blue-400 shrink-0" />
                      <span className="truncate">{activeSimulation === "SSRF" ? "Firing..." : "SSRF Probe"}</span>
                    </button>

                    <button
                      id="sim-nosqli"
                      onClick={() => handleSimulate("NOSQLI")}
                      disabled={isSimulating}
                      className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-fuchsia-950/50 hover:bg-fuchsia-900/70 text-fuchsia-300 border border-fuchsia-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer"
                      title="NoSQL Operator Injection: {'$ne': ''}"
                    >
                      <AlertCircle className="w-3 h-3 text-fuchsia-400 shrink-0" />
                      <span className="truncate">{activeSimulation === "NOSQLI" ? "Firing..." : "NoSQLi Probe"}</span>
                    </button>

                    <button
                      id="sim-mass"
                      onClick={() => handleSimulate("MASS_ASSIGNMENT")}
                      disabled={isSimulating}
                      className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-purple-950/50 hover:bg-purple-900/70 text-purple-300 border border-purple-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer"
                      title="Mass Assignment: {'role': 'admin', 'is_superuser': true}"
                    >
                      <UserCheck className="w-3 h-3 text-purple-400 shrink-0" />
                      <span className="truncate">{activeSimulation === "MASS_ASSIGNMENT" ? "Firing..." : "Mass Assign"}</span>
                    </button>

                    <button
                      id="sim-bola"
                      onClick={() => handleSimulate("BOLA")}
                      disabled={isSimulating}
                      className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-orange-950/50 hover:bg-orange-900/70 text-orange-300 border border-orange-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer"
                      title="BOLA / IDOR Enumeration: /api/v1/vulnerable/orders/{id}"
                    >
                      <KeyRound className="w-3 h-3 text-orange-400 shrink-0" />
                      <span className="truncate">{activeSimulation === "BOLA" ? "Firing..." : "BOLA IDOR"}</span>
                    </button>

                    <button
                      id="sim-soap"
                      onClick={() => handleSimulate("SOAP_XXE")}
                      disabled={isSimulating}
                      className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-cyan-950/50 hover:bg-cyan-900/70 text-cyan-300 border border-cyan-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer"
                      title="SOAP XXE / XML Entity Injection"
                    >
                      <FileCode className="w-3 h-3 text-cyan-400 shrink-0" />
                      <span className="truncate">{activeSimulation === "SOAP_XXE" ? "Firing..." : "SOAP XXE"}</span>
                    </button>

                    <button
                      id="sim-dlp"
                      onClick={() => handleSimulate("DATA_EXPOSURE")}
                      disabled={isSimulating}
                      className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-sky-950/50 hover:bg-sky-900/70 text-sky-300 border border-sky-800/50 transition active:scale-95 disabled:opacity-50 cursor-pointer"
                      title="Excessive Data Exposure (Response DLP Redaction)"
                    >
                      <Info className="w-3 h-3 text-sky-400 shrink-0" />
                      <span className="truncate">{activeSimulation === "DATA_EXPOSURE" ? "Firing..." : "Data DLP"}</span>
                    </button>
                  </div>
                </div>

                {/* Clean Benign Traffic */}
                <button
                  id="sim-benign"
                  onClick={() => handleSimulate("BENIGN")}
                  disabled={isSimulating}
                  className="mt-2 w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-emerald-950/50 hover:bg-emerald-900/70 text-emerald-300 border border-emerald-800/50 text-xs font-mono transition active:scale-95 disabled:opacity-50 cursor-pointer shadow-sm"
                  title="Gửi lưu lượng hợp lệ an toàn (HTTP 200 OK)"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{activeSimulation === "BENIGN" ? "Đang gửi sạch..." : "🍏 Gửi Benign Traffic (200 OK)"}</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 2: ANALYTICS & ATTACK SESSIONS (Full Screen) */}
        {activeView === "analytics" && (
          <div className="h-full flex flex-col gap-3 overflow-y-auto pr-1">
            {/* Top 3 Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 shrink-0">
              <div className="lg:col-span-6">
                <ThreatTimelineChart data={timeline} />
              </div>
              <div className="lg:col-span-3">
                <AttackDistributionChart data={distribution} />
              </div>
              <div className="lg:col-span-3">
                <ProtocolDistributionChart data={protocols} />
              </div>
            </div>

            {/* Inlined Attack Sessions (MITRE Kill Chain Correlation) */}
            <div className="flex-1 min-h-[300px] bg-slate-900/70 border border-slate-800/80 rounded-xl p-4 shadow flex flex-col">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800 text-xs font-mono">
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-rose-400" />
                  <span className="text-sm font-bold text-white">Chuỗi Phiên Tấn Công (MITRE ATT&amp;CK Kill Chain)</span>
                  <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
                    {sessions.length} sessions
                  </span>
                </div>
                <button
                  onClick={() => { setSessionIpFilter(""); setIsAttackSessionsOpen(true); }}
                  className="text-xs text-purple-400 hover:text-purple-300 underline cursor-pointer"
                >
                  Mở chế độ phân tích sâu ▾
                </button>
              </div>

              <div className="flex-1 overflow-y-auto mt-3 space-y-2">
                {sessions.length > 0 ? (
                  sessions.map((s) => (
                    <div
                      key={s.session_id}
                      className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 transition flex items-center justify-between gap-4 text-xs font-mono"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-cyan-400">{s.client_ip}</span>
                          <span className="text-slate-500">•</span>
                          <span className="text-slate-400">ID: {s.session_id.substring(0, 8)}...</span>
                          <span className="text-slate-500">•</span>
                          <span className="text-slate-400">{s.total_events} events</span>
                          <span className="text-slate-500">•</span>
                          <span className="text-slate-400">{s.duration_seconds}s</span>
                        </div>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {s.kill_chain_stages.map((stage, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-0.5 rounded text-[10px] bg-rose-950/60 text-rose-300 border border-rose-800/50"
                            >
                              {stage}
                            </span>
                          ))}
                        </div>
                      </div>

                      <div className="text-right shrink-0">
                        <span className="text-xs font-bold text-amber-400">Risk: {s.max_risk_score.toFixed(1)}</span>
                        <div className="mt-1">
                          <button
                            onClick={() => { setSessionIpFilter(s.client_ip); setIsAttackSessionsOpen(true); }}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] cursor-pointer"
                          >
                            Xem chi tiết
                          </button>
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="py-12 text-center text-slate-500 text-xs font-mono">
                    Chưa có phiên tấn công đa bước nào được ghi nhận. Bắn vài đợt payload từ Quick Simulator để kích hoạt!
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* VIEW 3: CYBER RANGE PHYSICAL TOPOLOGY */}
        {activeView === "topology" && (
          <div className="h-full flex flex-col gap-3 overflow-y-auto pr-1">
            <NetworkTopologyMap topology={topology} />

            {/* Blue Team v3.0 Defense Pipeline Architecture Table */}
            <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-4 shadow text-xs font-mono">
              <h3 className="text-sm font-bold text-white mb-2 flex items-center gap-2">
                <Shield className="w-4 h-4 text-purple-400" />
                Kiến Trúc Phòng Thủ Đa Tầng Blue Team v3.0 (Zero-Day &amp; Evasion Resilient)
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-3">
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <div className="text-purple-400 font-bold mb-1">Tầng 1: Giải Mã &amp; Chuẩn Hóa</div>
                  <p className="text-[11px] text-slate-400">
                    URL Decode đệ quy, Unicode NFKC, strip null bytes, chống Whitespace/Comment obfuscation trước khi quét luật.
                  </p>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <div className="text-cyan-400 font-bold mb-1">Tầng 2: Dual ML Brain (26-D + IF)</div>
                  <p className="text-[11px] text-slate-400">
                    XGBoost 26-D phân loại tấn công đã biết + Isolation Forest phát hiện bất thường Zero-Day phi cấu trúc.
                  </p>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <div className="text-emerald-400 font-bold mb-1">Tầng 3: OWASP API Logic &amp; DLP</div>
                  <p className="text-[11px] text-slate-400">
                    BOLA Leaky Bucket, Mass Assignment schema filter, SSRF private IP check, DLP Regex che giấu dữ liệu nhạy cảm.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* 4. Drawers & Modals */}
      <PayloadEvidenceDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
        onOpenExplainModal={(ev) => setExplainingEvent(ev)}
        onOpenSessionTimeline={(ip) => { setSessionIpFilter(ip); setIsAttackSessionsOpen(true); }}
      />

      <DetectionExplainabilityModal
        event={explainingEvent}
        onClose={() => setExplainingEvent(null)}
      />

      <AttackSessionsModal
        isOpen={isAttackSessionsOpen}
        onClose={() => setIsAttackSessionsOpen(false)}
        initialIpFilter={sessionIpFilter}
      />

      {/* 5. Footer Status Bar (h-7, 28px) */}
      <footer className="w-full h-7 shrink-0 border-t border-slate-900 bg-slate-950/90 px-4 text-[11px] font-mono text-slate-500 flex items-center justify-between whitespace-nowrap">
        <div className="flex items-center gap-3">
          <span>PBL6 — Web API Security Platform</span>
          <span>•</span>
          <span className="text-purple-400">Blue Team v3.0: Rule + XGBoost 26-D + Isolation Forest + OWASP API Guards</span>
          <span>•</span>
          <span className="text-slate-400">Team: vcongggggg &amp; naocavang08</span>
        </div>
        <div>
          <span>WAF Gateway: <span className="text-emerald-400 font-bold">ONLINE (:8000)</span></span>
        </div>
      </footer>
    </div>
  );
}
