"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { Header } from "@/components/Header";
import { MetricCards } from "@/components/MetricCards";
import { ThreatTimelineChart } from "@/components/ThreatTimelineChart";
import { AttackDistributionChart } from "@/components/AttackDistributionChart";
import { LiveEventsTable } from "@/components/LiveEventsTable";
import { PayloadEvidenceDrawer } from "@/components/PayloadEvidenceDrawer";
import {
  fetchDashboardStats,
  fetchDashboardEvents,
  fetchDashboardTimeline,
  fetchDashboardDistribution,
  triggerSimulation,
  resetDemoData,
} from "@/services/api";
import {
  AttackDistributionItem,
  DashboardStats,
  SecurityEventItem,
  TimelinePoint,
} from "@/types/dashboard";
import { CheckCircle2, AlertCircle, Info, X } from "lucide-react";

export default function SOCDashboard() {
  // Data states
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [distribution, setDistribution] = useState<AttackDistributionItem[]>([]);

  // UI & Table filter states
  const [page, setPage] = useState<number>(1);
  const limit = 10;
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [attackTypeFilter, setAttackTypeFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);

  // Operation states
  const [pollingInterval, setPollingInterval] = useState<number>(3); // 3s default
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isResetting, setIsResetting] = useState<boolean>(false);
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
    setTimeout(() => setToast(null), 4500);
  };

  // Main data loader
  const loadData = useCallback(async (showLoadingSpinner: boolean = false) => {
    if (showLoadingSpinner) setIsRefreshing(true);
    try {
      const [statsData, eventsData, timelineData, distData] = await Promise.all([
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
      ]);

      if (statsData) setStats(statsData);
      setEvents(eventsData.items);
      setTotalEvents(eventsData.total);
      setTimeline(timelineData);
      setDistribution(distData);
    } catch (err: any) {
      console.error("Dashboard data load error:", err);
    } finally {
      if (showLoadingSpinner) setIsRefreshing(false);
    }
  }, [page, limit, severityFilter, attackTypeFilter, debouncedQuery]);

  // Initial load & filter change
  useEffect(() => {
    loadData(false);
  }, [loadData]);

  // Smart Polling Effect: Pauses when user has opened PayloadEvidenceDrawer or interval is 0
  const isDrawerOpen = selectedEvent !== null;
  const isDrawerOpenRef = useRef(isDrawerOpen);
  isDrawerOpenRef.current = isDrawerOpen;

  useEffect(() => {
    if (pollingInterval <= 0) return;

    const interval = setInterval(() => {
      // Pause background refresh if user is currently inspecting a payload
      if (!isDrawerOpenRef.current) {
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
      // Immediately refresh data after attack
      await loadData(false);
    } catch (err: any) {
      showToast(`Simulation failed: ${err.message}`, "error");
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

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 flex flex-col font-sans selection:bg-purple-500 selection:text-white">
      {/* Toast Notification Banner */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl border shadow-2xl backdrop-blur-xl transition-all duration-300 animate-in fade-in slide-in-from-bottom-5 bg-slate-900/95 border-slate-700 text-xs font-mono">
          {toast.type === "success" && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
          {toast.type === "error" && <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />}
          {toast.type === "info" && <Info className="w-4 h-4 text-cyan-400 shrink-0" />}
          <span className="text-slate-200">{toast.message}</span>
          <button
            onClick={() => setToast(null)}
            className="ml-2 text-slate-500 hover:text-white transition"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* 1. Header Bar */}
      <Header
        stats={stats}
        pollingInterval={pollingInterval}
        setPollingInterval={setPollingInterval}
        onRefresh={() => loadData(true)}
        onResetDemo={handleResetDemo}
        isRefreshing={isRefreshing}
        isResetting={isResetting}
      />

      {/* 2. Main Dashboard Content Container */}
      <main className="flex-1 max-w-[1720px] w-full mx-auto p-4 sm:p-6 space-y-6">
        {/* 2.1. 5 KPI Cards Row */}
        <MetricCards
          stats={stats}
          onSimulate={handleSimulate}
          isSimulating={isSimulating}
          activeSimulation={activeSimulation}
        />

        {/* 2.2. Charts Row: Timeline (65%) + Distribution (35%) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-8">
            <ThreatTimelineChart data={timeline} />
          </div>
          <div className="lg:col-span-4">
            <AttackDistributionChart data={distribution} />
          </div>
        </div>

        {/* 2.3. Live Security Events Table */}
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
          selectedEventId={selectedEvent?.event_id ?? null}
        />
      </main>

      {/* 3. Payload Evidence Drawer */}
      <PayloadEvidenceDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />

      {/* 4. Footer Status Bar */}
      <footer className="w-full border-t border-slate-900 bg-slate-950/60 px-6 py-2.5 text-[11px] font-mono text-slate-500 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <span>PBL6 — Web API Security Platform</span>
          <span>•</span>
          <span className="text-purple-400">Phase 2: Deterministic Rule Engine</span>
          <span>•</span>
          <span className="text-slate-400">Team: vcongggggg & naocavang08</span>
        </div>
        <div>
          <span>Engine Status: <span className="text-emerald-400 font-bold">ONLINE</span></span>
        </div>
      </footer>
    </div>
  );
}
