"use client";

import React from "react";
import { Search, Filter, Download, Eye, ShieldAlert, ChevronLeft, ChevronRight } from "lucide-react";
import { SecurityEventItem } from "@/types/dashboard";

interface LiveEventsTableProps {
  events: SecurityEventItem[];
  totalEvents: number;
  page: number;
  limit: number;
  setPage: (p: number) => void;
  severityFilter: string;
  setSeverityFilter: (s: string) => void;
  attackTypeFilter: string;
  setAttackTypeFilter: (t: string) => void;
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  onSelectEvent: (event: SecurityEventItem) => void;
  selectedEventId: string | null;
}

export const LiveEventsTable: React.FC<LiveEventsTableProps> = ({
  events,
  totalEvents,
  page,
  limit,
  setPage,
  severityFilter,
  setSeverityFilter,
  attackTypeFilter,
  setAttackTypeFilter,
  searchQuery,
  setSearchQuery,
  onSelectEvent,
  selectedEventId,
}) => {
  const totalPages = Math.max(1, Math.ceil(totalEvents / limit));

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
        return "bg-rose-950/70 text-rose-300 border-rose-800/80 shadow-[0_0_8px_rgba(244,63,94,0.3)]";
      case "HIGH":
        return "bg-amber-950/70 text-amber-300 border-amber-800/80";
      case "MEDIUM":
        return "bg-yellow-950/70 text-yellow-300 border-yellow-800/80";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  const getAttackTypeBadge = (type: string) => {
    switch (type.toUpperCase()) {
      case "SQL_INJECTION":
      case "SQLI":
        return "text-blue-400 bg-blue-950/50 border-blue-800/50";
      case "XSS":
        return "text-rose-400 bg-rose-950/50 border-rose-800/50";
      case "PATH_TRAVERSAL":
      case "PATH":
        return "text-emerald-400 bg-emerald-950/50 border-emerald-800/50";
      case "COMMAND_INJECTION":
      case "CMD":
        return "text-amber-400 bg-amber-950/50 border-amber-800/50";
      default:
        return "text-purple-400 bg-purple-950/50 border-purple-800/50";
    }
  };

  const exportToJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(events, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `security_events_${new Date().toISOString()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="bg-slate-900/70 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-lg flex flex-col">
      {/* Toolbar: Search, Filters & Export */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-rose-400" />
          <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            Live Events Table
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
              {totalEvents} incidents
            </span>
          </h2>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 text-xs font-mono">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search by IP / Request ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-950/90 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition w-56 text-xs"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1 bg-slate-950/90 border border-slate-800 rounded-lg px-2 py-1">
            <Filter className="w-3 h-3 text-slate-500" />
            <span className="text-slate-400 text-[11px]">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-slate-200 focus:outline-none text-xs cursor-pointer"
            >
              <option value="ALL" className="bg-slate-900">ALL</option>
              <option value="CRITICAL" className="bg-slate-900">CRITICAL</option>
              <option value="HIGH" className="bg-slate-900">HIGH</option>
              <option value="MEDIUM" className="bg-slate-900">MEDIUM</option>
              <option value="LOW" className="bg-slate-900">LOW</option>
            </select>
          </div>

          {/* Attack Type Filter */}
          <div className="flex items-center gap-1 bg-slate-950/90 border border-slate-800 rounded-lg px-2 py-1">
            <span className="text-slate-400 text-[11px]">Type:</span>
            <select
              value={attackTypeFilter}
              onChange={(e) => setAttackTypeFilter(e.target.value)}
              className="bg-transparent text-slate-200 focus:outline-none text-xs cursor-pointer"
            >
              <option value="ALL" className="bg-slate-900">ALL</option>
              <option value="SQL_INJECTION" className="bg-slate-900">SQLi</option>
              <option value="XSS" className="bg-slate-900">XSS</option>
              <option value="PATH_TRAVERSAL" className="bg-slate-900">Path Traversal</option>
              <option value="COMMAND_INJECTION" className="bg-slate-900">Cmd Injection</option>
            </select>
          </div>

          {/* Export JSON Button */}
          <button
            onClick={exportToJson}
            disabled={events.length === 0}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition disabled:opacity-40 cursor-pointer text-xs"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Table Container */}
      <div className="overflow-x-auto mt-2">
        <table className="w-full text-left text-xs font-mono">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase text-[11px]">
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3">Request ID</th>
              <th className="py-2.5 px-3">Attack Type</th>
              <th className="py-2.5 px-3">Severity</th>
              <th className="py-2.5 px-3">Location</th>
              <th className="py-2.5 px-3">Rule ID</th>
              <th className="py-2.5 px-3">Score</th>
              <th className="py-2.5 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {events.length > 0 ? (
              events.map((ev) => {
                const isSelected = selectedEventId === ev.event_id;
                const timeStr = ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : "--:--:--";

                return (
                  <tr
                    key={ev.event_id}
                    className={`hover:bg-slate-800/50 transition cursor-pointer ${
                      isSelected ? "bg-purple-950/30 border-l-2 border-purple-500" : ""
                    }`}
                    onClick={() => onSelectEvent(ev)}
                  >
                    <td className="py-3 px-3 text-slate-300 whitespace-nowrap">{timeStr}</td>
                    <td className="py-3 px-3 text-cyan-400 font-bold whitespace-nowrap">
                      #{ev.request_id.slice(0, 10)}...
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded border text-[11px] font-semibold whitespace-nowrap ${getAttackTypeBadge(ev.attack_type)}`}>
                        {ev.attack_type}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-bold tracking-wide uppercase whitespace-nowrap ${getSeverityBadge(ev.severity)}`}>
                        {ev.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-300 whitespace-nowrap">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px]">
                        {ev.location}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-300 font-bold whitespace-nowrap">{ev.rule_id}</td>
                    <td className="py-3 px-3 text-amber-400 font-bold whitespace-nowrap">{ev.rule_score.toFixed(1)}</td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectEvent(ev);
                        }}
                        className={`inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] border transition ${
                          isSelected
                            ? "bg-purple-600 text-white border-purple-500"
                            : "bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700"
                        }`}
                      >
                        <Eye className="w-3 h-3" />
                        <span>View</span>
                      </button>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={8} className="text-center py-10 text-slate-500 font-mono">
                  <div className="flex flex-col items-center justify-center">
                    <ShieldAlert className="w-8 h-8 text-slate-700 mb-2" />
                    <p className="text-xs">No security events match the current filter.</p>
                    <p className="text-[11px] text-slate-600 mt-1">
                      Click buttons on <span className="text-purple-400 font-semibold">Quick Simulator</span> to fire real attack requests!
                    </p>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-3 mt-2 border-t border-slate-800/80 text-xs font-mono text-slate-400">
          <span>Page {page} of {totalPages}</span>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPage(Math.max(1, page - 1))}
              disabled={page === 1}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage(Math.min(totalPages, page + 1))}
              disabled={page === totalPages}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
