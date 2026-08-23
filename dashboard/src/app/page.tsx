import { Shield, Server, CheckCircle2, Terminal } from "lucide-react";
import { config } from "@/config/env";

export default function Home() {
  return (
    <main className="min-h-screen flex flex-col items-center justify-center p-6 bg-[#09090b] text-slate-100">
      <div className="max-w-2xl w-full bg-slate-900/50 border border-slate-800 rounded-2xl p-8 backdrop-blur-md shadow-2xl">
        <div className="flex items-center gap-4 mb-6 pb-6 border-b border-slate-800">
          <div className="bg-purple-600/20 text-purple-400 p-3 rounded-xl border border-purple-500/30">
            <Shield className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white">
              {config.appName}
            </h1>
            <p className="text-xs text-purple-400 font-mono mt-0.5">
              {config.phase} — Base Infrastructure Initialized
            </p>
          </div>
        </div>

        <div className="space-y-4 mb-8">
          <div className="flex items-start gap-3 p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Frontend Foundation Ready</h3>
              <p className="text-xs text-slate-400 mt-1">
                Next.js App Router, TypeScript, and Tailwind CSS configured cleanly without placeholder metrics.
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3 p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
            <Server className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Backend API Gateway Integration</h3>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                API Base URL: <span className="text-purple-300">{config.apiBaseUrl}</span>
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3 p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
            <Terminal className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Phase Plan Alignment</h3>
              <p className="text-xs text-slate-400 mt-1">
                Security metrics, WAF event feeds, and Attack Lab controls will be implemented in Phase 9.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between text-xs text-slate-500 pt-4 border-t border-slate-800/60">
          <span>PBL6 — An Toàn Thông Tin</span>
          <span>Status: Foundation Active</span>
        </div>
      </div>
    </main>
  );
}
