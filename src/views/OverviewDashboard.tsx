import React from 'react';
import {
  Server,
  Wrench,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lock,
  Crosshair,
  CheckCircle2,
  Clock,
  ArrowRight,
  TrendingUp,
  Activity
} from 'lucide-react';
import { SystemStats, SecurityEvent, SecurityTestRun } from '../types/index.js';
import { NavPage } from '../components/Sidebar.js';

interface OverviewDashboardProps {
  stats: SystemStats | null;
  recentEvents: SecurityEvent[];
  recentTestRuns: SecurityTestRun[];
  onNavigate: (page: NavPage) => void;
  onOpenDemo: () => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  stats,
  recentEvents,
  recentTestRuns,
  onNavigate,
  onOpenDemo
}) => {
  if (!stats) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400">
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <span>Loading system telemetry...</span>
        </div>
      </div>
    );
  }

  const statCards = [
    {
      label: 'Registered MCP Servers',
      value: stats.totalServers,
      subtext: `${stats.approvedServers} Approved · ${stats.unapprovedServers} Untrusted`,
      icon: Server,
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10 border-blue-500/20'
    },
    {
      label: 'Protected Tools',
      value: stats.totalTools,
      subtext: 'Cryptographically fingerprinted',
      icon: Wrench,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/10 border-cyan-500/20'
    },
    {
      label: 'Total Tool Requests',
      value: stats.totalRequests,
      subtext: `${stats.allowedRequests} Allowed · ${stats.deniedRequests} Denied`,
      icon: Activity,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10 border-emerald-500/20'
    },
    {
      label: 'Security Control Pass Rate',
      value: `${stats.testPassRate}%`,
      subtext: `${stats.passedTests} Passed · ${stats.failedTests} Failed · ${stats.inconclusiveTests} Inconclusive`,
      icon: Crosshair,
      color: stats.testPassRate >= 90 ? 'text-emerald-400' : 'text-amber-400',
      bgColor: 'bg-purple-500/10 border-purple-500/20'
    },
    {
      label: 'Pending Human Approvals',
      value: stats.pendingApprovals,
      subtext: stats.pendingApprovals > 0 ? 'Action required in Approval Centre' : 'Zero tickets waiting',
      icon: Lock,
      color: stats.pendingApprovals > 0 ? 'text-amber-400' : 'text-slate-400',
      bgColor: stats.pendingApprovals > 0 ? 'bg-amber-500/10 border-amber-500/30' : 'bg-slate-800/40 border-slate-700/50',
      action: () => onNavigate('approvals')
    },
    {
      label: 'Active Security Incidents',
      value: stats.activeIncidentsCount,
      subtext: `${stats.sensitiveFindingsCount} DLP detections logged`,
      icon: AlertTriangle,
      color: stats.activeIncidentsCount > 0 ? 'text-red-400' : 'text-emerald-400',
      bgColor: stats.activeIncidentsCount > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-slate-800/40 border-slate-700/50',
      action: () => onNavigate('incidents')
    }
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner: Mission & Section 33 CTA */}
      <div className="p-6 rounded-xl bg-gradient-to-r from-[#0F172A] via-[#131D33] to-[#0A101D] border border-blue-900/40 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[10px] font-mono uppercase tracking-widest px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
              OPERATIONAL SOC STATUS: ENFORCING
            </span>
            <span className="text-xs text-slate-400">· Default-Deny Active</span>
          </div>
          <h1 className="text-xl font-bold text-slate-100">
            Enterprise MCP Security Gateway &amp; Validation Platform
          </h1>
          <p className="text-xs text-slate-400 max-w-2xl mt-1 leading-relaxed">
            Intercepts and validates every AI assistant tool invocation, enforces least-privilege RBAC policies, blocks sensitive data exfiltration, redacts credentials, and verifies actual security outcomes through the automated testing lab.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={onOpenDemo}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-900/40 flex items-center gap-2 cursor-pointer transition-all"
          >
            <span>Run Section 33 Demo</span>
            <ArrowRight className="w-4 h-4" />
          </button>
          <button
            onClick={() => onNavigate('testing-lab')}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-2 cursor-pointer transition-all"
          >
            <Crosshair className="w-4 h-4 text-cyan-400" />
            <span>Open Testing Lab</span>
          </button>
        </div>
      </div>

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {statCards.map((c, idx) => {
          const Icon = c.icon;
          return (
            <div
              key={idx}
              onClick={c.action}
              className={`p-4 rounded-xl border ${c.bgColor} transition-all ${
                c.action ? 'cursor-pointer hover:border-slate-500' : ''
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">{c.label}</span>
                <Icon className={`w-4 h-4 ${c.color}`} />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold tracking-tight text-slate-100 font-mono">
                  {c.value}
                </span>
              </div>
              <p className="mt-1 text-[11px] text-slate-400">{c.subtext}</p>
            </div>
          );
        })}
      </div>

      {/* Middle Section: Request Breakdown & Security Posture Bar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Gateway Enforcement Metrics */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div>
              <h2 className="text-sm font-bold text-slate-100">Gateway Traffic &amp; Decision Breakdown</h2>
              <p className="text-xs text-slate-400">Deterministic policy resolution across all simulated AI clients</p>
            </div>
            <button
              onClick={() => onNavigate('monitor')}
              className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center gap-1 cursor-pointer"
            >
              <span>Live Monitor</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-800/30">
              <span className="text-xs text-emerald-400 font-medium">Permitted (ALLOW)</span>
              <div className="text-xl font-bold text-slate-100 font-mono mt-1">{stats.allowedRequests}</div>
              <span className="text-[10px] text-slate-400">Passed all security gates</span>
            </div>
            <div className="p-3.5 rounded-lg bg-red-950/20 border border-red-800/30">
              <span className="text-xs text-red-400 font-medium">Blocked (DENY)</span>
              <div className="text-xl font-bold text-slate-100 font-mono mt-1">{stats.deniedRequests}</div>
              <span className="text-[10px] text-slate-400">Halted before tool dispatch</span>
            </div>
            <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-800/30">
              <span className="text-xs text-amber-400 font-medium">Pending Approvals</span>
              <div className="text-xl font-bold text-slate-100 font-mono mt-1">{stats.pendingApprovals}</div>
              <span className="text-[10px] text-slate-400">Suspended in approval gate</span>
            </div>
          </div>

          {/* Graphical Ratio Bar */}
          <div className="space-y-1.5 pt-2">
            <div className="flex justify-between text-[11px] text-slate-400 font-mono">
              <span>Traffic Distribution</span>
              <span>
                {stats.totalRequests > 0
                  ? `${Math.round((stats.allowedRequests / stats.totalRequests) * 100)}% Allowed · ${Math.round(
                      (stats.deniedRequests / stats.totalRequests) * 100
                    )}% Denied`
                  : 'Awaiting traffic'}
              </span>
            </div>
            <div className="w-full h-2.5 rounded-full bg-slate-800 overflow-hidden flex">
              <div
                className="bg-emerald-500 transition-all duration-500"
                style={{
                  width: `${stats.totalRequests > 0 ? (stats.allowedRequests / stats.totalRequests) * 100 : 50}%`
                }}
              />
              <div
                className="bg-red-500 transition-all duration-500"
                style={{
                  width: `${stats.totalRequests > 0 ? (stats.deniedRequests / stats.totalRequests) * 100 : 50}%`
                }}
              />
            </div>
          </div>
        </div>

        {/* Verification Engine Summary */}
        <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <h2 className="text-sm font-bold text-slate-100">Security Testing Lab</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                12 SCENARIOS
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Validates that controls actually prevent defined attacks instead of simply displaying simulated messages.
            </p>

            <div className="mt-4 space-y-2.5 text-xs">
              <div className="flex justify-between items-center py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400">Total Scenarios Executed:</span>
                <span className="font-mono text-slate-200 font-bold">{stats.totalTestsRun}</span>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-slate-800/60">
                <span className="text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Verified PASS:
                </span>
                <span className="font-mono text-emerald-300 font-bold">{stats.passedTests}</span>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-slate-800/60">
                <span className="text-red-400 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" /> Defeated / FAIL:
                </span>
                <span className="font-mono text-red-300 font-bold">{stats.failedTests}</span>
              </div>
              <div className="flex justify-between items-center py-1.5">
                <span className="text-slate-400">Inconclusive Evidence:</span>
                <span className="font-mono text-slate-400 font-bold">{stats.inconclusiveTests}</span>
              </div>
            </div>
          </div>

          <button
            onClick={() => onNavigate('testing-lab')}
            className="w-full mt-4 py-2 px-3 text-xs font-semibold rounded-lg bg-blue-600/20 text-blue-300 border border-blue-500/30 hover:bg-blue-600/30 transition-all flex items-center justify-center gap-2 cursor-pointer"
          >
            <span>Launch Red vs Blue Lab</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Recent Security Events & Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Audit Events */}
        <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h2 className="text-sm font-bold text-slate-100">Recent Security Decisions &amp; Audit Events</h2>
            <button
              onClick={() => onNavigate('audit')}
              className="text-xs text-blue-400 hover:text-blue-300 font-medium cursor-pointer"
            >
              View Full Audit Log
            </button>
          </div>

          <div className="mt-3 divide-y divide-slate-800/60">
            {recentEvents.slice(0, 5).map((evt) => (
              <div key={evt.id} className="py-2.5 flex items-start justify-between gap-3 text-xs">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-slate-300">{evt.eventType}</span>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        evt.decision === 'ALLOW' || evt.decision === 'SANITIZE_AND_ALLOW'
                          ? 'bg-emerald-950 text-emerald-400'
                          : evt.decision === 'REQUIRE_APPROVAL'
                          ? 'bg-amber-950 text-amber-400'
                          : 'bg-red-950 text-red-400'
                      }`}
                    >
                      {evt.decision}
                    </span>
                  </div>
                  <p className="text-slate-400 line-clamp-1 text-[11px]">{evt.evidenceSummary}</p>
                </div>
                <div className="text-right shrink-0">
                  <span className="text-[10px] font-mono text-slate-500">
                    {new Date(evt.createdAt).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            ))}
            {recentEvents.length === 0 && (
              <p className="py-4 text-xs text-slate-500 text-center">No recent security events logged.</p>
            )}
          </div>
        </div>

        {/* Latest Attack Simulation Runs */}
        <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h2 className="text-sm font-bold text-slate-100">Latest Security Test Runs</h2>
            <button
              onClick={() => onNavigate('reports')}
              className="text-xs text-blue-400 hover:text-blue-300 font-medium cursor-pointer"
            >
              View Assessment Reports
            </button>
          </div>

          <div className="mt-3 divide-y divide-slate-800/60">
            {recentTestRuns.slice(0, 5).map((run) => (
              <div key={run.id} className="py-2.5 flex items-start justify-between gap-3 text-xs">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-blue-400">{run.testId}</span>
                    <span
                      className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                        run.status === 'PASS'
                          ? 'bg-emerald-950 text-emerald-400'
                          : run.status === 'FAIL'
                          ? 'bg-red-950 text-red-400'
                          : 'bg-amber-950 text-amber-400'
                      }`}
                    >
                      {run.status}
                    </span>
                  </div>
                  <p className="text-slate-400 line-clamp-1 text-[11px]">{run.actualResult}</p>
                </div>
                <div className="text-right shrink-0">
                  <span className="text-[10px] font-mono text-slate-500">{run.durationMs}ms</span>
                </div>
              </div>
            ))}
            {recentTestRuns.length === 0 && (
              <div className="py-6 text-center text-xs text-slate-500">
                <p>No test scenarios executed yet.</p>
                <button
                  onClick={() => onNavigate('testing-lab')}
                  className="mt-2 text-blue-400 hover:underline cursor-pointer"
                >
                  Run test suite in Testing Lab →
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
