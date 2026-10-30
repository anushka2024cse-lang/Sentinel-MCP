import React, { useState } from 'react';
import {
  Crosshair,
  Shield,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Flame,
  Lock,
  Layers,
  ArrowRight,
  Clock,
  FileText
} from 'lucide-react';
import {
  SecurityTestScenario,
  SecurityTestRun,
  UserRole
} from '../types/index.js';
import { api } from '../services/api.js';

interface SecurityTestingLabProps {
  scenarios: SecurityTestScenario[];
  testRuns: SecurityTestRun[];
  currentRole: UserRole;
  onRefresh: () => void;
  onViewReports: () => void;
}

export const SecurityTestingLab: React.FC<SecurityTestingLabProps> = ({
  scenarios,
  testRuns,
  currentRole,
  onRefresh,
  onViewReports
}) => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(scenarios[0]?.id || 'scen-t01');
  const [isRunningSingle, setIsRunningSingle] = useState(false);
  const [isRunningAll, setIsRunningAll] = useState(false);
  const [latestRun, setLatestRun] = useState<SecurityTestRun | null>(testRuns[0] || null);

  const selectedScenario = scenarios.find(s => s.id === selectedScenarioId) || scenarios[0];

  const handleRunSingle = async () => {
    if (!selectedScenario) return;
    setIsRunningSingle(true);
    try {
      const run = await api.runTest(selectedScenario.id);
      setLatestRun(run);
      onRefresh();
    } catch (e: any) {
      alert(`Test run failed: ${e.message}`);
    } finally {
      setIsRunningSingle(false);
    }
  };

  const handleRunAll = async () => {
    setIsRunningAll(true);
    try {
      const runs = await api.runAllTests();
      if (runs.length > 0) setLatestRun(runs[runs.length - 1]);
      onRefresh();
    } catch (e: any) {
      alert(`Batch regression run failed: ${e.message}`);
    } finally {
      setIsRunningAll(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Crosshair className="w-5 h-5 text-red-400" />
            <span>Security Testing Lab &amp; Verification Engine</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Red Team vs Blue Team validation harness. Executes repeatable attack scenarios (T01–T12) through the real runtime gateway to verify actual security outcomes.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRunAll}
            disabled={isRunningAll || isRunningSingle}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white flex items-center gap-2 shadow-lg shadow-red-950/40 cursor-pointer disabled:opacity-50"
          >
            {isRunningAll ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Running 12 Scenarios...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Run Full Regression Suite</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Scenario Selector Ribbon */}
      <div className="p-3 bg-[#0F172A] border border-slate-800 rounded-xl overflow-x-auto scrollbar-thin scrollbar-thumb-slate-800">
        <div className="flex items-center gap-2 min-w-max">
          {scenarios.map((scen) => {
            const isSelected = selectedScenario?.id === scen.id;
            const recentRunForThis = testRuns.find(r => r.testId === scen.testId);

            return (
              <button
                key={scen.id}
                onClick={() => {
                  setSelectedScenarioId(scen.id);
                  if (recentRunForThis) setLatestRun(recentRunForThis);
                }}
                className={`px-3 py-2 rounded-lg text-xs font-mono font-medium transition-all flex items-center gap-2 cursor-pointer ${
                  isSelected
                    ? 'bg-blue-600 text-white shadow-md'
                    : 'bg-[#111C30] text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                <span className="font-bold">{scen.testId}</span>
                <span className="text-[11px] font-sans truncate max-w-[130px]">{scen.name}</span>
                {recentRunForThis && (
                  <span
                    className={`text-[9px] px-1 py-0.2 rounded font-bold ${
                      recentRunForThis.status === 'PASS'
                        ? 'bg-emerald-950 text-emerald-300'
                        : recentRunForThis.status === 'FAIL'
                        ? 'bg-red-950 text-red-300'
                        : 'bg-amber-950 text-amber-300'
                    }`}
                  >
                    {recentRunForThis.status}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Red Team vs Blue Team Dual Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Red Team Panel */}
        <div className="p-5 rounded-xl bg-[#0F172A] border border-red-900/40 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
              <h2 className="text-sm font-bold text-red-400 font-mono tracking-wider">
                RED TEAM: CONTROLLED ATTACK SIMULATION
              </h2>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 font-bold">
              SCENARIO {selectedScenario?.testId}
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <span className="text-slate-400 font-medium">Scenario Title:</span>
              <h3 className="text-sm font-bold text-slate-100 mt-0.5">{selectedScenario?.name}</h3>
            </div>

            <div>
              <span className="text-slate-400 font-medium">Attack Category:</span>
              <div className="mt-0.5 text-cyan-400 font-mono font-bold">{selectedScenario?.category}</div>
            </div>

            <div>
              <span className="text-slate-400 font-medium">Preconditions:</span>
              <p className="text-slate-300 leading-relaxed bg-black/40 p-2.5 rounded border border-slate-800/80 mt-1">
                {selectedScenario?.preconditions}
              </p>
            </div>

            <div>
              <span className="text-slate-400 font-medium">Synthetic Attack Input (Submitted to Gateway):</span>
              <pre className="p-3 rounded-lg bg-black/60 border border-slate-800 font-mono text-[11px] text-red-300 overflow-x-auto mt-1 max-h-48 scrollbar-thin scrollbar-thumb-slate-800">
                {JSON.stringify(selectedScenario?.syntheticInput, null, 2)}
              </pre>
            </div>

            <div>
              <span className="text-slate-400 font-medium">Expected Security Decision:</span>
              <div className="mt-1 font-mono font-bold text-amber-400">{selectedScenario?.expectedDecision}</div>
            </div>

            <button
              onClick={handleRunSingle}
              disabled={isRunningSingle || isRunningAll}
              className="w-full mt-2 py-2.5 px-4 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold flex items-center justify-center gap-2 cursor-pointer shadow-lg shadow-red-950/40 disabled:opacity-50"
            >
              {isRunningSingle ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Executing Attack Scenario...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Execute {selectedScenario?.testId} Scenario</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Blue Team Panel */}
        <div className="p-5 rounded-xl bg-[#0F172A] border border-blue-900/40 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-pulse" />
              <h2 className="text-sm font-bold text-blue-400 font-mono tracking-wider">
                BLUE TEAM: DEFENSIVE RESPONSE &amp; VERIFICATION
              </h2>
            </div>
            {latestRun && (
              <span
                className={`text-[10px] font-mono px-2.5 py-1 rounded font-bold ${
                  latestRun.status === 'PASS'
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : latestRun.status === 'FAIL'
                    ? 'bg-red-950 text-red-400 border border-red-800'
                    : 'bg-amber-950 text-amber-400 border border-amber-800'
                }`}
              >
                VERDICT: {latestRun.status} ({latestRun.durationMs}ms)
              </span>
            )}
          </div>

          {latestRun ? (
            <div className="space-y-4 text-xs animate-in fade-in duration-200">
              {/* Verdict Banner */}
              <div
                className={`p-3 rounded-lg border flex items-center justify-between font-mono ${
                  latestRun.status === 'PASS'
                    ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-300'
                    : latestRun.status === 'FAIL'
                    ? 'bg-red-950/20 border-red-800/40 text-red-300'
                    : 'bg-amber-950/20 border-amber-800/40 text-amber-300'
                }`}
              >
                <div className="flex items-center gap-2">
                  {latestRun.status === 'PASS' ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  ) : latestRun.status === 'FAIL' ? (
                    <XCircle className="w-5 h-5 text-red-400" />
                  ) : (
                    <AlertTriangle className="w-5 h-5 text-amber-400" />
                  )}
                  <div>
                    <div className="font-bold text-xs">
                      {latestRun.status === 'PASS'
                        ? 'SECURITY CONTROL VERIFIED EFFECTIVE'
                        : latestRun.status === 'FAIL'
                        ? 'SECURITY VIOLATION DETECTED'
                        : 'INCONCLUSIVE EVIDENCE'}
                    </div>
                    <span className="text-[11px] text-slate-400 font-sans">{latestRun.actualResult}</span>
                  </div>
                </div>
              </div>

              {/* Verified Checkpoints Table */}
              <div className="space-y-2">
                <span className="text-slate-300 font-bold">Verification Engine Evidence Checkpoints:</span>
                <div className="space-y-1.5 font-mono text-[11px]">
                  {latestRun.verificationEvidence?.map((chk, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded bg-black/40 border border-slate-800 flex items-start justify-between gap-3"
                    >
                      <div className="space-y-0.5">
                        <span className="text-slate-300 font-semibold">{chk.checkpoint}</span>
                        <div className="text-[10px] text-slate-500">Expected: {chk.expected}</div>
                        <div className="text-[10px] text-cyan-300">Observed: {chk.observed}</div>
                      </div>

                      <span
                        className={`text-[9px] px-2 py-0.5 rounded font-bold uppercase shrink-0 ${
                          chk.verified
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : 'bg-red-950 text-red-400 border border-red-800'
                        }`}
                      >
                        {chk.verified ? 'VERIFIED' : 'FAILED'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Physical Evidence Indicators */}
              <div className="grid grid-cols-3 gap-2.5 text-center font-mono text-[11px]">
                <div className="p-2 rounded bg-black/40 border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">PROTECTED TOOL</span>
                  <span className={`font-bold ${latestRun.toolExecuted ? 'text-emerald-400' : 'text-red-400'}`}>
                    {latestRun.toolExecuted ? 'EXECUTED' : 'HALTED'}
                  </span>
                </div>
                <div className="p-2 rounded bg-black/40 border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">DATA EXFILTRATED</span>
                  <span className={`font-bold ${latestRun.dataExfiltrated ? 'text-red-400' : 'text-emerald-400'}`}>
                    {latestRun.dataExfiltrated ? 'YES (LEAK)' : 'NO (0 BYTES)'}
                  </span>
                </div>
                <div className="p-2 rounded bg-black/40 border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">AUDIT RECORDED</span>
                  <span className={`font-bold ${latestRun.auditEventCreated ? 'text-cyan-400' : 'text-red-400'}`}>
                    {latestRun.auditEventCreated ? 'VERIFIED' : 'MISSING'}
                  </span>
                </div>
              </div>

              {latestRun.failureReason && (
                <div className="p-2.5 rounded bg-red-950/30 border border-red-800 text-xs text-red-300">
                  <strong>Failure Explanation:</strong> {latestRun.failureReason}
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 text-center text-xs text-slate-500 space-y-2">
              <Crosshair className="w-8 h-8 text-blue-400 mx-auto opacity-40" />
              <p>Click &ldquo;Execute Scenario&rdquo; to dispatch the attack and observe Blue Team response.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
