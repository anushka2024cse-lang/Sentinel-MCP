import React, { useState } from 'react';
import {
  FileBarChart2,
  Download,
  Printer,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  ShieldCheck,
  FileText
} from 'lucide-react';
import { SecurityTestRun, SecurityTestScenario } from '../types/index.js';

interface TestResultsReportsProps {
  testRuns: SecurityTestRun[];
  scenarios: SecurityTestScenario[];
}

export const TestResultsReports: React.FC<TestResultsReportsProps> = ({
  testRuns,
  scenarios
}) => {
  const [selectedRunId, setSelectedRunId] = useState<string>(testRuns[0]?.id || '');

  const selectedRun = testRuns.find(r => r.id === selectedRunId) || testRuns[0];
  const matchedScenario = selectedRun ? scenarios.find(s => s.testId === selectedRun.testId) : null;

  const exportReportJson = () => {
    if (!selectedRun) return;
    const reportData = {
      reportId: `REP-${selectedRun.testRunId}`,
      scenarioId: selectedRun.testId,
      scenarioName: matchedScenario?.name,
      executionTimestamp: selectedRun.completedAt,
      verdict: selectedRun.status,
      durationMs: selectedRun.durationMs,
      expectedResult: selectedRun.expectedResult,
      actualResult: selectedRun.actualResult,
      gatewayDecision: selectedRun.actualDecision,
      toolExecuted: selectedRun.toolExecuted,
      dataExfiltrated: selectedRun.dataExfiltrated,
      checkpoints: selectedRun.verificationEvidence,
      failureReason: selectedRun.failureReason,
      disclaimer: 'This assessment report reflects automated verification in a sandboxed synthetic MCP evaluation environment.'
    };

    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(reportData, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `sentinel-assessment-report-${selectedRun.testId}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileBarChart2 className="w-5 h-5 text-emerald-400" />
            <span>Test Results &amp; Security Assessment Reports</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Auditable security reports based on empirical verification runs with checkpoint-level evidence.
          </p>
        </div>

        {selectedRun && (
          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 cursor-pointer shadow-sm"
            >
              <Printer className="w-3.5 h-3.5 text-slate-400" />
              <span>Print Report</span>
            </button>
            <button
              onClick={exportReportJson}
              className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-1.5 cursor-pointer shadow-md shadow-blue-900/30"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Report JSON</span>
            </button>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Test Run Selector */}
        <div className="lg:col-span-4 p-4 rounded-xl bg-[#0F172A] border border-slate-800 space-y-3">
          <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
            Verification Run History ({testRuns.length})
          </h2>

          <div className="space-y-2 max-h-[600px] overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800">
            {testRuns.map((run) => (
              <div
                key={run.id}
                onClick={() => setSelectedRunId(run.id)}
                className={`p-3 rounded-lg border text-xs font-mono cursor-pointer transition-all ${
                  selectedRun?.id === run.id
                    ? 'bg-blue-950/40 border-blue-500 text-slate-100 shadow-md'
                    : 'bg-[#111C30] border-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-blue-400">{run.testId}</span>
                  <span
                    className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${
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
                <div className="text-[11px] text-slate-300 mt-1 truncate">
                  Run ID: {run.testRunId}
                </div>
                <div className="flex justify-between text-[10px] text-slate-500 mt-1">
                  <span>{new Date(run.completedAt).toLocaleTimeString()}</span>
                  <span>{run.durationMs}ms</span>
                </div>
              </div>
            ))}

            {testRuns.length === 0 && (
              <p className="py-6 text-center text-xs text-slate-500">No test runs executed yet.</p>
            )}
          </div>
        </div>

        {/* Right: Formal Assessment Report Document */}
        <div className="lg:col-span-8">
          {selectedRun ? (
            <div className="p-8 rounded-xl bg-[#0F172A] border border-slate-800 space-y-6 print:border-none print:p-0">
              {/* Document Header */}
              <div className="border-b border-slate-800 pb-5 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-slate-100">
                      SECURITY ASSESSMENT REPORT
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
                      ID: REP-{selectedRun.testRunId}
                    </span>
                  </div>

                  <span
                    className={`text-xs font-mono font-bold px-3 py-1 rounded ${
                      selectedRun.status === 'PASS'
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : selectedRun.status === 'FAIL'
                        ? 'bg-red-950 text-red-400 border border-red-800'
                        : 'bg-amber-950 text-amber-400 border border-amber-800'
                    }`}
                  >
                    STATUS: {selectedRun.status}
                  </span>
                </div>

                <h2 className="text-lg font-bold text-slate-100">
                  Scenario {selectedRun.testId}: {matchedScenario?.name || 'MCP Security Test'}
                </h2>
                <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400 pt-1">
                  <span>Timestamp: {new Date(selectedRun.completedAt).toLocaleString()}</span>
                  <span>Execution Duration: {selectedRun.durationMs}ms</span>
                  <span>Category: {matchedScenario?.category}</span>
                </div>
              </div>

              {/* Assessment Section: Preconditions & Expectations */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                <div className="p-3.5 rounded-lg bg-black/40 border border-slate-800 space-y-1">
                  <span className="text-slate-400 uppercase font-bold text-[10px]">Preconditions:</span>
                  <p className="text-slate-200">{matchedScenario?.preconditions || 'Target server active.'}</p>
                </div>
                <div className="p-3.5 rounded-lg bg-black/40 border border-slate-800 space-y-1">
                  <span className="text-slate-400 uppercase font-bold text-[10px]">Expected Result:</span>
                  <p className="text-slate-200">{selectedRun.expectedResult}</p>
                </div>
              </div>

              {/* Actual Outcome Verification */}
              <div className="space-y-2 text-xs">
                <span className="font-bold text-slate-300">Observed Gateway &amp; Tool Behavior:</span>
                <div className="p-3.5 rounded-lg bg-black/60 border border-slate-800 font-mono text-cyan-300">
                  {selectedRun.actualResult}
                </div>
              </div>

              {/* Verified Checkpoints Table */}
              <div className="space-y-2 text-xs">
                <span className="font-bold text-slate-300">Verification Engine Evidence:</span>
                <table className="w-full text-xs font-mono border-collapse border border-slate-800">
                  <thead>
                    <tr className="bg-[#111C30] text-slate-400 border-b border-slate-800 text-left">
                      <th className="p-2.5">Verification Checkpoint</th>
                      <th className="p-2.5">Expected Condition</th>
                      <th className="p-2.5">Observed Condition</th>
                      <th className="p-2.5 text-center">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {selectedRun.verificationEvidence?.map((chk, idx) => (
                      <tr key={idx}>
                        <td className="p-2.5 font-bold text-slate-300">{chk.checkpoint}</td>
                        <td className="p-2.5 text-slate-400">{chk.expected}</td>
                        <td className="p-2.5 text-cyan-300">{chk.observed}</td>
                        <td className="p-2.5 text-center">
                          <span
                            className={`text-[9px] px-2 py-0.5 rounded font-bold ${
                              chk.verified
                                ? 'bg-emerald-950 text-emerald-400'
                                : 'bg-red-950 text-red-400'
                            }`}
                          >
                            {chk.verified ? 'PASS' : 'FAIL'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Remediation or Failure notes */}
              {selectedRun.failureReason && (
                <div className="p-3.5 rounded-lg bg-red-950/20 border border-red-800 text-xs text-red-300 font-mono">
                  <strong>Defect Diagnostic:</strong> {selectedRun.failureReason}
                </div>
              )}

              {/* Governance & Disclaimer Notice per Section 25 */}
              <div className="pt-4 border-t border-slate-800 text-[11px] text-slate-500 font-mono leading-relaxed">
                <strong>Platform Governance Notice (Section 25):</strong> This automated security test report certifies the observed execution outcome for the evaluated scenario in a sandboxed enterprise MCP gateway testbed. It does not certify the entirety of external infrastructure or guarantee absolute security against novel zero-day vectors.
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-xs text-slate-500 rounded-xl bg-[#0F172A] border border-slate-800">
              Select a verification run from history to generate report view.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
