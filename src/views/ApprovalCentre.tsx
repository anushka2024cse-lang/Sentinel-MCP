import React, { useState } from 'react';
import {
  CheckSquare,
  ShieldAlert,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Lock,
  ArrowRight
} from 'lucide-react';
import { ApprovalRequest, UserRole } from '../types/index.js';
import { api } from '../services/api.js';

interface ApprovalCentreProps {
  approvals: ApprovalRequest[];
  currentRole: UserRole;
  currentIdentityId: string;
  onRefresh: () => void;
}

export const ApprovalCentre: React.FC<ApprovalCentreProps> = ({
  approvals,
  currentRole,
  currentIdentityId,
  onRefresh
}) => {
  const [decidingId, setDecidingId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'pending' | 'resolved'>('pending');

  const canApprove = currentRole === 'Administrator' || currentRole === 'Approver';

  const pendingList = approvals.filter(a => a.status === 'PENDING');
  const resolvedList = approvals.filter(a => a.status !== 'PENDING');

  const handleDecision = async (id: string, decision: 'APPROVED' | 'DENIED') => {
    if (!canApprove) {
      alert('Access denied: sign in with a server-configured Administrator or Approver credential.');
      return;
    }
    const ticket = approvals.find(approval => approval.id === id);
    if (ticket?.requesterId === currentIdentityId) {
      alert('A requester cannot decide their own approval.');
      return;
    }
    const confirmation = decision === 'APPROVED'
      ? 'This will approve and execute the exact stored operation after server-side revalidation. Continue?'
      : 'Reject this operation? It will not be executed.';
    if (!window.confirm(confirmation)) return;

    setDecidingId(id);
    try {
      await api.decideApproval(id, decision);
    } catch (err: any) {
      alert(`Approval error: ${err.message}`);
    } finally {
      setDecidingId(null);
      onRefresh();
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <CheckSquare className="w-5 h-5 text-amber-400" />
            <span>Human Approval Centre</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Approval dispatches the original operation only after server-side revalidation. The current adapter is simulated.
          </p>
        </div>

        {/* Tab switch */}
        <div className="flex items-center gap-1 p-1 bg-[#0F172A] border border-slate-800 rounded-lg text-xs font-medium">
          <button
            onClick={() => setActiveTab('pending')}
            className={`px-3 py-1.5 rounded-md cursor-pointer transition-colors ${
              activeTab === 'pending'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Pending Tickets ({pendingList.length})
          </button>
          <button
            onClick={() => setActiveTab('resolved')}
            className={`px-3 py-1.5 rounded-md cursor-pointer transition-colors ${
              activeTab === 'resolved'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Resolved History ({resolvedList.length})
          </button>
        </div>
      </div>

      {/* Role permission info */}
      <div className="p-3.5 rounded-lg bg-[#0F172A] border border-slate-800 text-xs text-slate-400 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Lock className="w-4 h-4 text-cyan-400" />
          <span>
            Current Active Role: <strong className="text-slate-200 font-mono">{currentRole}</strong>
          </span>
        </div>
        {canApprove ? (
          <span className="text-emerald-400 font-mono font-bold text-[11px] flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" /> AUTHORIZED TO DECIDE
          </span>
        ) : (
          <span className="text-amber-400 font-mono font-bold text-[11px] flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5" />             READ-ONLY (APPROVER CREDENTIAL REQUIRED)
          </span>
        )}
      </div>

      {/* Ticket List */}
      <div className="space-y-4">
        {activeTab === 'pending' && (
          <>
            {pendingList.map((ticket) => (
              <div
                key={ticket.id}
                className="p-5 rounded-xl bg-[#0F172A] border border-amber-900/40 space-y-4 shadow-lg shadow-amber-950/10"
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 border-b border-slate-800 pb-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-amber-400 text-sm">{ticket.id}</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 font-bold">
                        AWAITING SIGN-OFF
                      </span>
                      <span className="text-slate-400 font-mono text-xs">
                        Tool: <strong className="text-slate-200">{ticket.toolName}</strong> ({ticket.operation})
                      </span>
                    </div>
                    <p className="text-xs text-slate-300">{ticket.policyReason}</p>
                  </div>

                  <div className="text-right shrink-0">
                    <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1 sm:justify-end">
                      <Clock className="w-3.5 h-3.5" />
                      {Date.parse(ticket.expiresAt) > Date.now()
                        ? `Expires ${new Date(ticket.expiresAt).toLocaleString()}`
                        : 'Expired — refresh to resolve'}
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">
                      Req ID: {ticket.requestId}
                    </span>
                  </div>
                </div>

                {/* Details Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  {/* Parameters preview */}
                  <div className="space-y-1.5">
                    <span className="text-slate-400 font-medium">Sanitized Parameters Preview:</span>
                    <pre className="p-2.5 rounded bg-black/60 border border-slate-800 text-cyan-300 font-mono text-[11px] overflow-x-auto">
                      {JSON.stringify(ticket.parametersRedacted, null, 2)}
                    </pre>
                  </div>

                  {/* Risk Factors */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 font-medium">Risk Factors:</span>
                      <span className="text-amber-400 font-mono font-bold">Score: {ticket.riskScore}/100</span>
                    </div>
                    <div className="space-y-1">
                      {ticket.riskFactors.map((rf, idx) => (
                        <div key={idx} className="p-1.5 rounded bg-slate-900/60 border border-slate-800 text-[11px] text-slate-300 flex items-center gap-1.5">
                          <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
                          <span>{rf}</span>
                        </div>
                      ))}
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 pt-1">
                      <span>Requester:</span> <span className="text-slate-200">{ticket.requesterId} ({ticket.requesterRole})</span>
                    </div>
                  </div>
                </div>

                {/* Decision Actions */}
                <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-500">
                    Signature Bound: {ticket.requestFingerprint}
                  </span>

                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => handleDecision(ticket.id, 'DENIED')}
                      disabled={decidingId === ticket.id || !canApprove || ticket.requesterId === currentIdentityId}
                      className="px-4 py-1.5 rounded-lg bg-red-950/40 text-red-300 border border-red-800 hover:bg-red-900/40 text-xs font-semibold cursor-pointer disabled:opacity-50"
                    >
                      Reject Operation
                    </button>
                    <button
                      onClick={() => handleDecision(ticket.id, 'APPROVED')}
                      disabled={decidingId === ticket.id || !canApprove || ticket.requesterId === currentIdentityId}
                      className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold cursor-pointer shadow-md shadow-emerald-900/30 disabled:opacity-50"
                    >
                      Approve & Execute
                    </button>
                  </div>
                </div>
              </div>
            ))}

            {pendingList.length === 0 && (
              <div className="p-10 rounded-xl bg-[#0F172A] border border-slate-800 text-center space-y-2 text-slate-400">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                <h3 className="text-sm font-bold text-slate-200">Zero Pending Approval Requests</h3>
                <p className="text-xs text-slate-400">All high-risk requests are currently resolved or none are pending.</p>
              </div>
            )}
          </>
        )}

        {activeTab === 'resolved' && (
          <div className="divide-y divide-slate-800/60 bg-[#0F172A] border border-slate-800 rounded-xl p-5">
            {resolvedList.map((ticket) => (
              <div key={ticket.id} className="py-3 flex items-start justify-between gap-4 text-xs font-mono">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-200">{ticket.id}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                      ticket.status === 'APPROVED' ? 'bg-emerald-950 text-emerald-400' : 'bg-red-950 text-red-400'
                    }`}>
                      {ticket.status}
                    </span>
                    {ticket.executionStatus && (
                      <span className="text-slate-400">Execution: {ticket.executionStatus}</span>
                    )}
                    <span className="text-slate-400">Tool: {ticket.toolName}</span>
                  </div>
                  <p className="text-slate-400 text-[11px]">Decided by {ticket.approverId || 'Approver'} · Reason: {ticket.approverReason || 'Policy verification'}</p>
                  {ticket.executionOutcome && (
                    <p className="text-slate-300 text-[11px]">{ticket.executionOutcome}</p>
                  )}
                </div>
                <span className="text-slate-500 text-[11px] shrink-0">
                  {ticket.decidedAt ? new Date(ticket.decidedAt).toLocaleString() : 'N/A'}
                </span>
              </div>
            ))}
            {resolvedList.length === 0 && (
              <p className="text-xs text-slate-500 text-center py-4">No resolved approval history yet.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
