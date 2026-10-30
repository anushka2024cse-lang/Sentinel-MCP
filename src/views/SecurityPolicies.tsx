import React, { useState } from 'react';
import {
  Shield,
  Plus,
  ToggleLeft,
  ToggleRight,
  AlertTriangle,
  CheckCircle2,
  Lock,
  ListOrdered
} from 'lucide-react';
import { SecurityPolicy, UserRole, MCPServer, MCPTool } from '../types/index.js';
import { api } from '../services/api.js';

interface SecurityPoliciesProps {
  policies: SecurityPolicy[];
  servers: MCPServer[];
  tools: MCPTool[];
  currentRole: UserRole;
  onRefresh: () => void;
}

export const SecurityPolicies: React.FC<SecurityPoliciesProps> = ({
  policies,
  servers,
  tools,
  currentRole,
  onRefresh
}) => {
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState(50);
  const [applicableToolName, setApplicableToolName] = useState('');
  const [approvalRequired, setApprovalRequired] = useState(false);
  const [remediationMessage, setRemediationMessage] = useState('');
  const [destinationsInput, setDestinationsInput] = useState('');

  const isAdmin = currentRole === 'Administrator';

  const handleTogglePolicy = async (id: string) => {
    try {
      await api.togglePolicy(id);
      onRefresh();
    } catch (e: any) {
      alert(`Error toggling policy: ${e.message}`);
    }
  };

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    try {
      const allowedDestinations = destinationsInput
        ? destinationsInput.split(',').map(s => s.trim()).filter(Boolean)
        : [];

      await api.createPolicy({
        name,
        description,
        priority,
        applicableToolName: applicableToolName || undefined,
        approvalRequired,
        remediationMessage,
        allowedDestinations,
        allowedRoles: ['Administrator']
      });

      setIsCreateOpen(false);
      setName('');
      setDescription('');
      onRefresh();
    } catch (e: any) {
      alert(`Error creating policy: ${e.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-400" />
            <span>Central Policy Engine &amp; Precedence Rules</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic rule precedence (Priority 10 → 100). Mandatory Deny rules strictly override lower-priority allowances.
          </p>
        </div>

        {isAdmin && (
          <button
            onClick={() => setIsCreateOpen(true)}
            className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-1.5 cursor-pointer shadow-md shadow-blue-900/30 shrink-0"
          >
            <Plus className="w-4 h-4" />
            <span>Add Custom Policy</span>
          </button>
        )}
      </div>

      {/* Workflow F Regression Hint */}
      <div className="p-3.5 rounded-lg bg-blue-950/20 border border-blue-900/40 text-xs text-slate-300 flex items-start gap-2.5">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-100">Workflow F Regression Testing Note:</span> You can toggle any policy (such as <span className="font-mono text-cyan-300">pol-002: Deny Unauthorised Financial Exports</span>) to Disabled. When you run the Security Testing Lab suite, the verification engine will immediately detect that the security control is breached and flag a <span className="font-mono text-red-400 font-bold">FAIL</span>!
        </div>
      </div>

      {/* Policies List */}
      <div className="space-y-4">
        {policies.map((policy) => {
          return (
            <div
              key={policy.id}
              className={`p-5 rounded-xl border transition-all ${
                policy.enabled
                  ? 'bg-[#0F172A] border-slate-800'
                  : 'bg-slate-900/40 border-slate-800/50 opacity-60'
              }`}
            >
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                <div className="space-y-1.5 flex-1">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="font-mono text-xs font-bold text-blue-400">
                      [{policy.id}]
                    </span>
                    <h2 className="text-sm font-bold text-slate-100">{policy.name}</h2>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      Priority: {policy.priority}
                    </span>
                    {policy.approvalRequired && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 flex items-center gap-1">
                        <Lock className="w-2.5 h-2.5" /> APPROVAL GATE
                      </span>
                    )}
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{policy.description}</p>

                  <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-400 pt-1">
                    {policy.applicableToolName && (
                      <div>
                        <span>Tool Bound:</span>
                        <span className="text-cyan-300 ml-1">{policy.applicableToolName}</span>
                      </div>
                    )}
                    {policy.allowedDestinations && policy.allowedDestinations.length > 0 && (
                      <div>
                        <span>Approved Destinations:</span>
                        <span className="text-emerald-300 ml-1">
                          {policy.allowedDestinations.join(', ')}
                        </span>
                      </div>
                    )}
                    <div>
                      <span>Permitted Roles:</span>
                      <span className="text-slate-200 ml-1">{policy.allowedRoles.join(', ')}</span>
                    </div>
                  </div>

                  <div className="text-[11px] text-amber-400/90 font-mono bg-black/30 p-2 rounded mt-2 border border-slate-800">
                    <span className="text-slate-400">Remediation Message:</span> {policy.remediationMessage}
                  </div>
                </div>

                {/* Right controls: Enable/Disable switch */}
                <div className="flex items-center gap-3 shrink-0 self-end md:self-start">
                  {isAdmin ? (
                    <button
                      onClick={() => handleTogglePolicy(policy.id)}
                      className="flex items-center gap-2 text-xs font-mono font-semibold cursor-pointer text-slate-300 hover:text-white"
                      title={policy.enabled ? 'Click to disable policy (useful for testing regression)' : 'Click to enable policy'}
                    >
                      {policy.enabled ? (
                        <>
                          <span className="text-emerald-400">ENABLED</span>
                          <ToggleRight className="w-6 h-6 text-emerald-400" />
                        </>
                      ) : (
                        <>
                          <span className="text-slate-500">DISABLED</span>
                          <ToggleLeft className="w-6 h-6 text-slate-600" />
                        </>
                      )}
                    </button>
                  ) : (
                    <span className={`text-xs font-mono font-bold ${policy.enabled ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {policy.enabled ? 'ENABLED' : 'DISABLED'}
                    </span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Add Policy Modal */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-[#0F172A] border border-slate-700 rounded-xl max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Shield className="w-4 h-4 text-blue-400" />
                <span>Create Central Security Policy</span>
              </h2>
              <button
                onClick={() => setIsCreateOpen(false)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreatePolicy} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Policy Title</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Disallow Bulk Data Export to Cloud Buckets"
                  className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Description &amp; Rationale</label>
                <textarea
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Explain why this control is required..."
                  className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Priority (10-100)</label>
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={priority}
                    onChange={(e) => setPriority(Number(e.target.value))}
                    className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Applicable Tool (Optional)</label>
                  <select
                    value={applicableToolName}
                    onChange={(e) => setApplicableToolName(e.target.value)}
                    className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                  >
                    <option value="">All Tools</option>
                    {tools.map(t => (
                      <option key={t.id} value={t.name}>{t.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Allowed Destinations (Comma-separated)</label>
                <input
                  type="text"
                  value={destinationsInput}
                  onChange={(e) => setDestinationsInput(e.target.value)}
                  placeholder="https://compliance-vault.corp, s3://corp-storage"
                  className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="apprCheck"
                  checked={approvalRequired}
                  onChange={(e) => setApprovalRequired(e.target.checked)}
                  className="rounded bg-slate-800 border-slate-700 text-blue-500 focus:ring-0"
                />
                <label htmlFor="apprCheck" className="text-slate-300 cursor-pointer">
                  Require human-in-the-loop approval before tool execution
                </label>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Remediation Guidance</label>
                <input
                  type="text"
                  value={remediationMessage}
                  onChange={(e) => setRemediationMessage(e.target.value)}
                  placeholder="Contact compliance officer or request role elevation."
                  className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="pt-3 border-t border-slate-800 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="px-4 py-2 rounded-lg text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold cursor-pointer"
                >
                  Save Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
