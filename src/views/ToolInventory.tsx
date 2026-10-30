import React, { useState } from 'react';
import {
  Wrench,
  ShieldAlert,
  ShieldCheck,
  Code2,
  Lock,
  AlertTriangle,
  RotateCcw,
  CheckCircle2,
  FileCode,
  Tag
} from 'lucide-react';
import { MCPTool, MCPServer, UserRole } from '../types/index.js';
import { api } from '../services/api.js';

interface ToolInventoryProps {
  tools: MCPTool[];
  servers: MCPServer[];
  selectedServerId?: string;
  currentRole: UserRole;
  onRefresh: () => void;
}

export const ToolInventory: React.FC<ToolInventoryProps> = ({
  tools,
  servers,
  selectedServerId,
  currentRole,
  onRefresh
}) => {
  const [filterServer, setFilterServer] = useState<string>(selectedServerId || 'ALL');
  const [filterCapability, setFilterCapability] = useState<string>('ALL');
  const [selectedTool, setSelectedTool] = useState<MCPTool | null>(null);
  const [tamperingId, setTamperingId] = useState<string | null>(null);
  const [toolToApprove, setToolToApprove] = useState<MCPTool | null>(null);
  const [approvalCapability, setApprovalCapability] = useState<MCPTool['capabilityType']>('Read');
  const [approvalRoles, setApprovalRoles] = useState<UserRole[]>(['Administrator']);
  const [approvalRequired, setApprovalRequired] = useState(true);

  const isAdmin = currentRole === 'Administrator';

  const filteredTools = tools.filter(t => {
    if (filterServer !== 'ALL' && t.serverId !== filterServer) return false;
    if (filterCapability !== 'ALL' && t.capabilityType !== filterCapability) return false;
    return true;
  });

  const handleTamperTool = async (id: string) => {
    setTamperingId(id);
    try {
      await api.tamperTool(id);
      onRefresh();
    } catch (err: any) {
      alert(`Tamper failed: ${err.message}`);
    } finally {
      setTamperingId(null);
    }
  };

  const handleRestoreTool = async (id: string) => {
    setTamperingId(id);
    try {
      await api.restoreTool(id);
      onRefresh();
    } catch (err: any) {
      alert(`Restore failed: ${err.message}`);
    } finally {
      setTamperingId(null);
    }
  };

  const handleApproveMcpTool = async () => {
    if (!toolToApprove || approvalRoles.length === 0) return;
    setTamperingId(toolToApprove.id);
    try {
      await api.approveMcpTool(toolToApprove.id, {
        capabilityType: approvalCapability,
        allowedRoles: approvalRoles,
        approvalRequirements: approvalRequired
      });
      setToolToApprove(null);
      onRefresh();
    } catch (err: any) {
      alert(`Tool approval failed: ${err.message}`);
    } finally {
      setTamperingId(null);
    }
  };

  const toggleApprovalRole = (role: UserRole) => {
    setApprovalRoles(current => current.includes(role)
      ? current.filter(value => value !== role)
      : [...current, role]);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Wrench className="w-5 h-5 text-cyan-400" />
            <span>MCP Tool Inventory &amp; Integrity Monitor</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Tracks declared schemas, capability classifications, RBAC bindings, and cryptographic definition fingerprints.
          </p>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3">
          <select
            value={filterServer}
            onChange={(e) => setFilterServer(e.target.value)}
            className="text-xs bg-[#111C30] border border-slate-700 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-blue-500 cursor-pointer"
          >
            <option value="ALL">All Servers ({tools.length} Tools)</option>
            {servers.map(s => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>

          <select
            value={filterCapability}
            onChange={(e) => setFilterCapability(e.target.value)}
            className="text-xs bg-[#111C30] border border-slate-700 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-blue-500 cursor-pointer"
          >
            <option value="ALL">All Capabilities</option>
            <option value="Read">Read</option>
            <option value="Write">Write</option>
            <option value="Export">Export</option>
            <option value="Destructive">Destructive</option>
          </select>
        </div>
      </div>

      {/* Integrity Concept Note */}
      <div className="p-3.5 rounded-lg bg-[#0F172A] border border-slate-800 text-xs text-slate-400 flex items-start gap-2.5">
        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-200">Cryptographic Definition Hashing:</span> Each registered tool definition (name, description, schema) is hashed into a SHA-256 fingerprint. Any out-of-band mutation triggers an immediate integrity alarm and halts tool execution (Scenario T07).
        </div>
      </div>

      {/* Tools Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {filteredTools.map((tool) => {
          const server = servers.find(s => s.id === tool.serverId);
          const isTampered = tool.definitionFingerprint === 'tampered_hash_deadbeef' || tool.approvalStatus === 'unapproved';

          return (
            <div
              key={tool.id}
              className={`p-5 rounded-xl border flex flex-col justify-between transition-all ${
                isTampered
                  ? 'bg-red-950/20 border-red-700/60 shadow-lg shadow-red-950/30'
                  : 'bg-[#0F172A] border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-sm text-slate-100">{tool.name}</span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                          tool.capabilityType === 'Destructive'
                            ? 'bg-red-950 text-red-400 border border-red-800'
                            : tool.capabilityType === 'Export'
                            ? 'bg-purple-950 text-purple-400 border border-purple-800'
                            : tool.capabilityType === 'Write'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-blue-950 text-blue-400 border border-blue-800'
                        }`}
                      >
                        {tool.capabilityType}
                      </span>
                    </div>
                    <span className="text-xs text-slate-400 font-mono">Server: {server?.name || tool.serverId}</span>
                  </div>

                  {/* Tampered Badge */}
                  {isTampered ? (
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold bg-red-950 text-red-400 border border-red-800 flex items-center gap-1 animate-pulse">
                      <AlertTriangle className="w-3 h-3" />
                      {tool.definitionFingerprint === 'tampered_hash_deadbeef' ? 'TAMPERED FINGERPRINT' : 'UNAPPROVED / REVIEW REQUIRED'}
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" />
                      VERIFIED
                    </span>
                  )}
                </div>

                <p className="text-xs text-slate-300 leading-relaxed min-h-[36px]">
                  {tool.description}
                </p>

                {/* Fingerprint & RBAC */}
                <div className="p-2.5 rounded bg-black/40 border border-slate-800/80 font-mono text-[11px] space-y-1.5">
                  <div className="flex items-center justify-between text-slate-400">
                    <span>SHA-256 Fingerprint:</span>
                    <span className={`font-bold ${isTampered ? 'text-red-400' : 'text-cyan-400'}`}>
                      {tool.definitionFingerprint}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-slate-400">
                    <span>Allowed Roles:</span>
                    <span className="text-slate-200">{tool.allowedRoles.join(', ')}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-400">
                    <span>Approval Required:</span>
                    <span className={tool.approvalRequirements ? 'text-amber-400 font-bold' : 'text-slate-400'}>
                      {tool.approvalRequirements ? 'YES (Human-in-the-Loop)' : 'NO (Automated Gate)'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between gap-2">
                <button
                  onClick={() => setSelectedTool(tool)}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1.5 cursor-pointer"
                >
                  <Code2 className="w-3.5 h-3.5" />
                  <span>Inspect Input Schema</span>
                </button>

                {isAdmin && (
                  <div className="flex items-center gap-2">
                    {server?.connectionMode === 'live_mcp_proxy' && tool.approvalStatus !== 'approved' ? (
                      <button
                        onClick={() => {
                          setToolToApprove(tool);
                          setApprovalCapability('Read');
                          setApprovalRoles(['Administrator']);
                          setApprovalRequired(true);
                        }}
                        disabled={tamperingId === tool.id || server.trustStatus !== 'trusted' || server.approvalStatus !== 'approved'}
                        className="px-2.5 py-1 text-[11px] font-semibold rounded bg-blue-950/40 text-blue-200 border border-blue-700 hover:bg-blue-900/40 disabled:opacity-50"
                        title="Review this discovered MCP definition and set its approved baseline"
                      >
                        Review &amp; approve definition
                      </button>
                    ) : isTampered ? (
                      <button
                        onClick={() => handleRestoreTool(tool.id)}
                        disabled={tamperingId === tool.id}
                        className="px-2.5 py-1 text-[11px] font-semibold rounded bg-emerald-950/40 text-emerald-300 border border-emerald-700 hover:bg-emerald-900/40 cursor-pointer flex items-center gap-1"
                      >
                        <RotateCcw className="w-3 h-3" />
                        <span>Restore Baseline</span>
                      </button>
                    ) : (
                      <button
                        onClick={() => handleTamperTool(tool.id)}
                        disabled={tamperingId === tool.id}
                        className="px-2.5 py-1 text-[11px] font-semibold rounded bg-red-950/40 text-red-300 border border-red-800 hover:bg-red-900/40 cursor-pointer flex items-center gap-1"
                        title="Simulate unapproved definition alteration to test T07"
                      >
                        <AlertTriangle className="w-3 h-3" />
                        <span>Simulate Tampering (T07)</span>
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Schema Detail Modal */}
      {selectedTool && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-[#0F172A] border border-slate-700 rounded-xl max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-base font-bold text-slate-100 font-mono">
                  {selectedTool.name} Input Schema
                </h2>
                <span className="text-xs text-slate-400">JSON Schema Definition</span>
              </div>
              <button
                onClick={() => setSelectedTool(null)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer text-sm"
              >
                ✕
              </button>
            </div>

            <div className="bg-black/60 p-4 rounded-lg border border-slate-800 font-mono text-xs text-cyan-300 max-h-80 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800">
              <pre>{JSON.stringify(selectedTool.inputSchema, null, 2)}</pre>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedTool(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {toolToApprove && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4">
          <div className="bg-[#0F172A] border border-slate-700 rounded-xl max-w-lg w-full p-6 space-y-4">
            <div className="border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-slate-100">Approve discovered MCP definition</h2>
              <p className="mt-1 text-xs text-slate-400">
                {toolToApprove.name} · the current server definition becomes the fingerprint baseline.
              </p>
            </div>
            <label className="block text-xs text-slate-300">
              Capability classification
              <select
                value={approvalCapability}
                onChange={event => setApprovalCapability(event.target.value as MCPTool['capabilityType'])}
                className="mt-1 w-full bg-[#111C30] border border-slate-700 rounded-lg p-2 text-slate-200"
              >
                <option value="Read">Read</option>
                <option value="Write">Write</option>
                <option value="Export">Export</option>
                <option value="Destructive">Destructive</option>
                <option value="Administrative">Administrative</option>
              </select>
            </label>
            <fieldset className="space-y-2">
              <legend className="text-xs text-slate-300">Allowed roles</legend>
              {(['Administrator', 'Security Analyst', 'Approver', 'Read-only Auditor'] as const).map(role => (
                <label key={role} className="flex items-center gap-2 text-xs text-slate-300">
                  <input
                    type="checkbox"
                    checked={approvalRoles.includes(role)}
                    onChange={() => toggleApprovalRole(role)}
                  />
                  {role}
                </label>
              ))}
            </fieldset>
            <label className="flex items-center gap-2 text-xs text-amber-200">
              <input
                type="checkbox"
                checked={approvalRequired}
                onChange={event => setApprovalRequired(event.target.checked)}
              />
              Require human approval for each invocation
            </label>
            <div className="flex justify-end gap-2 border-t border-slate-800 pt-3">
              <button onClick={() => setToolToApprove(null)} className="px-3 py-2 text-xs text-slate-300">
                Cancel
              </button>
              <button
                onClick={handleApproveMcpTool}
                disabled={tamperingId === toolToApprove.id || approvalRoles.length === 0}
                className="px-3 py-2 text-xs font-semibold rounded bg-blue-600 text-white disabled:opacity-50"
              >
                Approve fingerprint
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
