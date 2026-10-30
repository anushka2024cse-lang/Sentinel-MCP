import React, { useState } from 'react';
import {
  Users,
  Key,
  ShieldCheck,
  Clock,
  Copy,
  Check,
  CheckCircle2,
  XCircle,
  AlertCircle
} from 'lucide-react';
import { IdentityProfile, UserRole, MCPTool } from '../types/index.js';
import { api } from '../services/api.js';

interface IdentityAccessProps {
  identities: IdentityProfile[];
  tools: MCPTool[];
  currentRole: UserRole;
  onRefresh: () => void;
}

export const IdentityAccess: React.FC<IdentityAccessProps> = ({
  identities,
  tools,
  currentRole,
  onRefresh
}) => {
  const [selectedIdentityId, setSelectedIdentityId] = useState<string>(identities[0]?.id || '');
  const [tokenDuration, setTokenDuration] = useState<number>(60);
  const [generatedTokenInfo, setGeneratedTokenInfo] = useState<any | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);

  const isAdmin = currentRole === 'Administrator';

  const handleGenerateToken = async () => {
    if (!selectedIdentityId) return;
    setIsGenerating(true);
    try {
      const data = await api.generateEphemeralToken(selectedIdentityId, tokenDuration);
      setGeneratedTokenInfo(data);
      onRefresh();
    } catch (e: any) {
      alert(`Token generation failed: ${e.message}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const rolesList: UserRole[] = ['Administrator', 'Security Analyst', 'Approver', 'Read-only Auditor'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Users className="w-5 h-5 text-blue-400" />
          <span>Identity, RBAC &amp; Ephemeral Access Control</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Enforce least-privilege role boundaries, client authentication tokens, and short-lived credentials for AI clients.
        </p>
      </div>

      {/* Ephemeral Credential Generator Section */}
      <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">Sentinel Ephemeral Token Authority</h2>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
            TIME-BOUND TOKENS
          </span>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          Issues cryptographically signed, short-lived bearer tokens for AI clients and external callers. The runtime gateway validates token signature and expiry on every tool request.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
          <div>
            <label className="block text-xs text-slate-300 font-medium mb-1">Target Identity</label>
            <select
              value={selectedIdentityId}
              onChange={(e) => setSelectedIdentityId(e.target.value)}
              className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              {identities.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.name} ({i.role})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs text-slate-300 font-medium mb-1">Validity Window</label>
            <select
              value={tokenDuration}
              onChange={(e) => setTokenDuration(Number(e.target.value))}
              className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value={15}>15 Minutes (High Sensitivity)</option>
              <option value={60}>1 Hour (Standard Session)</option>
              <option value={480}>8 Hours (Shift Window)</option>
              <option value={1440}>24 Hours (Maximum Allowed)</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              onClick={handleGenerateToken}
              disabled={isGenerating || !isAdmin}
              className="w-full py-2 px-3 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white flex items-center justify-center gap-1.5 cursor-pointer shadow-md shadow-blue-900/30 disabled:opacity-50"
              title={isAdmin ? 'Issue new signed token' : 'Requires Administrator role'}
            >
              <Key className="w-3.5 h-3.5" />
              <span>{isGenerating ? 'Signing...' : 'Issue Ephemeral Token'}</span>
            </button>
          </div>
        </div>

        {generatedTokenInfo && (
          <div className="mt-3 p-3.5 rounded-lg bg-black/40 border border-slate-700/80 space-y-2 font-mono text-xs">
            <div className="flex items-center justify-between text-slate-300">
              <span className="text-emerald-400 font-bold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Token Issued Successfully:
              </span>
              <button
                onClick={() => copyToClipboard(generatedTokenInfo.token)}
                className="text-slate-400 hover:text-slate-200 flex items-center gap-1 cursor-pointer text-[11px]"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy Token'}</span>
              </button>
            </div>

            <div className="p-2 rounded bg-slate-900 border border-slate-800 text-cyan-300 break-all select-all">
              {generatedTokenInfo.token}
            </div>

            <div className="flex justify-between text-[11px] text-slate-400">
              <span>Expires: {new Date(generatedTokenInfo.expiresAt).toLocaleTimeString()} ({generatedTokenInfo.durationMinutes}m window)</span>
              <span>Role Bound: {generatedTokenInfo.role}</span>
            </div>
          </div>
        )}
      </div>

      {/* Role Permission Matrix Table */}
      <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4">
        <div>
          <h2 className="text-sm font-bold text-slate-100">Role-Based Access Control (RBAC) Permission Matrix</h2>
          <p className="text-xs text-slate-400">Explicit tool invocation authorization mapped across organization roles.</p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono">
                <th className="py-2.5 px-3">Protected Tool</th>
                <th className="py-2.5 px-3">Classification</th>
                {rolesList.map(r => (
                  <th key={r} className="py-2.5 px-3 text-center">{r}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {tools.map(tool => (
                <tr key={tool.id} className="hover:bg-slate-800/20">
                  <td className="py-2.5 px-3 font-bold text-slate-200">
                    {tool.name}
                  </td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                        tool.capabilityType === 'Destructive'
                          ? 'bg-red-950 text-red-400'
                          : tool.capabilityType === 'Export'
                          ? 'bg-purple-950 text-purple-400'
                          : tool.capabilityType === 'Write'
                          ? 'bg-amber-950 text-amber-400'
                          : 'bg-blue-950 text-blue-400'
                      }`}
                    >
                      {tool.capabilityType}
                    </span>
                  </td>
                  {rolesList.map(role => {
                    const isAllowed = tool.allowedRoles.includes(role);
                    return (
                      <td key={role} className="py-2.5 px-3 text-center">
                        {isAllowed ? (
                          <span className="text-emerald-400 font-bold inline-flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" /> ALLOW
                          </span>
                        ) : (
                          <span className="text-red-400 font-bold inline-flex items-center gap-1">
                            <XCircle className="w-3.5 h-3.5" /> DENY
                          </span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
