import React from 'react';
import {
  Users,
  Key,
  ShieldCheck,
  CheckCircle2,
  XCircle
} from 'lucide-react';
import { UserRole, MCPTool } from '../types/index.js';

interface IdentityAccessProps {
  tools: MCPTool[];
  currentRole: UserRole;
}

export const IdentityAccess: React.FC<IdentityAccessProps> = ({
  tools,
  currentRole
}) => {
  const rolesList: UserRole[] = ['Administrator', 'Security Analyst', 'Approver', 'Read-only Auditor'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Users className="w-5 h-5 text-blue-400" />
          <span>Identity &amp; Role-Based Access Control</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          API access is authenticated by server-configured credentials; role claims are resolved by the gateway.
        </p>
      </div>

      {/* Authentication configuration */}
      <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">Server-managed API credentials</h2>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
            AUTHENTICATED AS {currentRole.toUpperCase()}
          </span>
        </div>
        <div className="flex items-start gap-3 text-xs leading-relaxed text-slate-400">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" />
          <p>
            Credentials and their role bindings are configured with <code className="text-cyan-300">SENTINEL_API_TOKENS</code> on
            the server. They are never issued by this UI or stored in the application database. Local development
            prints a temporary administrator token in the server terminal; production startup requires explicit
            credentials. Remove or rotate a configured credential and restart the server to revoke it.
          </p>
        </div>
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
