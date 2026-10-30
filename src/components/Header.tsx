import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Play,
  RotateCcw,
  UserCheck
} from 'lucide-react';
import { UserRole, IdentityProfile } from '../types/index.js';

interface HeaderProps {
  currentRole: UserRole;
  onRoleChange: (role: UserRole) => void;
  identities: IdentityProfile[];
  currentIdentityId: string;
  onIdentityChange: (id: string) => void;
  onRunPrimaryDemo: () => void;
  onResetDemo: () => void;
  isResetting: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  currentRole,
  onRoleChange,
  identities,
  currentIdentityId,
  onIdentityChange,
  onRunPrimaryDemo,
  onResetDemo,
  isResetting
}) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-[#0B1120] px-6 flex items-center justify-between select-none z-20">
      {/* Brand & Tagline */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold tracking-wider text-slate-100 text-base">SENTINEL-MCP</span>
              <span className="text-[10px] tracking-widest font-mono uppercase px-1.5 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800/60">
                GATEWAY v2.4
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Secure the Connection · Test the Defence · Prove the Protection
            </p>
          </div>
        </div>
      </div>

      {/* Center / Action Bar: Primary Demo Walkthrough */}
      <div className="flex items-center gap-3">
        <button
          onClick={onRunPrimaryDemo}
          className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white shadow-md shadow-blue-900/30 transition-all cursor-pointer"
          title="Run required Section 33 end-to-end verification walkthrough"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>Section 33 Demo Walkthrough</span>
        </button>

        <button
          onClick={onResetDemo}
          disabled={isResetting}
          className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 rounded-lg border border-slate-800 transition-colors cursor-pointer"
          title="Reset synthetic enterprise records to pristine baseline"
        >
          <RotateCcw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin' : ''}`} />
          <span className="hidden md:inline">Reset Sandbox</span>
        </button>
      </div>

      {/* Right Controls: Role & Identity Switcher */}
      <div className="flex items-center gap-4">
        {/* Active Role Selector */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-mono hidden lg:inline">Active Role:</span>
          <select
            value={currentRole}
            onChange={(e) => onRoleChange(e.target.value as UserRole)}
            className="text-xs font-medium bg-[#111C30] border border-slate-700 text-slate-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500 cursor-pointer"
          >
            <option value="Administrator">Administrator (SARAH)</option>
            <option value="Security Analyst">Security Analyst (MARCUS)</option>
            <option value="Approver">Approver (ELENA)</option>
            <option value="Read-only Auditor">Read-only Auditor (AUDIT-BOT)</option>
          </select>
        </div>

        {/* Identity Context */}
        <div className="hidden xl:flex items-center gap-2 border-l border-slate-800 pl-3">
          <UserCheck className="w-4 h-4 text-cyan-400" />
          <select
            value={currentIdentityId}
            onChange={(e) => onIdentityChange(e.target.value)}
            className="text-xs font-mono bg-transparent border-none text-slate-300 focus:outline-none cursor-pointer max-w-[150px] truncate"
          >
            {identities.map(i => (
              <option key={i.id} value={i.id} className="bg-[#111C30] text-slate-200">
                {i.name}
              </option>
            ))}
          </select>
        </div>
      </div>
    </header>
  );
};
