import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  LogOut
} from 'lucide-react';
import { UserRole } from '../types/index.js';

interface HeaderProps {
  currentRole: UserRole;
  currentIdentityId: string;
  onLogout: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentRole,
  currentIdentityId,
  onLogout
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

      {/* Authenticated principal */}
      <div className="flex items-center gap-4">
        <div className="hidden sm:block text-right">
          <div className="text-xs font-medium text-slate-200">{currentRole}</div>
          <div className="text-[10px] font-mono text-slate-500">{currentIdentityId}</div>
        </div>
        <button
          onClick={onLogout}
          className="flex items-center gap-1.5 rounded-lg border border-slate-800 px-2.5 py-1.5 text-xs text-slate-400 hover:bg-slate-800/80 hover:text-slate-200"
          title="Sign out of this browser session"
        >
          <LogOut className="h-3.5 w-3.5" />
          <span>Sign out</span>
        </button>
      </div>
    </header>
  );
};
