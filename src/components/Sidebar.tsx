import React from 'react';
import {
  LayoutDashboard,
  Server,
  Wrench,
  Users,
  Shield,
  Activity,
  Flame,
  Lock,
  CheckSquare,
  AlertTriangle,
  FileText,
  Boxes,
  Crosshair,
  FileBarChart2,
  Settings
} from 'lucide-react';

export type NavPage =
  | 'dashboard'
  | 'servers'
  | 'tools'
  | 'access'
  | 'policies'
  | 'monitor'
  | 'threats'
  | 'dlp'
  | 'approvals'
  | 'incidents'
  | 'audit'
  | 'supply-chain'
  | 'testing-lab'
  | 'reports'
  | 'settings';

interface SidebarProps {
  currentPage: NavPage;
  onNavigate: (page: NavPage) => void;
  pendingApprovalsCount: number;
  openIncidentsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onNavigate,
  pendingApprovalsCount,
  openIncidentsCount
}) => {
  const sections: Array<{
    group: string;
    items: Array<{
      id: NavPage;
      label: string;
      icon: React.ComponentType<{ className?: string }>;
      badge?: number;
      badgeColor?: string;
    }>;
  }> = [
    {
      group: 'Core Gateway',
      items: [
        { id: 'dashboard', label: 'Overview Dashboard', icon: LayoutDashboard },
        { id: 'servers', label: 'MCP Server Inventory', icon: Server },
        { id: 'tools', label: 'Tool Inventory', icon: Wrench },
        { id: 'access', label: 'Identity & Access Control', icon: Users },
        { id: 'policies', label: 'Security Policies', icon: Shield }
      ]
    },
    {
      group: 'Runtime Security',
      items: [
        { id: 'monitor', label: 'Runtime Monitor & Gateway', icon: Activity },
        { id: 'threats', label: 'Threat & Injection Detection', icon: Flame },
        { id: 'dlp', label: 'Data Protection & DLP', icon: Lock },
        {
          id: 'approvals',
          label: 'Approval Centre',
          icon: CheckSquare,
          badge: pendingApprovalsCount,
          badgeColor: 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
        },
        {
          id: 'incidents',
          label: 'Security Incidents',
          icon: AlertTriangle,
          badge: openIncidentsCount,
          badgeColor: 'bg-red-500/20 text-red-400 border border-red-500/30'
        },
        { id: 'audit', label: 'Audit Trail', icon: FileText }
      ]
    },
    {
      group: 'Testing & Verification',
      items: [
        { id: 'supply-chain', label: 'Supply-Chain Scanner', icon: Boxes },
        { id: 'testing-lab', label: 'Security Testing Lab', icon: Crosshair },
        { id: 'reports', label: 'Test Results & Reports', icon: FileBarChart2 },
        { id: 'settings', label: 'Settings & Architecture', icon: Settings }
      ]
    }
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-[#0A0F1D] flex flex-col shrink-0 select-none">
      <div className="flex-1 overflow-y-auto py-4 px-3 space-y-6 scrollbar-thin scrollbar-thumb-slate-800">
        {sections.map((sec, sIdx) => (
          <div key={sIdx} className="space-y-1">
            <h3 className="px-3 text-[10px] font-semibold font-mono tracking-widest text-slate-400 uppercase">
              {sec.group}
            </h3>
            <div className="space-y-0.5 pt-1">
              {sec.items.map((item) => {
                const Icon = item.icon;
                const isActive = currentPage === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onNavigate(item.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-lg transition-all text-left cursor-pointer ${
                      isActive
                        ? 'bg-blue-600/15 text-blue-300 font-semibold border-l-2 border-blue-500 pl-2.5'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 truncate">
                      <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-blue-400' : 'text-slate-500'}`} />
                      <span className="truncate">{item.label}</span>
                    </div>

                    {item.badge !== undefined && item.badge > 0 && (
                      <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${item.badgeColor || 'bg-slate-800 text-slate-300'}`}>
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Footer Info */}
      <div className="p-3 border-t border-slate-800/80 bg-[#080D18]/60 text-xs">
        <div className="flex items-center justify-between text-slate-400 text-[11px]">
          <span>Security Engine:</span>
          <span className="text-emerald-400 font-mono font-medium flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            ACTIVE (FAIL-CLOSED)
          </span>
        </div>
      </div>
    </aside>
  );
};
