import React, { useEffect, useState } from 'react';
import {
  Settings,
  Sliders,
  Info,
  Lock,
  CheckCircle2,
  RotateCcw
} from 'lucide-react';
import { GatewaySettings, UserRole } from '../types/index.js';
import { api } from '../services/api.js';

interface SettingsViewProps {
  currentRole: UserRole;
  onResetDemo: () => void;
  isResetting: boolean;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  currentRole,
  onResetDemo,
  isResetting
}) => {
  const [defaultDeny, setDefaultDeny] = useState<boolean>(true);
  const [maxPayloadMb, setMaxPayloadMb] = useState<number>(10);
  const [anomalyThreshold, setAnomalyThreshold] = useState<number>(3);
  const [savedNotice, setSavedNotice] = useState<boolean>(false);
  const [isLoadingSettings, setIsLoadingSettings] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [settingsError, setSettingsError] = useState<string>();

  const isAdmin = currentRole === 'Administrator';

  useEffect(() => {
    let active = true;
    api.getSettings().then(settings => {
      if (!active) return;
      setDefaultDeny(settings.defaultDeny);
      setMaxPayloadMb(settings.maxPayloadMb);
      setAnomalyThreshold(settings.anomalyThreshold);
      setIsLoadingSettings(false);
    }).catch(error => {
      if (!active) return;
      setSettingsError(error instanceof Error ? error.message : 'Settings could not be loaded.');
      setIsLoadingSettings(false);
    });
    return () => {
      active = false;
    };
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSettingsError(undefined);
    setIsSaving(true);
    try {
      const settings: GatewaySettings = await api.updateSettings({ maxPayloadMb, anomalyThreshold });
      setDefaultDeny(settings.defaultDeny);
      setMaxPayloadMb(settings.maxPayloadMb);
      setAnomalyThreshold(settings.anomalyThreshold);
      setSavedNotice(true);
      setTimeout(() => setSavedNotice(false), 2500);
    } catch (error) {
      setSettingsError(error instanceof Error ? error.message : 'Settings could not be saved.');
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Settings className="w-5 h-5 text-slate-400" />
          <span>System Settings &amp; Architecture Configuration</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Adjust runtime gateway operational thresholds, default-deny boundaries, and review technical limitations disclosures.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Gateway Core Settings */}
        <form onSubmit={handleSave} className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-blue-400" />
              <span>Gateway Enforcement Parameters</span>
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
              RUNTIME CONFIG
            </span>
          </div>

          <div className="space-y-4 text-xs">
            <div className="flex items-center justify-between p-3 rounded-lg bg-black/40 border border-slate-800">
              <div>
                <span className="font-bold text-slate-200">Default-Deny Access Policy</span>
                <p className="text-slate-400 text-[11px]">A fixed security invariant: unverified servers, tools, and roles are rejected.</p>
              </div>
              <input
                type="checkbox"
                checked={defaultDeny}
                onChange={(e) => setDefaultDeny(e.target.checked)}
                disabled
                className="w-4 h-4 rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-0 cursor-pointer"
              />
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Max JSON Request Payload Size (MB)</label>
              <input
                type="number"
                min={1}
                max={50}
                value={maxPayloadMb}
                onChange={(e) => setMaxPayloadMb(Number(e.target.value))}
                disabled={!isAdmin || isLoadingSettings || isSaving}
                className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">
                Anomaly Detection Burst Threshold (Denied Requests / Minute)
              </label>
              <input
                type="number"
                min={1}
                max={20}
                value={anomalyThreshold}
                onChange={(e) => setAnomalyThreshold(Number(e.target.value))}
                disabled={!isAdmin || isLoadingSettings || isSaving}
                className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>

            {isAdmin && (
              <div className="pt-2 flex items-center justify-between">
                <button
                  type="submit"
                  disabled={isLoadingSettings || isSaving}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold cursor-pointer shadow-md shadow-blue-900/30"
                >
                  {isSaving ? 'Saving...' : 'Save Gateway Parameters'}
                </button>
                {savedNotice && (
                  <span className="text-emerald-400 font-mono text-[11px] flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Parameters updated!
                  </span>
                )}
                {isLoadingSettings && <p className="text-slate-400">Loading persisted settings…</p>}
                {settingsError && <p role="alert" className="text-red-400">{settingsError}</p>}
              </div>
            )}
          </div>
        </form>

        {/* Risk Scoring Bands */}
        <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              <span>Transparent Risk Scoring Bands (Section 14)</span>
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
              CONFIGURABLE
            </span>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="p-2.5 rounded bg-emerald-950/20 border border-emerald-900/30 flex items-center justify-between">
              <span className="text-emerald-400 font-bold">Low Risk: 0 – 29</span>
              <span className="text-slate-400 text-[11px]">Read-only queries, approved tools</span>
            </div>
            <div className="p-2.5 rounded bg-blue-950/20 border border-blue-900/30 flex items-center justify-between">
              <span className="text-cyan-300 font-bold">Medium Risk: 30 – 59</span>
              <span className="text-slate-400 text-[11px]">Standard write operations with authorized role</span>
            </div>
            <div className="p-2.5 rounded bg-amber-950/20 border border-amber-900/30 flex items-center justify-between">
              <span className="text-amber-400 font-bold">High Risk: 60 – 79</span>
              <span className="text-slate-400 text-[11px]">Bulk exports, heuristic injection indicators</span>
            </div>
            <div className="p-2.5 rounded bg-red-950/20 border border-red-900/30 flex items-center justify-between">
              <span className="text-red-400 font-bold">Critical Risk: 80 – 100</span>
              <span className="text-slate-400 text-[11px]">Destructive tools, direct bypass, tampering</span>
            </div>
          </div>
        </div>
      </div>

      {/* Non-Negotiable Transparency Disclosures per Section 1, 2, 20 */}
      <div className="p-5 rounded-xl bg-[#0F172A] border border-blue-900/40 space-y-3">
        <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
          <Info className="w-4 h-4 text-cyan-400" />
          <span>Architecture &amp; Platform Transparency Disclosures</span>
        </h2>

        <div className="space-y-2 text-xs text-slate-300 leading-relaxed">
          <p>
            • <strong>Simulated vs Live MCP Adapters:</strong> All demonstration servers (Logistics, Finance, Document Knowledge Base) operate on high-fidelity synthetic MCP adapters with real schema validation, deterministic policy resolution, and verified synthetic storage. They are modularly designed so production MCP protocol transports (stdio, SSE, WebSockets) can be plugged in without refactoring the UI or policy engine.
          </p>
          <p>
            • <strong>Ephemeral Token Authority:</strong> Ephemeral tokens are cryptographically generated and validated against actual expiration timestamps by the server-side gateway. They are bounded to the Sentinel domain authority and are not falsely presented as third-party cloud credentials.
          </p>
          <p>
            • <strong>Static Supply-Chain Scanner:</strong> The package manifest scanner performs local AST inspection for test fixture packages and dangerous lifecycle scripts. It does not fabricate artificial CVE findings when an external authoritative CVE feed is unconfigured.
          </p>
        </div>
      </div>

      {/* Sandbox Reset Button */}
      <div className="p-5 rounded-xl bg-red-950/10 border border-red-900/40 flex items-center justify-between">
        <div>
          <h3 className="text-xs font-bold text-red-300">Reset Synthetic Sandbox</h3>
          <p className="text-xs text-slate-400">Restores all servers, tools, policies, incidents, and test records to factory baseline.</p>
        </div>
        <button
          onClick={onResetDemo}
          disabled={isResetting || !isAdmin}
          className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
        >
          <RotateCcw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin' : ''}`} />
          <span>Reset Database</span>
        </button>
      </div>
    </div>
  );
};
