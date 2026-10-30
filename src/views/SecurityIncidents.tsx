import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  Clock,
  User,
  Plus,
  Send,
  FileText
} from 'lucide-react';
import { SecurityIncident, UserRole } from '../types/index.js';
import { api } from '../services/api.js';

interface SecurityIncidentsProps {
  incidents: SecurityIncident[];
  currentRole: UserRole;
  onRefresh: () => void;
  onViewAuditTrail: () => void;
}

export const SecurityIncidents: React.FC<SecurityIncidentsProps> = ({
  incidents,
  currentRole,
  onRefresh,
  onViewAuditTrail
}) => {
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(incidents[0] || null);
  const [newNote, setNewNote] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [detail, setDetail] = useState<Awaited<ReturnType<typeof api.getIncidentDetails>> | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [isMutating, setIsMutating] = useState(false);
  const canInvestigate = currentRole === 'Administrator' || currentRole === 'Security Analyst';
  const canContainOrResolve = currentRole === 'Administrator';

  useEffect(() => {
    if (!selectedIncident) return;
    const refreshedIncident = incidents.find(incident => incident.id === selectedIncident.id);
    if (refreshedIncident && refreshedIncident.updatedAt !== selectedIncident.updatedAt) {
      setSelectedIncident(refreshedIncident);
    }
  }, [incidents, selectedIncident]);

  useEffect(() => {
    if (!selectedIncident) {
      setDetail(null);
      return;
    }
    let active = true;
    setIsLoadingDetail(true);
    api.getIncidentDetails(selectedIncident.id)
      .then(result => { if (active) setDetail(result); })
      .catch(error => {
        if (active) {
          setDetail(null);
          alert(`Failed to load incident evidence: ${error.message}`);
        }
      })
      .finally(() => { if (active) setIsLoadingDetail(false); });
    return () => { active = false; };
  }, [selectedIncident?.id, selectedIncident?.updatedAt]);

  const filtered = incidents.filter(i => {
    if (statusFilter !== 'ALL' && i.status !== statusFilter) return false;
    return true;
  });

  const handleAddNote = async () => {
    if (!selectedIncident || !newNote.trim()) return;
    setIsMutating(true);
    try {
      await api.updateIncident(selectedIncident.id, { note: newNote.trim() });
      setNewNote('');
      onRefresh();
    } catch (e: any) {
      alert(`Error updating notes: ${e.message}`);
    } finally {
      setIsMutating(false);
    }
  };

  const runIncidentAction = async (
    action: 'investigate' | 'contain' | 'resolve' | 'release',
    value: string
  ) => {
    if (!selectedIncident || !value.trim()) return;
    setIsMutating(true);
    try {
      if (action === 'investigate') await api.investigateIncident(selectedIncident.id, value.trim());
      if (action === 'contain') await api.containIncident(selectedIncident.id, value.trim());
      if (action === 'resolve') await api.resolveIncident(selectedIncident.id, value.trim());
      if (action === 'release') await api.releaseIncidentContainment(selectedIncident.id, value.trim());
      onRefresh();
    } catch (e: any) {
      alert(`Incident action failed: ${e.message}`);
    } finally {
      setIsMutating(false);
    }
  };

  const requestIncidentAction = (action: 'investigate' | 'contain' | 'resolve' | 'release') => {
    if (!selectedIncident || isMutating) return;
    if (action === 'investigate') {
      const note = window.prompt('Record the initial investigation note:');
      if (note?.trim()) void runIncidentAction(action, note);
      return;
    }
    const prompts = {
      contain: 'Quarantine the affected MCP server? All its protected tool calls will be blocked until explicit recovery.',
      resolve: 'Provide resolution evidence (at least 10 characters):',
      release: 'Release the incident enforcement lock? The server remains quarantined until it is separately re-approved.'
    };
    const value = action === 'contain'
      ? window.confirm(prompts.contain) ? window.prompt('Reason for containment:') : null
      : window.prompt(prompts[action]);
    if (value?.trim()) void runIncidentAction(action, value);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <span>Security Incident Response &amp; Investigation</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Automated correlation of high-severity telemetry, prompt injection attempts, rate-limit anomalies, and containment workflows.
          </p>
        </div>

        {/* Status filter */}
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="text-xs bg-[#111C30] border border-slate-700 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-blue-500 cursor-pointer self-start sm:self-auto"
        >
          <option value="ALL">All Statuses ({incidents.length})</option>
          <option value="Open">Open</option>
          <option value="Investigating">Investigating</option>
          <option value="Contained">Contained</option>
          <option value="Resolved">Resolved</option>
        </select>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Incident List */}
        <div className="lg:col-span-5 space-y-3">
          {filtered.map((inc) => {
            const isSelected = selectedIncident?.id === inc.id;
            return (
              <button
                key={inc.id}
                type="button"
                onClick={() => setSelectedIncident(inc)}
                className={`w-full text-left p-4 rounded-xl border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-[#152033] border-blue-500/80 shadow-lg shadow-blue-950/40'
                    : 'bg-[#0F172A] border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <span className="font-mono text-xs font-bold text-slate-200 line-clamp-1">
                    {inc.title}
                  </span>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold shrink-0 ${
                      inc.severity === 'Critical'
                        ? 'bg-red-950 text-red-400 border border-red-800'
                        : inc.severity === 'High'
                        ? 'bg-orange-950 text-orange-400 border border-orange-800'
                        : 'bg-amber-950 text-amber-400 border border-amber-800'
                    }`}
                  >
                    {inc.severity}
                  </span>
                </div>

                <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                  {inc.description}
                </p>

                <div className="mt-3 flex items-center justify-between text-[11px] font-mono text-slate-500 pt-2 border-t border-slate-800/80">
                  <span className={`font-bold ${
                    inc.status === 'Open' ? 'text-red-400' : inc.status === 'Investigating' ? 'text-blue-400' : 'text-emerald-400'
                  }`}>
                    ● {inc.status}
                  </span>
                  <span>{new Date(inc.createdAt).toLocaleTimeString()}</span>
                </div>
              </button>
            );
          })}

          {filtered.length === 0 && (
            <p className="p-8 text-center text-xs text-slate-500">No matching incidents.</p>
          )}
        </div>

        {/* Incident Detail Panel */}
        <div className="lg:col-span-7">
          {selectedIncident ? (
            <div className="p-6 rounded-xl bg-[#0F172A] border border-slate-800 space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 border-b border-slate-800 pb-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-blue-400 font-bold">{selectedIncident.id}</span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        selectedIncident.status === 'Open'
                          ? 'bg-red-950 text-red-400'
                          : selectedIncident.status === 'Investigating'
                          ? 'bg-blue-950 text-blue-400'
                          : 'bg-emerald-950 text-emerald-400'
                      }`}
                    >
                      {selectedIncident.status}
                    </span>
                  </div>
                  <h2 className="text-base font-bold text-slate-100">{selectedIncident.title}</h2>
                </div>

                {/* Lifecycle actions perform server-side transitions; status is never changed by the UI alone. */}
                <div className="flex flex-wrap items-center gap-2">
                  {selectedIncident.status === 'Open' && canInvestigate && (
                    <button disabled={isMutating} onClick={() => requestIncidentAction('investigate')}
                      className="px-2.5 py-1 text-[11px] font-semibold rounded bg-blue-950 text-blue-300 border border-blue-800 hover:bg-blue-900 disabled:opacity-50">
                      Investigate
                    </button>
                  )}
                  {['Open', 'Investigating'].includes(selectedIncident.status) && canContainOrResolve && (
                    <button disabled={isMutating} onClick={() => requestIncidentAction('contain')}
                      className="px-2.5 py-1 text-[11px] font-semibold rounded bg-amber-950 text-amber-300 border border-amber-800 hover:bg-amber-900 disabled:opacity-50">
                      Quarantine affected server
                    </button>
                  )}
                  {['Open', 'Investigating', 'Contained'].includes(selectedIncident.status) && canContainOrResolve && (
                    <button disabled={isMutating} onClick={() => requestIncidentAction('resolve')}
                      className="px-2.5 py-1 text-[11px] font-semibold rounded bg-emerald-950 text-emerald-300 border border-emerald-800 hover:bg-emerald-900 disabled:opacity-50">
                      Resolve with evidence
                    </button>
                  )}
                  {selectedIncident.containment?.active && canContainOrResolve && (
                    <button disabled={isMutating} onClick={() => requestIncidentAction('release')}
                      className="px-2.5 py-1 text-[11px] font-semibold rounded bg-slate-800 text-slate-200 border border-slate-600 hover:bg-slate-700 disabled:opacity-50">
                      Release containment lock
                    </button>
                  )}
                </div>
              </div>

              {/* Description & Remediation */}
              <div className="space-y-3 text-xs">
                <div>
                  <h3 className="text-slate-400 font-medium mb-1">Incident Overview:</h3>
                  <p className="text-slate-200 leading-relaxed bg-black/30 p-3 rounded-lg border border-slate-800">
                    {selectedIncident.description}
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-900/40 text-blue-300 space-y-1">
                  <span className="font-bold flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-blue-400" />
                    Recommended Remediation:
                  </span>
                  <p className="text-slate-300">{selectedIncident.recommendedRemediation}</p>
                </div>

                <div className="grid grid-cols-2 gap-3 font-mono text-[11px] text-slate-400 pt-1">
                  <div>
                    <span>Affected Server:</span> <span className="text-slate-200">{selectedIncident.affectedServerId}</span>
                  </div>
                  <div>
                    <span>Assigned Analyst:</span> <span className="text-slate-200">{selectedIncident.assignedTo || 'Unassigned'}</span>
                  </div>
                  {selectedIncident.containment && (
                    <div className={`p-3 rounded-lg border text-xs ${
                      selectedIncident.containment.active
                        ? 'bg-red-950/30 border-red-900/60 text-red-200'
                        : 'bg-slate-900 border-slate-800 text-slate-300'
                    }`}>
                      <strong>{selectedIncident.containment.active ? 'ENFORCEMENT ACTIVE' : 'Containment released'}</strong>
                      <p className="mt-1">{selectedIncident.containment.reason}</p>
                      {selectedIncident.containment.releasedAt && (
                        <p className="mt-1 text-slate-400">
                          Released by {selectedIncident.containment.releasedBy} at {new Date(selectedIncident.containment.releasedAt).toLocaleString()}.
                          Server trust is not automatically restored.
                        </p>
                      )}
                    </div>
                  )}
                  {selectedIncident.resolutionDetails && (
                    <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/40 text-xs text-emerald-200">
                      <strong>Resolution evidence</strong>
                      <p className="mt-1">{selectedIncident.resolutionDetails}</p>
                    </div>
                  )}
                </div>

                <div className="space-y-3 pt-3 border-t border-slate-800">
                  <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
                    <FileText className="w-4 h-4 text-blue-400" /> Correlated evidence
                  </h3>
                  {isLoadingDetail && <p className="text-xs text-slate-500">Loading incident evidence…</p>}
                  {detail && (
                    <>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                        <div className="p-2 rounded bg-black/30 border border-slate-800 text-slate-300">
                          Related requests: {detail.requests.length}
                        </div>
                        <div className="p-2 rounded bg-black/30 border border-slate-800 text-slate-300">
                          Matched policies: {detail.policies.map(policy => policy.name).join(', ') || 'None recorded'}
                        </div>
                      </div>
                      <div className="max-h-44 overflow-y-auto space-y-2">
                        {detail.events.map(event => (
                          <div key={event.id} className="p-2 rounded bg-black/30 border border-slate-800 text-[11px]">
                            <div className="flex justify-between gap-2 text-slate-400">
                              <span>{event.eventType} · {event.decision}</span>
                              <span>{new Date(event.createdAt).toLocaleString()}</span>
                            </div>
                            <p className="mt-1 text-slate-300">{event.evidenceSummary}</p>
                          </div>
                        ))}
                        {detail.events.length === 0 && <p className="text-xs text-slate-500">No correlated audit events found.</p>}
                      </div>
                      {detail.requests.length > 0 && (
                        <div className="space-y-1">
                          {detail.requests.map(request => (
                            <div key={request.id} className="text-[11px] text-slate-400">
                              {request.requestId} · {request.actorId} · {request.toolName} · {request.decision} · risk {request.riskScore}
                              {request.remediationReason && <span> · {request.remediationReason}</span>}
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>

              {/* Investigation Notes & Timeline */}
              <div className="space-y-3 pt-3 border-t border-slate-800">
                <h3 className="text-xs font-bold text-slate-200">Analyst Investigation Notes</h3>
                <div className="space-y-2 max-h-48 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800">
                  {selectedIncident.investigationNotes?.map((n, idx) => (
                    <div key={idx} className="p-2.5 rounded bg-black/40 border border-slate-800 text-xs space-y-1">
                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                        <span className="text-blue-400 font-bold">{n.author}</span>
                        <span>{new Date(n.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-slate-300 text-[11px] leading-relaxed">{n.note}</p>
                    </div>
                  ))}
                  {(!selectedIncident.investigationNotes || selectedIncident.investigationNotes.length === 0) && (
                    <p className="text-xs text-slate-500">No analyst notes recorded yet.</p>
                  )}
                </div>

                {/* Add note input */}
                <div className="flex items-center gap-2 pt-2">
                  <input
                    type="text"
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    placeholder="Add an investigation note or action taken..."
                    className="flex-1 bg-[#111C30] border border-slate-700 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                    onKeyDown={(e) => { if (e.key === 'Enter') void handleAddNote(); }}
                  />
                  <button
                    onClick={handleAddNote}
                    disabled={isMutating || selectedIncident.status === 'Resolved' || selectedIncident.status === 'False Positive' || !canInvestigate}
                    className="px-3 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1 cursor-pointer disabled:opacity-50"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>Add</span>
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-[#0F172A] border border-slate-800 text-center text-xs text-slate-500">
              Select an incident to view details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
