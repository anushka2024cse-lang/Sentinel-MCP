import React, { useState } from 'react';
import {
  FileText,
  Download,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Lock,
  Copy,
  Check
} from 'lucide-react';
import { SecurityEvent } from '../types/index.js';

interface AuditTrailProps {
  events: SecurityEvent[];
}

export const AuditTrail: React.FC<AuditTrailProps> = ({ events }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filtered = events.filter((e) => {
    if (decisionFilter !== 'ALL' && e.decision !== decisionFilter) return false;
    if (searchTerm) {
      const match =
        e.eventId.toLowerCase().includes(searchTerm.toLowerCase()) ||
        e.eventType.toLowerCase().includes(searchTerm.toLowerCase()) ||
        e.evidenceSummary.toLowerCase().includes(searchTerm.toLowerCase()) ||
        e.toolName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        e.actorId.toLowerCase().includes(searchTerm.toLowerCase());
      if (!match) return false;
    }
    return true;
  });

  const exportToJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(events, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `sentinel-audit-trail-${new Date().toISOString().substring(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const copyEventId = (id: string) => {
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-400" />
            <span>Immutable Action Logging &amp; Audit Trail</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Complete cryptographic audit trail of all gateway evaluations, policy triggers, and containment events. Secrets redacted at point of entry.
          </p>
        </div>

        <button
          onClick={exportToJson}
          className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 cursor-pointer shadow-sm shrink-0"
        >
          <Download className="w-4 h-4 text-cyan-400" />
          <span>Export Audit Log (JSON)</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-[#0F172A] p-3 rounded-xl border border-slate-800">
        <div className="flex items-center gap-2 w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search Event ID, tool, actor, or payload..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-transparent text-xs text-slate-200 placeholder-slate-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto justify-end">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          <select
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
            className="text-xs bg-[#111C30] border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Decisions ({events.length})</option>
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
            <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
            <option value="SANITIZE_AND_ALLOW">SANITIZE_AND_ALLOW</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono bg-[#111C30]">
                <th className="py-3 px-4">Event ID</th>
                <th className="py-3 px-3">Timestamp</th>
                <th className="py-3 px-3">Event Type</th>
                <th className="py-3 px-3">Decision</th>
                <th className="py-3 px-3">Tool</th>
                <th className="py-3 px-3">Actor</th>
                <th className="py-3 px-4">Evidence Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {filtered.map((evt) => {
                return (
                  <tr key={evt.id} className="hover:bg-slate-800/20">
                    <td className="py-3 px-4 font-bold text-blue-400 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span>{evt.eventId}</span>
                        <button
                          onClick={() => copyEventId(evt.eventId)}
                          className="text-slate-500 hover:text-slate-300 cursor-pointer"
                          title="Copy Event ID"
                        >
                          {copiedId === evt.eventId ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="py-3 px-3 text-slate-500 whitespace-nowrap">
                      {new Date(evt.createdAt).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-3 font-semibold text-slate-300">
                      {evt.eventType}
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded font-bold ${
                          evt.decision === 'ALLOW' || evt.decision === 'SANITIZE_AND_ALLOW'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : evt.decision === 'REQUIRE_APPROVAL'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-red-950 text-red-400 border border-red-800'
                        }`}
                      >
                        {evt.decision}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-cyan-300 font-bold whitespace-nowrap">
                      {evt.toolName || 'N/A'}
                    </td>
                    <td className="py-3 px-3 text-slate-400 whitespace-nowrap">
                      {evt.actorId}
                    </td>
                    <td className="py-3 px-4 text-slate-300 max-w-md truncate" title={evt.evidenceSummary}>
                      {evt.evidenceSummary}
                    </td>
                  </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-slate-500">
                    No matching audit trail events found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
