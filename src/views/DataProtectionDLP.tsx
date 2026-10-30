import React, { useState } from 'react';
import {
  Lock,
  EyeOff,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  FileText,
  KeyRound,
  Mail,
  Copy
} from 'lucide-react';
import { SensitiveDataFinding } from '../types/index.js';

interface DataProtectionDLPProps {
  findings: SensitiveDataFinding[];
}

export const DataProtectionDLP: React.FC<DataProtectionDLPProps> = ({ findings }) => {
  const [testPayload, setTestPayload] = useState<string>(
    'Debug logs from logistics gateway: Auth Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9. Backup credential found: sk-demo-secret-key-99321. Contact: admin@corp.internal'
  );
  const [inspectedOutput, setInspectedOutput] = useState<string | null>(null);

  const handleTestRedaction = () => {
    let text = testPayload;
    text = text.replace(/(?:sk-[a-zA-Z0-9_-]{16,40}|ghp_[a-zA-Z0-9]{36})/gi, '[REDACTED_API_KEY_sk-***]');
    text = text.replace(/(?:bearer\s+[a-zA-Z0-9\._-]{24,}|eyJh[a-zA-Z0-9\._-]{20,})/gi, '[REDACTED_ACCESS_TOKEN]');
    text = text.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi, '[REDACTED_PII_EMAIL]');
    setInspectedOutput(text);
  };

  const patternDefinitions = [
    { name: 'API Keys & Secrets', pattern: 'sk-*, ghp_*, aws_secret_key_*', action: 'REDACT', icon: KeyRound, severity: 'Critical' },
    { name: 'Bearer & JWT Tokens', pattern: 'Bearer eyJ*, eyJh*', action: 'REDACT', icon: Lock, severity: 'High' },
    { name: 'Plaintext Passwords', pattern: 'password=*, secret=*', action: 'BLOCK', icon: EyeOff, severity: 'Critical' },
    { name: 'PII Email Addresses', pattern: '*@*.*', action: 'REDACT / MASK', icon: Mail, severity: 'Medium' }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Lock className="w-5 h-5 text-cyan-400" />
          <span>Data Protection, DLP &amp; Secret Redaction Engine</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Inspects outgoing tool responses and incoming arguments for credentials, access tokens, and sensitive records prior to client delivery.
        </p>
      </div>

      {/* Secret Pattern Coverage */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {patternDefinitions.map((p, idx) => {
          const Icon = p.icon;
          return (
            <div key={idx} className="p-4 rounded-xl bg-[#0F172A] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <Icon className="w-4 h-4 text-cyan-400" />
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                  p.severity === 'Critical' ? 'bg-red-950 text-red-400' : 'bg-amber-950 text-amber-400'
                }`}>
                  {p.severity}
                </span>
              </div>
              <h3 className="text-xs font-bold text-slate-100">{p.name}</h3>
              <p className="text-[11px] font-mono text-slate-400 truncate">{p.pattern}</p>
              <div className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" />
                <span>Action: {p.action}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Interactive DLP Simulator */}
      <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <EyeOff className="w-4 h-4 text-cyan-400" />
            <span>Interactive DLP Redaction Playground</span>
          </h2>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
            STREAM INSPECTOR
          </span>
        </div>

        <div className="space-y-3 text-xs">
          <div>
            <label className="block text-slate-300 font-medium mb-1">
              Unsanitized Raw Tool Response Payload
            </label>
            <textarea
              rows={3}
              value={testPayload}
              onChange={(e) => setTestPayload(e.target.value)}
              className="w-full bg-black/60 border border-slate-700 rounded-lg p-2.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex justify-end">
            <button
              onClick={handleTestRedaction}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1.5 cursor-pointer shadow-md shadow-cyan-900/30"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Inspect &amp; Redact Secrets</span>
            </button>
          </div>

          {inspectedOutput && (
            <div className="space-y-1.5 pt-2 border-t border-slate-800">
              <span className="text-xs font-bold text-slate-300">Sanitized Client Payload (Zero Plaintext Secrets):</span>
              <pre className="p-3 rounded-lg bg-black/60 border border-slate-800 font-mono text-xs text-emerald-300 whitespace-pre-wrap">
                {inspectedOutput}
              </pre>
            </div>
          )}
        </div>
      </div>

      {/* Real Findings Log */}
      <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4">
        <h2 className="text-sm font-bold text-slate-100">DLP Findings &amp; Redaction History</h2>
        <div className="divide-y divide-slate-800/60">
          {findings.map((f) => (
            <div key={f.id} className="py-3 flex items-start justify-between gap-4 text-xs">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-cyan-400">{f.category}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
                    {f.severity}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                    ACTION: {f.appliedAction}
                  </span>
                  <span className="text-slate-400 font-mono">Location: {f.location}</span>
                </div>
                <div className="font-mono text-[11px] text-slate-300">
                  <span className="text-slate-400">Pattern:</span> {f.matchedPattern} · <span className="text-slate-400">Preview:</span> <span className="text-amber-300 font-bold">{f.redactedPreview}</span>
                </div>
              </div>
              <span className="text-[10px] font-mono text-slate-500 shrink-0">
                {new Date(f.createdAt).toLocaleTimeString()}
              </span>
            </div>
          ))}
          {findings.length === 0 && (
            <p className="py-4 text-xs text-slate-500 text-center">No sensitive findings detected yet.</p>
          )}
        </div>
      </div>
    </div>
  );
};
