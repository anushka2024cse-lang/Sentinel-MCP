import React, { useState } from 'react';
import {
  Activity,
  Send,
  ShieldCheck,
  ShieldAlert,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Code2,
  FileText,
  Flame,
  Radio
} from 'lucide-react';
import { MCPTool, MCPServer, UserRole, SecurityRequest } from '../types/index.js';
import { api } from '../services/api.js';

interface RuntimeMonitorProps {
  servers: MCPServer[];
  tools: MCPTool[];
  currentRole: UserRole;
  recentRequests: SecurityRequest[];
  onRefresh: () => void;
}

export const RuntimeMonitor: React.FC<RuntimeMonitorProps> = ({
  servers,
  tools,
  currentRole,
  recentRequests,
  onRefresh
}) => {
  const [selectedServerId, setSelectedServerId] = useState<string>(servers[0]?.id || 'srv-demo-enterprise');
  const [selectedToolName, setSelectedToolName] = useState<string>('get_shipment_status');
  const [argsJson, setArgsJson] = useState<string>('{\n  "trackingNumber": "TRK-99214"\n}');
  const [destination, setDestination] = useState<string>('');
  const [bypassGateway, setBypassGateway] = useState<boolean>(false);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [evalResult, setEvalResult] = useState<any | null>(null);

  const availableTools = tools.filter(t => t.serverId === selectedServerId);
  const selectedServer = servers.find(server => server.id === selectedServerId);

  const handleToolChange = (toolName: string) => {
    setSelectedToolName(toolName);
    const tool = tools.find(t => t.serverId === selectedServerId && t.name === toolName);
    if (tool) {
      // populate template arguments from schema
      const sampleArgs: Record<string, any> = {};
      if (tool.inputSchema?.properties) {
        for (const [k, v] of Object.entries(tool.inputSchema.properties)) {
          if (k === 'trackingNumber') sampleArgs[k] = 'TRK-99214';
          else if (k === 'query') sampleArgs[k] = 'logistics_gateway_sop';
          else if (k === 'warehouseId') sampleArgs[k] = 'WH-EAST-1';
          else if (k === 'sku') sampleArgs[k] = 'SKU-1049';
          else if (k === 'adjustment') sampleArgs[k] = 20;
          else if (k === 'quarter') sampleArgs[k] = 'Q3-2026';
          else if (k === 'destination') sampleArgs[k] = 'https://compliance-vault.internal.corp';
          else if (k === 'recordId') sampleArgs[k] = 'REC-TEST-9901';
          else if (k === 'confirmPhrase') sampleArgs[k] = 'CONFIRM_PERMANENT_DELETION';
          else sampleArgs[k] = v.type === 'number' ? 10 : v.type === 'boolean' ? false : 'sample_value';
        }
      }
      setArgsJson(JSON.stringify(sampleArgs, null, 2));
      if (sampleArgs.destination) setDestination(sampleArgs.destination);
    }
  };

  const handleRunEvaluation = async () => {
    setIsEvaluating(true);
    setEvalResult(null);

    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = JSON.parse(argsJson);
    } catch (e: any) {
      alert(`Invalid JSON arguments: ${e.message}`);
      setIsEvaluating(false);
      return;
    }

    try {
      const res = await api.evaluateGateway({
        serverId: selectedServerId,
        toolName: selectedToolName,
        arguments: parsedArgs,
        destination: destination || undefined,
        bypassGateway
      });
      setEvalResult(res);
      onRefresh();
    } catch (err: any) {
      alert(`Evaluation error: ${err.message}`);
    } finally {
      setIsEvaluating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Activity className="w-5 h-5 text-emerald-400" />
          <span>Runtime Security Gateway</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Requests are evaluated by the backend before execution. Live MCP servers are contacted only through the configured Streamable HTTP proxy.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Request Dispatcher */}
        <div className="lg:col-span-5 p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              <span>Gateway Tool Request</span>
            </h2>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              selectedServer?.connectionMode === 'live_mcp_proxy'
                ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                : 'bg-amber-950 text-amber-300 border-amber-800'
            }`}>
              {selectedServer?.connectionMode === 'live_mcp_proxy' ? 'LIVE MCP PROXY' : 'SIMULATION ADAPTER'}
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div className="rounded-lg border border-slate-800 bg-black/20 px-3 py-2 text-slate-400">
              Authenticated caller role: <strong className="text-slate-200">{currentRole}</strong>
            </div>

            {/* Server & Tool Pickers */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Target MCP Server</label>
                <select
                  value={selectedServerId}
                  onChange={(e) => {
                    setSelectedServerId(e.target.value);
                    const firstTool = tools.find(t => t.serverId === e.target.value);
                    if (firstTool) handleToolChange(firstTool.name);
                  }}
                  className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-blue-500 cursor-pointer"
                >
                  {servers.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Target Tool</label>
                <select
                  value={selectedToolName}
                  onChange={(e) => handleToolChange(e.target.value)}
                  className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-blue-500 font-mono cursor-pointer"
                >
                  {availableTools.map((t) => (
                    <option key={t.id} value={t.name}>
                      {t.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Optional Destination */}
            <div>
              <label className="block text-slate-300 font-medium mb-1">
                Intended Destination (For Export / Transfers)
              </label>
              <input
                type="text"
                value={destination}
                onChange={(e) => setDestination(e.target.value)}
                placeholder="e.g. https://attacker-exfil.cc/drop or https://compliance-vault.internal.corp"
                className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* Arguments Editor */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-slate-300 font-medium">Tool Call Arguments (JSON)</label>
                <button
                  type="button"
                  onClick={() => handleToolChange(selectedToolName)}
                  className="text-[11px] text-cyan-400 hover:underline cursor-pointer"
                >
                  Reset Template
                </button>
              </div>
              <textarea
                rows={6}
                value={argsJson}
                onChange={(e) => setArgsJson(e.target.value)}
                className="w-full bg-black/60 border border-slate-700 rounded-lg p-2.5 text-cyan-300 font-mono text-xs focus:outline-none focus:border-blue-500 scrollbar-thin scrollbar-thumb-slate-800"
              />
            </div>

            {/* Direct Bypass Simulation Checkbox */}
            <div className="p-2.5 rounded bg-red-950/20 border border-red-900/40 flex items-center gap-2">
              <input
                type="checkbox"
                id="bypassToggle"
                checked={bypassGateway}
                onChange={(e) => setBypassGateway(e.target.checked)}
                className="rounded bg-slate-800 border-slate-700 text-red-500 focus:ring-0"
              />
              <label htmlFor="bypassToggle" className="text-[11px] text-red-300 cursor-pointer font-semibold">
                Simulate Direct Gateway Bypass (Circumvent Sentinel mediation)
              </label>
            </div>

            {/* Submit Button */}
            <button
              onClick={handleRunEvaluation}
              disabled={isEvaluating}
              className="w-full py-2.5 px-4 text-xs font-semibold rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white flex items-center justify-center gap-2 shadow-lg shadow-blue-900/30 cursor-pointer transition-all disabled:opacity-50"
            >
              {isEvaluating ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Evaluating Gateway Pipeline...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Submit Request to Gateway</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right: Security Decision & Inspection Results */}
        <div className="lg:col-span-7 space-y-4">
          {evalResult ? (
            <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4 animate-in fade-in duration-300">
              {/* Verdict Header */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400 font-mono">GATEWAY DECISION:</span>
                    <span
                      className={`text-sm font-mono font-bold px-3 py-1 rounded ${
                        evalResult.decision === 'ALLOW'
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          : evalResult.decision === 'SANITIZE_AND_ALLOW'
                          ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                          : evalResult.decision === 'REQUIRE_APPROVAL'
                          ? 'bg-amber-950 text-amber-400 border border-amber-800'
                          : 'bg-red-950 text-red-400 border border-red-800'
                      }`}
                    >
                      {evalResult.decision}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{evalResult.executionEvidence}</p>
                </div>

                <div className="text-right">
                  <div className="text-xs text-slate-400 font-mono">Risk Score</div>
                  <div className={`text-2xl font-bold font-mono ${
                    evalResult.riskScore >= 70 ? 'text-red-400' : evalResult.riskScore >= 40 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {evalResult.riskScore}<span className="text-xs text-slate-500">/100</span>
                  </div>
                </div>
              </div>

              {/* Status Pills */}
              <div className="grid grid-cols-3 gap-3 text-xs font-mono">
                <div className="p-2.5 rounded bg-black/40 border border-slate-800">
                  <span className="text-slate-400 text-[10px]">TOOL EXECUTION:</span>
                  <div className={`font-bold mt-0.5 ${evalResult.toolExecuted ? 'text-emerald-400' : 'text-red-400'}`}>
                    {evalResult.toolExecuted ? 'EXECUTED' : 'BLOCKED'}
                  </div>
                </div>

                <div className="p-2.5 rounded bg-black/40 border border-slate-800">
                  <span className="text-slate-400 text-[10px]">OUTBOUND EXFILTRATION:</span>
                  <div className={`font-bold mt-0.5 ${evalResult.dataExfiltrated ? 'text-red-400' : 'text-emerald-400'}`}>
                    {evalResult.dataExfiltrated ? 'LEAKED' : '0 BYTES (PREVENTED)'}
                  </div>
                </div>

                <div className="p-2.5 rounded bg-black/40 border border-slate-800">
                  <span className="text-slate-400 text-[10px]">AUDIT EVENT ID:</span>
                  <div className="text-cyan-400 font-bold mt-0.5">
                    {evalResult.auditEventId || 'LOGGED'}
                  </div>
                </div>
              </div>

              {/* Risk Factors Breakdown */}
              {evalResult.riskFactors?.length > 0 && (
                <div className="space-y-1.5">
                  <h3 className="text-xs font-bold text-slate-300">Contributing Risk Factors:</h3>
                  <div className="space-y-1">
                    {evalResult.riskFactors.map((rf: string, idx: number) => (
                      <div key={idx} className="text-xs text-amber-300/90 flex items-center gap-1.5 font-mono">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                        <span>{rf}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Sanitized Tool Output Preview */}
              {evalResult.sanitizedOutput && (
                <div className="space-y-1.5 pt-2 border-t border-slate-800">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-300">Sanitized Tool Response Output:</span>
                    {evalResult.sensitiveFindings?.length > 0 && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                        {evalResult.sensitiveFindings.length} Secret(s) Redacted in flight
                      </span>
                    )}
                  </div>
                  <pre className="p-3 rounded-lg bg-black/60 border border-slate-800 font-mono text-xs text-emerald-300 max-h-48 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800">
                    {typeof evalResult.sanitizedOutput === 'string'
                      ? evalResult.sanitizedOutput
                      : JSON.stringify(evalResult.sanitizedOutput, null, 2)}
                  </pre>
                </div>
              )}

              {/* Remediation reason if denied */}
              {evalResult.remediationReason && (
                <div className="p-3 rounded-lg bg-red-950/20 border border-red-800/40 text-xs text-red-300 space-y-1">
                  <span className="font-bold">Policy Remediation Advice:</span>
                  <p>{evalResult.remediationReason}</p>
                </div>
              )}
            </div>
          ) : (
            <div className="p-10 rounded-xl bg-[#0F172A] border border-slate-800 flex flex-col items-center justify-center text-center text-slate-400 space-y-3 min-h-[360px]">
              <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400">
                <Radio className="w-6 h-6 text-blue-400 animate-pulse" />
              </div>
              <h3 className="text-sm font-bold text-slate-200">Gateway Interceptor Ready</h3>
              <p className="text-xs text-slate-400 max-w-sm">
                Choose a tool and adjust its arguments. The gateway resolves your identity and role from your authenticated session.
              </p>
            </div>
          )}

          {/* Live Recent Stream */}
          <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-3">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
              Live Gateway Request Log (Recent Invocations)
            </h3>
            <div className="divide-y divide-slate-800/60 max-h-56 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800">
              {recentRequests.slice(0, 8).map((req) => (
                <div key={req.id} className="py-2 flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                        req.decision === 'ALLOW' || req.decision === 'SANITIZE_AND_ALLOW'
                          ? 'bg-emerald-950 text-emerald-400'
                          : req.decision === 'REQUIRE_APPROVAL'
                          ? 'bg-amber-950 text-amber-400'
                          : 'bg-red-950 text-red-400'
                      }`}
                    >
                      {req.decision}
                    </span>
                    <span className="text-slate-300 font-bold">{req.toolName}</span>
                    <span className="text-slate-500">by {req.actorRole}</span>
                  </div>
                  <span className="text-slate-500 text-[11px]">
                    {new Date(req.createdAt).toLocaleTimeString()}
                  </span>
                </div>
              ))}
              {recentRequests.length === 0 && (
                <p className="py-3 text-xs text-slate-500 text-center">No requests recorded yet.</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
