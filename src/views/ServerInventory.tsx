import React, { useState } from 'react';
import {
  Server,
  ShieldCheck,
  ShieldAlert,
  Plus,
  AlertTriangle,
  Radio,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Wrench
} from 'lucide-react';
import { MCPServer, MCPTool, UserRole } from '../types/index.js';
import { api } from '../services/api.js';

interface ServerInventoryProps {
  servers: MCPServer[];
  tools: MCPTool[];
  currentRole: UserRole;
  onRefresh: () => void;
  onSelectToolView: (serverId?: string) => void;
}

export const ServerInventory: React.FC<ServerInventoryProps> = ({
  servers,
  tools,
  currentRole,
  onRefresh,
  onSelectToolView
}) => {
  const [isRegisterOpen, setIsRegisterOpen] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [transportType, setTransportType] = useState<'stdio' | 'sse' | 'stream' | 'websocket'>('stdio');
  const [environment, setEnvironment] = useState<'production' | 'staging' | 'sandbox'>('production');
  const [connectionMode, setConnectionMode] = useState<'simulated_adapter' | 'live_mcp_proxy'>('simulated_adapter');
  const [endpointUrl, setEndpointUrl] = useState('');
  const [search, setSearch] = useState('');
  const [discoveringId, setDiscoveringId] = useState<string | null>(null);

  const isAdmin = currentRole === 'Administrator';

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    try {
      await api.registerServer({
        name,
        description,
        transportType: connectionMode === 'live_mcp_proxy' ? 'stream' : transportType,
        environment,
        endpointUrl,
        connectionMode,
        isSimulated: connectionMode !== 'live_mcp_proxy'
      });
      setIsRegisterOpen(false);
      setName('');
      setDescription('');
      onRefresh();
    } catch (err: any) {
      alert(`Registration error: ${err.message}`);
    }
  };

  const handleDiscoverTools = async (server: MCPServer) => {
    setDiscoveringId(server.id);
    try {
      const result = await api.discoverMcpTools(server.id);
      alert(`Discovered ${result.tools.length} tools. Each definition remains blocked until reviewed and explicitly approved.`);
      onRefresh();
    } catch (err: any) {
      alert(`MCP discovery failed: ${err.message}`);
    } finally {
      setDiscoveringId(null);
    }
  };

  const handleToggleTrust = async (id: string) => {
    try {
      await api.toggleServerTrust(id);
      onRefresh();
    } catch (err: any) {
      alert(`Error updating trust: ${err.message}`);
    }
  };

  const handleQuarantine = async (id: string) => {
    if (!confirm('Are you sure you want to quarantine this MCP server? All incoming tool requests will be immediately halted.')) return;
    try {
      await api.quarantineServer(id);
      onRefresh();
    } catch (err: any) {
      alert(`Error quarantining server: ${err.message}`);
    }
  };

  const filteredServers = servers.filter(s =>
    s.name.toLowerCase().includes(search.toLowerCase()) ||
    s.description.toLowerCase().includes(search.toLowerCase()) ||
    s.environment.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Server className="w-5 h-5 text-blue-400" />
            <span>MCP Server Discovery &amp; Inventory</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Centrally manage approved MCP server endpoints, transport bindings, and enforce strict server-side allowlists.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <input
            type="text"
            placeholder="Search servers..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="text-xs bg-[#111C30] border border-slate-700 rounded-lg px-3 py-1.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-48 sm:w-64"
          />
          {isAdmin && (
            <button
              onClick={() => setIsRegisterOpen(true)}
              className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-1.5 cursor-pointer shadow-md shadow-blue-900/30"
            >
              <Plus className="w-4 h-4" />
              <span>Register Server</span>
            </button>
          )}
        </div>
      </div>

      {/* Security Architecture Notice */}
      <div className="p-3.5 rounded-lg bg-[#0F172A] border border-slate-800 text-xs text-slate-400 flex items-start gap-2.5">
        <Radio className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-200">Execution mode:</span> Simulated adapters are local fixtures. Live MCP servers use Streamable HTTP and only dispatch through the authenticated gateway after server and tool approval.
        </div>
      </div>

      {/* Servers Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredServers.map((server) => {
          const serverTools = tools.filter(t => t.serverId === server.id);
          const isTrusted = server.trustStatus === 'trusted' && server.approvalStatus === 'approved';
          const isQuarantined = server.trustStatus === 'quarantined';

          return (
            <div
              key={server.id}
              className={`p-5 rounded-xl border flex flex-col justify-between transition-all ${
                isQuarantined
                  ? 'bg-red-950/10 border-red-800/40'
                  : isTrusted
                  ? 'bg-[#0F172A] border-slate-800 hover:border-slate-700'
                  : 'bg-amber-950/10 border-amber-800/40'
              }`}
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-sm text-slate-100">{server.name}</span>
                    </div>
                    <span className="font-mono text-[10px] text-slate-400">ID: {server.id}</span>
                  </div>

                  <span
                    className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold ${
                      isQuarantined
                        ? 'bg-red-950 text-red-400 border border-red-800'
                        : isTrusted
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : 'bg-amber-950 text-amber-400 border border-amber-800'
                    }`}
                  >
                    {isQuarantined ? 'QUARANTINED' : isTrusted ? 'TRUSTED' : 'UNTRUSTED'}
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed min-h-[38px]">
                  {server.description}
                </p>

                <div className="grid grid-cols-2 gap-2 text-[11px] pt-2 border-t border-slate-800/60 font-mono">
                  <div>
                    <span className="text-slate-400">Transport:</span>
                    <span className="text-slate-200 ml-1.5 uppercase">{server.transportType}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Env:</span>
                    <span className="text-slate-200 ml-1.5 capitalize">{server.environment}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Tools:</span>
                    <span className="text-cyan-400 font-bold ml-1.5">{serverTools.length} registered</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Adapter:</span>
                    <span className={`ml-1.5 ${server.connectionMode === 'live_mcp_proxy' ? 'text-emerald-300' : 'text-amber-300'}`}>
                      {server.connectionMode === 'live_mcp_proxy' ? 'Live MCP proxy' : 'Simulated'}
                    </span>
                  </div>
                </div>

                <div className="text-[11px] font-mono text-slate-400 truncate bg-black/30 p-1.5 rounded">
                  <span className="text-slate-400">Endpoint:</span> {server.endpointUrl}
                </div>
              </div>

              {/* Actions */}
              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between gap-2">
                <button
                  onClick={() => onSelectToolView(server.id)}
                  className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center gap-1 cursor-pointer"
                >
                  <Wrench className="w-3.5 h-3.5" />
                  <span>Inspect {serverTools.length} Tools</span>
                </button>

                {isAdmin && (
                  <div className="flex items-center gap-2">
                    {server.connectionMode === 'live_mcp_proxy' && (
                      <button
                        onClick={() => handleDiscoverTools(server)}
                        disabled={discoveringId === server.id}
                        className="px-2.5 py-1 text-[11px] font-medium rounded border border-cyan-800 bg-cyan-950/40 text-cyan-200 hover:bg-cyan-900/40 disabled:opacity-50"
                      >
                        {discoveringId === server.id ? 'Discovering…' : 'Discover tools'}
                      </button>
                    )}
                    <button
                      onClick={() => handleToggleTrust(server.id)}
                      className={`px-2.5 py-1 text-[11px] font-medium rounded border cursor-pointer transition-colors ${
                        isTrusted
                          ? 'bg-amber-950/40 text-amber-300 border-amber-800 hover:bg-amber-900/40'
                          : 'bg-emerald-950/40 text-emerald-300 border-emerald-800 hover:bg-emerald-900/40'
                      }`}
                      title={isTrusted ? 'Revoke trusted status' : 'Approve and trust server'}
                    >
                      {isTrusted ? 'Revoke Trust' : 'Approve Server'}
                    </button>

                    {!isQuarantined && (
                      <button
                        onClick={() => handleQuarantine(server.id)}
                        className="px-2.5 py-1 text-[11px] font-medium rounded bg-red-950/40 text-red-300 border border-red-800 hover:bg-red-900/40 cursor-pointer"
                        title="Isolate and block all traffic to server"
                      >
                        Quarantine
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Register Server Modal */}
      {isRegisterOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-[#0F172A] border border-slate-700 rounded-xl max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Server className="w-4 h-4 text-blue-400" />
                <span>Register New MCP Server</span>
              </h2>
              <button
                onClick={() => setIsRegisterOpen(false)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleRegister} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Execution Mode</label>
                <select
                  value={connectionMode}
                  onChange={(e) => {
                    const mode = e.target.value as 'simulated_adapter' | 'live_mcp_proxy';
                    setConnectionMode(mode);
                    if (mode === 'live_mcp_proxy') setTransportType('stream');
                  }}
                  className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                >
                  <option value="simulated_adapter">Simulation adapter</option>
                  <option value="live_mcp_proxy">Live MCP · Streamable HTTP</option>
                </select>
                <p className="mt-1 text-[11px] text-slate-500">
                  Live endpoints require HTTPS in production; development HTTP is restricted to loopback.
                </p>
              </div>
              <div>
                <label className="block text-slate-300 font-medium mb-1">Server Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Analytics Data MCP Service"
                  className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Description</label>
                <textarea
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Operational scope and exposed capabilities..."
                  className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Transport Type</label>
                  <select
                    value={transportType}
                    onChange={(e) => setTransportType(e.target.value as any)}
                    className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                  >
                    {connectionMode === 'live_mcp_proxy' ? (
                      <option value="stream">Streamable HTTP</option>
                    ) : (
                      <>
                        <option value="stdio">stdio (Simulation)</option>
                        <option value="sse">sse (Simulation)</option>
                        <option value="websocket">websocket (Simulation)</option>
                        <option value="stream">stream (Simulation)</option>
                      </>
                    )}
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Environment</label>
                  <select
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value as any)}
                    className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="sandbox">Sandbox</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Endpoint URI / Binding</label>
                <input
                  type="text"
                  value={endpointUrl}
                  onChange={(e) => setEndpointUrl(e.target.value)}
                  placeholder={connectionMode === 'live_mcp_proxy' ? 'https://mcp.example.com/mcp' : 'mcp://internal.corp/analytics/v1'}
                  className="w-full bg-[#111C30] border border-slate-700 rounded-lg p-2.5 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                  required={connectionMode === 'live_mcp_proxy'}
                />
              </div>

              <div className="pt-3 border-t border-slate-800 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsRegisterOpen(false)}
                  className="px-4 py-2 rounded-lg text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold cursor-pointer"
                >
                  Register Server
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
