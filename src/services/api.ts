import {
  MCPServer,
  MCPTool,
  SecurityPolicy,
  SecurityRequest,
  SecurityEvent,
  SensitiveDataFinding,
  ApprovalRequest,
  SecurityIncident,
  SecurityTestScenario,
  SecurityTestRun,
  IdentityProfile,
  SystemStats,
  GatewaySettings
} from '../types/index.js';

const ACCESS_TOKEN_KEY = 'sentinel-api-token';

export interface ApiSession {
  subject: string;
  role: 'Administrator' | 'Security Analyst' | 'Approver' | 'Read-only Auditor';
}

function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const token = sessionStorage.getItem(ACCESS_TOKEN_KEY);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  return fetch(input, { ...init, headers });
}

async function responseError(response: Response, fallback: string): Promise<Error> {
  const body = await response.json().catch(() => undefined);
  return new Error(typeof body?.error === 'string' ? body.error : fallback);
}

export const api = {
  setAccessToken(token: string): void {
    sessionStorage.setItem(ACCESS_TOKEN_KEY, token);
  },

  clearAccessToken(): void {
    sessionStorage.removeItem(ACCESS_TOKEN_KEY);
  },

  async getSession(): Promise<ApiSession> {
    const res = await apiFetch('/api/auth/session');
    if (!res.ok) throw await responseError(res, 'Authentication failed');
    return res.json();
  },

  async getSettings(): Promise<GatewaySettings> {
    const res = await apiFetch('/api/settings');
    if (!res.ok) throw await responseError(res, 'Failed to fetch system settings');
    return res.json();
  },

  async updateSettings(updates: Pick<GatewaySettings, 'maxPayloadMb' | 'anomalyThreshold'>): Promise<GatewaySettings> {
    const res = await apiFetch('/api/settings', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates)
    });
    if (!res.ok) throw await responseError(res, 'Failed to save system settings');
    return res.json();
  },

  // Stats
  async getStats(): Promise<SystemStats> {
    const res = await apiFetch('/api/stats');
    if (!res.ok) throw new Error('Failed to fetch stats');
    return res.json();
  },

  // Servers
  async getServers(): Promise<MCPServer[]> {
    const res = await apiFetch('/api/servers');
    if (!res.ok) throw new Error('Failed to fetch servers');
    return res.json();
  },

  async registerServer(data: Partial<MCPServer>): Promise<MCPServer> {
    const res = await apiFetch('/api/servers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw await responseError(res, 'Failed to register server');
    return res.json();
  },

  async discoverMcpTools(id: string): Promise<{ server: MCPServer; tools: MCPTool[] }> {
    const res = await apiFetch(`/api/servers/${id}/discover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    if (!res.ok) throw await responseError(res, 'MCP tool discovery failed');
    return res.json();
  },

  async toggleServerTrust(id: string): Promise<MCPServer> {
    const res = await apiFetch(`/api/servers/${id}/toggle-trust`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to toggle server trust');
    return res.json();
  },

  async quarantineServer(id: string): Promise<MCPServer> {
    const res = await apiFetch(`/api/servers/${id}/quarantine`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to quarantine server');
    return res.json();
  },

  // Tools
  async getTools(): Promise<MCPTool[]> {
    const res = await apiFetch('/api/tools');
    if (!res.ok) throw new Error('Failed to fetch tools');
    return res.json();
  },

  async tamperTool(id: string): Promise<MCPTool> {
    const res = await apiFetch(`/api/tools/${id}/tamper`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to tamper tool');
    return res.json();
  },

  async restoreTool(id: string): Promise<MCPTool> {
    const res = await apiFetch(`/api/tools/${id}/restore`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to restore tool');
    return res.json();
  },

  async approveMcpTool(
    id: string,
    configuration: Pick<MCPTool, 'capabilityType' | 'allowedRoles' | 'approvalRequirements'>
  ): Promise<MCPTool> {
    const res = await apiFetch(`/api/tools/${id}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(configuration)
    });
    if (!res.ok) throw await responseError(res, 'Failed to approve MCP tool definition');
    return res.json();
  },

  // Policies
  async getPolicies(): Promise<SecurityPolicy[]> {
    const res = await apiFetch('/api/policies');
    if (!res.ok) throw new Error('Failed to fetch policies');
    return res.json();
  },

  async createPolicy(data: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
    const res = await apiFetch('/api/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error('Failed to create policy');
    return res.json();
  },

  async updatePolicy(id: string, updates: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
    const res = await apiFetch(`/api/policies/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates)
    });
    if (!res.ok) throw new Error('Failed to update policy');
    return res.json();
  },

  async togglePolicy(id: string): Promise<SecurityPolicy> {
    const res = await apiFetch(`/api/policies/${id}/toggle`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to toggle policy');
    return res.json();
  },

  // Gateway Evaluation
  async evaluateGateway(payload: {
    serverId: string;
    toolName: string;
    arguments: Record<string, unknown>;
    destination?: string;
    bypassGateway?: boolean;
    tamperToolSchema?: boolean;
  }) {
    const res = await apiFetch('/api/gateway/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw await responseError(res, 'Gateway evaluation failed');
    return res.json();
  },

  // Approvals
  async getApprovals(): Promise<ApprovalRequest[]> {
    const res = await apiFetch('/api/approvals');
    if (!res.ok) throw new Error('Failed to fetch approvals');
    return res.json();
  },

  async decideApproval(id: string, decision: 'APPROVED' | 'DENIED', reason?: string): Promise<ApprovalRequest> {
    const res = await apiFetch(`/api/approvals/${id}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, reason })
    });
    if (!res.ok) throw await responseError(res, 'Failed to decide approval');
    return res.json();
  },

  // Incidents
  async getIncidents(): Promise<SecurityIncident[]> {
    const res = await apiFetch('/api/incidents');
    if (!res.ok) throw new Error('Failed to fetch incidents');
    return res.json();
  },

  async getIncidentDetails(id: string): Promise<{
    incident: SecurityIncident;
    server: MCPServer | null;
    tools: MCPTool[];
    requests: Omit<SecurityRequest, 'arguments' | 'sanitizedOutput'>[];
    events: SecurityEvent[];
    policies: Pick<SecurityPolicy, 'id' | 'name' | 'description' | 'enabled' | 'updatedAt'>[];
  }> {
    const res = await apiFetch(`/api/incidents/${id}`);
    if (!res.ok) throw await responseError(res, 'Failed to fetch incident evidence');
    return res.json();
  },

  async updateIncident(id: string, updates: { note: string; assignedTo?: string }): Promise<SecurityIncident> {
    const res = await apiFetch(`/api/incidents/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates)
    });
    if (!res.ok) throw await responseError(res, 'Failed to update incident');
    return res.json();
  },

  async investigateIncident(id: string, note: string): Promise<SecurityIncident> {
    const res = await apiFetch(`/api/incidents/${id}/investigate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note })
    });
    if (!res.ok) throw await responseError(res, 'Failed to start incident investigation');
    return res.json();
  },

  async containIncident(id: string, reason: string): Promise<SecurityIncident> {
    const res = await apiFetch(`/api/incidents/${id}/contain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason })
    });
    if (!res.ok) throw await responseError(res, 'Failed to contain incident');
    return res.json();
  },

  async resolveIncident(id: string, details: string): Promise<SecurityIncident> {
    const res = await apiFetch(`/api/incidents/${id}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ details })
    });
    if (!res.ok) throw await responseError(res, 'Failed to resolve incident');
    return res.json();
  },

  async releaseIncidentContainment(id: string, reason: string): Promise<SecurityIncident> {
    const res = await apiFetch(`/api/incidents/${id}/release-containment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason })
    });
    if (!res.ok) throw await responseError(res, 'Failed to release incident containment');
    return res.json();
  },

  // Audit Logs, Requests, Findings
  async getAuditLogs(): Promise<SecurityEvent[]> {
    const res = await apiFetch('/api/audit-logs');
    if (!res.ok) throw new Error('Failed to fetch audit logs');
    return res.json();
  },

  async getRequests(): Promise<SecurityRequest[]> {
    const res = await apiFetch('/api/requests');
    if (!res.ok) throw new Error('Failed to fetch requests');
    return res.json();
  },

  async getFindings(): Promise<SensitiveDataFinding[]> {
    const res = await apiFetch('/api/findings');
    if (!res.ok) throw new Error('Failed to fetch findings');
    return res.json();
  },

  // Test Runner
  async getScenarios(): Promise<SecurityTestScenario[]> {
    const res = await apiFetch('/api/tests/scenarios');
    if (!res.ok) throw new Error('Failed to fetch scenarios');
    return res.json();
  },

  async getTestRuns(): Promise<SecurityTestRun[]> {
    const res = await apiFetch('/api/tests/runs');
    if (!res.ok) throw new Error('Failed to fetch test runs');
    return res.json();
  },

  async runTest(scenarioId: string): Promise<SecurityTestRun> {
    const res = await apiFetch('/api/tests/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenarioId })
    });
    if (!res.ok) throw await responseError(res, 'Test run failed');
    return res.json();
  },

  async runAllTests(): Promise<SecurityTestRun[]> {
    const res = await apiFetch('/api/tests/run-all', { method: 'POST' });
    if (!res.ok) throw new Error('Batch test run failed');
    return res.json();
  },

  // Supply Chain Scanner
  async scanManifest(manifestJson: string | object) {
    const res = await apiFetch('/api/scanner/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ manifestJson })
    });
    if (!res.ok) throw await responseError(res, 'Scan failed');
    return res.json();
  },

  // Identities & Tokens
  async getIdentities(): Promise<IdentityProfile[]> {
    const res = await apiFetch('/api/identities');
    if (!res.ok) throw new Error('Failed to fetch identities');
    return res.json();
  },

  // Reset
  async resetDemo(): Promise<void> {
    const res = await apiFetch('/api/system/reset-demo', { method: 'POST' });
    if (!res.ok) throw await responseError(res, 'Failed to reset demo data');
  }
};
