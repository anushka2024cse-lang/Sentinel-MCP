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
  SystemStats
} from '../types/index.js';

export const api = {
  // Stats
  async getStats(): Promise<SystemStats> {
    const res = await fetch('/api/stats');
    if (!res.ok) throw new Error('Failed to fetch stats');
    return res.json();
  },

  // Servers
  async getServers(): Promise<MCPServer[]> {
    const res = await fetch('/api/servers');
    if (!res.ok) throw new Error('Failed to fetch servers');
    return res.json();
  },

  async registerServer(data: Partial<MCPServer>): Promise<MCPServer> {
    const res = await fetch('/api/servers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error('Failed to register server');
    return res.json();
  },

  async toggleServerTrust(id: string): Promise<MCPServer> {
    const res = await fetch(`/api/servers/${id}/toggle-trust`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to toggle server trust');
    return res.json();
  },

  async quarantineServer(id: string): Promise<MCPServer> {
    const res = await fetch(`/api/servers/${id}/quarantine`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to quarantine server');
    return res.json();
  },

  // Tools
  async getTools(): Promise<MCPTool[]> {
    const res = await fetch('/api/tools');
    if (!res.ok) throw new Error('Failed to fetch tools');
    return res.json();
  },

  async tamperTool(id: string): Promise<MCPTool> {
    const res = await fetch(`/api/tools/${id}/tamper`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to tamper tool');
    return res.json();
  },

  async restoreTool(id: string): Promise<MCPTool> {
    const res = await fetch(`/api/tools/${id}/restore`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to restore tool');
    return res.json();
  },

  // Policies
  async getPolicies(): Promise<SecurityPolicy[]> {
    const res = await fetch('/api/policies');
    if (!res.ok) throw new Error('Failed to fetch policies');
    return res.json();
  },

  async createPolicy(data: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
    const res = await fetch('/api/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error('Failed to create policy');
    return res.json();
  },

  async updatePolicy(id: string, updates: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
    const res = await fetch(`/api/policies/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates)
    });
    if (!res.ok) throw new Error('Failed to update policy');
    return res.json();
  },

  async togglePolicy(id: string): Promise<SecurityPolicy> {
    const res = await fetch(`/api/policies/${id}/toggle`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to toggle policy');
    return res.json();
  },

  // Gateway Evaluation
  async evaluateGateway(payload: {
    actorId?: string;
    actorRole?: string;
    serverId: string;
    toolName: string;
    arguments: Record<string, unknown>;
    destination?: string;
    bypassGateway?: boolean;
    tamperToolSchema?: boolean;
  }) {
    const res = await fetch('/api/gateway/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  // Approvals
  async getApprovals(): Promise<ApprovalRequest[]> {
    const res = await fetch('/api/approvals');
    if (!res.ok) throw new Error('Failed to fetch approvals');
    return res.json();
  },

  async decideApproval(id: string, decision: 'APPROVED' | 'DENIED', approverId: string, approverRole: string, reason?: string): Promise<ApprovalRequest> {
    const res = await fetch(`/api/approvals/${id}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, approverId, approverRole, reason })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to decide approval');
    }
    return res.json();
  },

  // Incidents
  async getIncidents(): Promise<SecurityIncident[]> {
    const res = await fetch('/api/incidents');
    if (!res.ok) throw new Error('Failed to fetch incidents');
    return res.json();
  },

  async updateIncident(id: string, updates: { status?: string; note?: string; author?: string; assignedTo?: string }): Promise<SecurityIncident> {
    const res = await fetch(`/api/incidents/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates)
    });
    if (!res.ok) throw new Error('Failed to update incident');
    return res.json();
  },

  // Audit Logs, Requests, Findings
  async getAuditLogs(): Promise<SecurityEvent[]> {
    const res = await fetch('/api/audit-logs');
    if (!res.ok) throw new Error('Failed to fetch audit logs');
    return res.json();
  },

  async getRequests(): Promise<SecurityRequest[]> {
    const res = await fetch('/api/requests');
    if (!res.ok) throw new Error('Failed to fetch requests');
    return res.json();
  },

  async getFindings(): Promise<SensitiveDataFinding[]> {
    const res = await fetch('/api/findings');
    if (!res.ok) throw new Error('Failed to fetch findings');
    return res.json();
  },

  // Test Runner
  async getScenarios(): Promise<SecurityTestScenario[]> {
    const res = await fetch('/api/tests/scenarios');
    if (!res.ok) throw new Error('Failed to fetch scenarios');
    return res.json();
  },

  async getTestRuns(): Promise<SecurityTestRun[]> {
    const res = await fetch('/api/tests/runs');
    if (!res.ok) throw new Error('Failed to fetch test runs');
    return res.json();
  },

  async runTest(scenarioId: string): Promise<SecurityTestRun> {
    const res = await fetch('/api/tests/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenarioId })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Test run failed');
    }
    return res.json();
  },

  async runAllTests(): Promise<SecurityTestRun[]> {
    const res = await fetch('/api/tests/run-all', { method: 'POST' });
    if (!res.ok) throw new Error('Batch test run failed');
    return res.json();
  },

  // Supply Chain Scanner
  async scanManifest(manifestJson: string | object) {
    const res = await fetch('/api/scanner/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ manifestJson })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Scan failed');
    }
    return res.json();
  },

  // Identities & Tokens
  async getIdentities(): Promise<IdentityProfile[]> {
    const res = await fetch('/api/identities');
    if (!res.ok) throw new Error('Failed to fetch identities');
    return res.json();
  },

  async generateEphemeralToken(identityId: string, durationMinutes = 60) {
    const res = await fetch('/api/identities/generate-token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identityId, durationMinutes })
    });
    if (!res.ok) throw new Error('Failed to generate token');
    return res.json();
  },

  // Reset
  async resetDemo(): Promise<void> {
    await fetch('/api/system/reset-demo', { method: 'POST' });
  }
};
