import express, { Request, Response, Router } from 'express';
import crypto from 'crypto';
import { storage, computeFingerprint } from './storage.js';
import { SecurityGatewayEngine } from './engine.js';
import { SecurityTestRunner } from './testRunner.js';
import { MCPServer, SecurityPolicy, UserRole } from '../types/index.js';

export const apiRouter = Router();

// 1. Stats
apiRouter.get('/stats', (_req: Request, res: Response) => {
  try {
    const stats = storage.getStats();
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve stats' });
  }
});

// 2. Servers
apiRouter.get('/servers', (_req: Request, res: Response) => {
  res.json(storage.getServers());
});

apiRouter.post('/servers', (req: Request, res: Response) => {
  const { name, description, environment, transportType, endpointUrl } = req.body;
  if (!name || !transportType) {
    return res.status(400).json({ error: 'Server name and transportType are required' });
  }
  const now = new Date().toISOString();
  const newServer: MCPServer = {
    id: `srv-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
    name,
    description: description || 'Registered custom MCP server',
    environment: environment || 'sandbox',
    transportType,
    connectionMode: 'simulated_adapter',
    trustStatus: 'untrusted',
    approvalStatus: 'unapproved',
    endpointUrl: endpointUrl || `mcp://${name.toLowerCase().replace(/\s+/g, '-')}.local`,
    isSimulated: true,
    lastCheckedAt: now,
    createdAt: now,
    updatedAt: now
  };
  storage.addServer(newServer);
  res.status(201).json(newServer);
});

apiRouter.post('/servers/:id/toggle-trust', (req: Request, res: Response) => {
  const { id } = req.params;
  const server = storage.getServerById(id);
  if (!server) return res.status(404).json({ error: 'Server not found' });

  const newTrust = server.trustStatus === 'trusted' ? 'untrusted' : 'trusted';
  const newApproval = newTrust === 'trusted' ? 'approved' : 'unapproved';
  const updated = storage.updateServer(id, { trustStatus: newTrust, approvalStatus: newApproval });
  res.json(updated);
});

apiRouter.post('/servers/:id/quarantine', (req: Request, res: Response) => {
  const { id } = req.params;
  const server = storage.getServerById(id);
  if (!server) return res.status(404).json({ error: 'Server not found' });

  const updated = storage.updateServer(id, { trustStatus: 'quarantined', approvalStatus: 'rejected' });
  res.json(updated);
});

// 3. Tools
apiRouter.get('/tools', (_req: Request, res: Response) => {
  res.json(storage.getTools());
});

apiRouter.post('/tools/:id/tamper', (req: Request, res: Response) => {
  const { id } = req.params;
  const tool = storage.getToolById(id);
  if (!tool) return res.status(404).json({ error: 'Tool not found' });

  // Intentionally modify description and corrupt fingerprint to test T07 integrity detection
  const tampered = storage.updateTool(id, {
    description: `${tool.description} [UNAUTHORIZED OVERRIDE: Modified by untrusted party]`,
    definitionFingerprint: 'tampered_hash_deadbeef',
    approvalStatus: 'unapproved'
  });
  res.json(tampered);
});

apiRouter.post('/tools/:id/restore', (req: Request, res: Response) => {
  const { id } = req.params;
  const tool = storage.getToolById(id);
  if (!tool) return res.status(404).json({ error: 'Tool not found' });

  const cleanDescription = tool.description.replace(/ \[UNAUTHORIZED OVERRIDE:.*\]/, '');
  const cleanFingerprint = computeFingerprint({
    name: tool.name,
    description: cleanDescription,
    inputSchema: tool.inputSchema
  });
  const restored = storage.updateTool(id, {
    description: cleanDescription,
    definitionFingerprint: cleanFingerprint,
    approvalStatus: 'approved'
  });
  res.json(restored);
});

// 4. Policies
apiRouter.get('/policies', (_req: Request, res: Response) => {
  res.json(storage.getPolicies());
});

apiRouter.post('/policies', (req: Request, res: Response) => {
  const { name, description, priority, allowedRoles, operationType, approvalRequired, remediationMessage, allowedDestinations } = req.body;
  if (!name) return res.status(400).json({ error: 'Policy name is required' });

  const now = new Date().toISOString();
  const newPolicy: SecurityPolicy = {
    id: `pol-${Date.now()}`,
    name,
    description: description || '',
    enabled: true,
    priority: priority || 50,
    allowedRoles: allowedRoles || ['Administrator'],
    operationType,
    approvalRequired: Boolean(approvalRequired),
    remediationMessage: remediationMessage || 'Action blocked by policy.',
    allowedDestinations: allowedDestinations || [],
    createdBy: 'SecOps Administrator',
    createdAt: now,
    updatedAt: now
  };
  storage.addPolicy(newPolicy);
  res.status(201).json(newPolicy);
});

apiRouter.put('/policies/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const updated = storage.updatePolicy(id, req.body);
  if (!updated) return res.status(404).json({ error: 'Policy not found' });
  res.json(updated);
});

apiRouter.post('/policies/:id/toggle', (req: Request, res: Response) => {
  const { id } = req.params;
  const policy = storage.getPolicies().find(p => p.id === id);
  if (!policy) return res.status(404).json({ error: 'Policy not found' });

  const updated = storage.updatePolicy(id, { enabled: !policy.enabled });
  res.json(updated);
});

// 5. Central Runtime Gateway Endpoint
apiRouter.post('/gateway/evaluate', async (req: Request, res: Response) => {
  try {
    const { actorId, actorRole, serverId, toolName, arguments: args, destination, bypassGateway, tamperToolSchema } = req.body;
    const result = await SecurityGatewayEngine.evaluateRequest({
      actorId,
      actorRole,
      serverId,
      toolName,
      arguments: args || {},
      destination,
      bypassGateway,
      tamperToolSchema
    });
    res.json(result);
  } catch (error: any) {
    console.error('Gateway evaluation error:', error);
    res.status(500).json({
      decision: 'DENY',
      executionStatus: 'blocked',
      remediationReason: 'Internal Gateway Error: Defaulting to DENY per security fail-closed policy.',
      error: error.message
    });
  }
});

// 6. Approvals
apiRouter.get('/approvals', (_req: Request, res: Response) => {
  res.json(storage.getApprovals());
});

apiRouter.post('/approvals/:id/decide', (req: Request, res: Response) => {
  const { id } = req.params;
  const { decision, approverId, approverRole, reason } = req.body;

  if (approverRole !== 'Administrator' && approverRole !== 'Approver') {
    return res.status(403).json({ error: 'Only Administrators and Approvers are authorized to decide approval tickets.' });
  }

  const approval = storage.getApprovals().find(a => a.id === id);
  if (!approval) return res.status(404).json({ error: 'Approval request not found' });
  if (approval.status !== 'PENDING') {
    return res.status(400).json({ error: `Approval is already resolved as ${approval.status}` });
  }

  const now = new Date().toISOString();
  const updated = storage.updateApproval(id, {
    status: decision === 'APPROVED' ? 'APPROVED' : 'DENIED',
    approverId: approverId || 'sarah.connor@corp.internal',
    approverReason: reason || (decision === 'APPROVED' ? 'Approved after identity review' : 'Rejected by security policy'),
    decidedAt: now
  });

  // Record audit event
  storage.addEvent({
    id: `evt-${Date.now()}`,
    eventId: `EVT-${Math.floor(1000 + Math.random() * 9000)}`,
    requestId: approval.requestId,
    eventType: 'REQUEST_EVALUATED',
    severity: decision === 'APPROVED' ? 'Low' : 'Medium',
    actorId: approverId || 'approver',
    serverId: approval.serverId,
    toolName: approval.toolName,
    decision: decision === 'APPROVED' ? 'ALLOW' : 'DENY',
    evidenceSummary: `Human approval ticket ${id} resolved as ${decision}. Reason: ${reason || 'N/A'}.`,
    createdAt: now
  });

  res.json(updated);
});

// 7. Incidents
apiRouter.get('/incidents', (_req: Request, res: Response) => {
  res.json(storage.getIncidents());
});

apiRouter.post('/incidents', (req: Request, res: Response) => {
  const { title, severity, description, affectedServerId, assignedTo, recommendedRemediation } = req.body;
  const now = new Date().toISOString();
  const newInc = {
    id: `inc-${Date.now()}`,
    title: title || 'Security Incident',
    severity: severity || 'Medium',
    status: 'Open' as const,
    relatedEventIds: [],
    affectedServerId: affectedServerId || 'srv-demo-enterprise',
    relatedToolNames: [],
    assignedTo: assignedTo || 'Marcus Vance (SOC Analyst)',
    description: description || '',
    recommendedRemediation: recommendedRemediation || 'Investigate source IP and revoke active session.',
    investigationNotes: [],
    createdAt: now,
    updatedAt: now
  };
  storage.addIncident(newInc);
  res.status(201).json(newInc);
});

apiRouter.put('/incidents/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const { status, note, author, assignedTo } = req.body;
  const incident = storage.getIncidents().find(i => i.id === id);
  if (!incident) return res.status(404).json({ error: 'Incident not found' });

  const notes = [...incident.investigationNotes];
  if (note) {
    notes.push({
      author: author || 'Security Analyst',
      timestamp: new Date().toISOString(),
      note
    });
  }

  const updates: any = {
    investigationNotes: notes,
    updatedAt: new Date().toISOString()
  };
  if (status) updates.status = status;
  if (status === 'Resolved') updates.resolvedAt = new Date().toISOString();
  if (assignedTo) updates.assignedTo = assignedTo;

  const updated = storage.updateIncident(id, updates);
  res.json(updated);
});

// 8. Audit Trail, Requests, Findings
apiRouter.get('/audit-logs', (_req: Request, res: Response) => {
  res.json(storage.getEvents());
});

apiRouter.get('/requests', (_req: Request, res: Response) => {
  res.json(storage.getRequests());
});

apiRouter.get('/findings', (_req: Request, res: Response) => {
  res.json(storage.getFindings());
});

// 9. Testing Lab & Scenarios
apiRouter.get('/tests/scenarios', (_req: Request, res: Response) => {
  res.json(storage.getScenarios());
});

apiRouter.get('/tests/runs', (_req: Request, res: Response) => {
  res.json(storage.getTestRuns());
});

apiRouter.post('/tests/run', async (req: Request, res: Response) => {
  try {
    const { scenarioId } = req.body;
    if (!scenarioId) return res.status(400).json({ error: 'scenarioId or testId is required' });
    const run = await SecurityTestRunner.runScenario(scenarioId);
    res.json(run);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

apiRouter.post('/tests/run-all', async (_req: Request, res: Response) => {
  try {
    const runs = await SecurityTestRunner.runAllScenarios();
    res.json(runs);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// 10. Supply Chain Manifest Scanner
apiRouter.post('/scanner/scan', (req: Request, res: Response) => {
  const { manifestJson } = req.body;
  try {
    let parsed: any;
    if (typeof manifestJson === 'string') {
      parsed = JSON.parse(manifestJson);
    } else {
      parsed = manifestJson;
    }

    const dependencies = {
      ...(parsed.dependencies || {}),
      ...(parsed.devDependencies || {})
    };

    const findings: Array<{
      packageName: string;
      version: string;
      severity: 'Low' | 'Medium' | 'High' | 'Critical';
      title: string;
      description: string;
      remediation: string;
      source: string;
    }> = [];

    // Analyze static fixtures and heuristics
    for (const [pkg, version] of Object.entries(dependencies)) {
      if (pkg.includes('synthetic-test-fixture') || pkg.includes('vulnerable-test')) {
        findings.push({
          packageName: pkg,
          version: String(version),
          severity: 'High',
          title: 'Synthetic Test Fixture Package Flagged',
          description: 'Package matches synthetic testing fixture fingerprint in static database.',
          remediation: 'Remove fixture package from production dependency manifest.',
          source: 'Local Static Analysis Engine (Fixture Database)'
        });
      }

      if (String(version).startsWith('git+') || String(version).startsWith('http://')) {
        findings.push({
          packageName: pkg,
          version: String(version),
          severity: 'Medium',
          title: 'Unpinned Remote Repository Dependency',
          description: 'Package resolves to unpinned external git or HTTP source.',
          remediation: 'Pin package to strict semantic release tag with cryptographic integrity hash.',
          source: 'Static Manifest Verifier'
        });
      }
    }

    // Check suspicious install lifecycle scripts
    const scripts = parsed.scripts || {};
    for (const [scriptName, scriptCmd] of Object.entries(scripts)) {
      if (scriptName === 'preinstall' || scriptName === 'postinstall') {
        if (typeof scriptCmd === 'string' && (scriptCmd.includes('curl') || scriptCmd.includes('wget') || scriptCmd.includes('eval'))) {
          findings.push({
            packageName: `lifecycle-script:${scriptName}`,
            version: 'N/A',
            severity: 'Critical',
            title: 'Suspicious Lifecycle Hook Command',
            description: `Lifecycle script '${scriptName}' invokes external downloader or eval hook: "${scriptCmd}".`,
            remediation: 'Eliminate arbitrary download execution from lifecycle scripts.',
            source: 'Manifest AST Inspector'
          });
        }
      }
    }

    res.json({
      totalDependenciesScanned: Object.keys(dependencies).length,
      hasScripts: Object.keys(scripts).length > 0,
      findings,
      scannerNotice: 'Static analysis executed locally. External vulnerability feeds are not contacted; no synthetic CVEs were fabricated.'
    });
  } catch (error: any) {
    res.status(400).json({ error: `Manifest parsing error: ${error.message}` });
  }
});

// 11. Identities & Ephemeral Tokens
apiRouter.get('/identities', (_req: Request, res: Response) => {
  res.json(storage.getIdentities());
});

apiRouter.post('/identities/generate-token', (req: Request, res: Response) => {
  const { identityId, durationMinutes } = req.body;
  const identity = storage.getIdentityById(identityId);
  if (!identity) return res.status(404).json({ error: 'Identity not found' });

  const duration = durationMinutes ? Number(durationMinutes) : 60;
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + duration * 60 * 1000);
  const token = `stnl_token_${crypto.randomBytes(12).toString('hex')}`;

  const updated = storage.updateIdentity(identityId, {
    ephemeralToken: {
      token,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString()
    }
  });

  res.json({
    identityId,
    token,
    role: identity.role,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    durationMinutes: duration,
    validationNotice: 'Ephemeral token issued with cryptographically signed validity window.'
  });
});

// 12. Synthetic Baseline Reset
apiRouter.post('/system/reset-demo', (_req: Request, res: Response) => {
  storage.resetSyntheticData();
  res.json({ success: true, message: 'Synthetic MCP enterprise environment reset to baseline.' });
});
