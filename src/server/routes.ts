import express, { Request, Response, Router, RequestHandler } from 'express';
import crypto from 'crypto';
import { storage, computeFingerprint } from './storage.js';
import { ApprovalWorkflowError, SecurityGatewayEngine } from './engine.js';
import { SecurityTestRunner } from './testRunner.js';
import {
  createAuthenticationMiddleware,
  createAuthorizationMiddleware,
  hasConfiguredPrincipal,
  loadApiTokenConfig,
  requirePrincipal
} from './auth.js';
import { initializeApprovalEncryptionKey } from './approvalCrypto.js';
import { GatewaySettings, MCPServer, SecurityEvent, SecurityIncident, SecurityPolicy, UserRole } from '../types/index.js';
import {
  computeMcpToolFingerprint,
  discoverMcpTools,
  McpConnectionError,
  validateMcpEndpoint
} from './mcpClient.js';

export const apiRouter = Router();

const apiTokenConfig = loadApiTokenConfig(process.env);
initializeApprovalEncryptionKey();

function asyncRoute(handler: (req: Request, res: Response) => Promise<unknown>): RequestHandler {
  return (req, res, next) => {
    void handler(req, res).catch(error => {
      console.error('[SENTINEL-MCP] Persistent operation failed:', error);
      if (!res.headersSent) {
        res.status(500).json({ error: 'The operation could not be durably completed.' });
      } else {
        next(error);
      }
    });
  };
}

function validatePolicyInput(value: unknown): value is Partial<SecurityPolicy> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const input = value as Record<string, unknown>;
  const allowedFields = new Set([
    'name', 'description', 'enabled', 'priority', 'applicableServerId', 'applicableToolName',
    'allowedRoles', 'allowedDestinations', 'disallowedDestinations', 'operationType',
    'maxRiskScore', 'approvalRequired', 'denyConditions', 'remediationMessage'
  ]);
  if (Object.keys(input).some(key => !allowedFields.has(key))) return false;
  const stringLimits: Record<string, number> = {
    name: 128,
    description: 1000,
    applicableServerId: 128,
    applicableToolName: 128,
    remediationMessage: 1000
  };
  for (const [field, maximum] of Object.entries(stringLimits)) {
    if (field in input && (
      typeof input[field] !== 'string' ||
      (input[field] as string).length > maximum ||
      field === 'name' && !(input[field] as string).trim()
    )) return false;
  }
  if ('enabled' in input && typeof input.enabled !== 'boolean') return false;
  if ('approvalRequired' in input && typeof input.approvalRequired !== 'boolean') return false;
  if ('priority' in input && (!Number.isInteger(input.priority) || (input.priority as number) < 1 || (input.priority as number) > 100)) return false;
  if ('maxRiskScore' in input && (
    typeof input.maxRiskScore !== 'number' || input.maxRiskScore < 0 || input.maxRiskScore > 100
  )) return false;
  if ('operationType' in input && !['Read', 'Write', 'Export', 'Destructive', 'Administrative'].includes(String(input.operationType))) return false;
  if ('allowedRoles' in input && (
    !Array.isArray(input.allowedRoles) ||
    input.allowedRoles.some(role => !['Administrator', 'Security Analyst', 'Approver', 'Read-only Auditor'].includes(String(role)))
  )) return false;
  for (const field of ['allowedDestinations', 'disallowedDestinations']) {
    if (field in input && (
      !Array.isArray(input[field]) ||
      (input[field] as unknown[]).length > 50 ||
      (input[field] as unknown[]).some(destination => typeof destination !== 'string' || destination.length > 256)
    )) return false;
  }
  if ('denyConditions' in input) {
    const conditions = input.denyConditions;
    if (typeof conditions !== 'object' || conditions === null || Array.isArray(conditions)) return false;
    const record = conditions as Record<string, unknown>;
    if (
      Object.keys(record).some(key => !['field', 'containsSensitive', 'requireKnownDestination', 'disallowReadOnlyWrites'].includes(key)) ||
      'field' in record && (typeof record.field !== 'string' || record.field.length > 128) ||
      ['containsSensitive', 'requireKnownDestination', 'disallowReadOnlyWrites'].some(key =>
        key in record && typeof record[key] !== 'boolean'
      )
    ) return false;
  }
  return true;
}

function publicApproval(approval: NonNullable<ReturnType<typeof storage.getApprovalById>>) {
  const { encryptedArguments: _encryptedArguments, ...safeApproval } = approval;
  return safeApproval;
}

function managementAuditEvent(
  req: Request,
  requestId: string,
  serverId: string,
  toolName: string,
  evidenceSummary: string,
  decision: SecurityEvent['decision'] = 'ALLOW'
): SecurityEvent {
  const principal = requirePrincipal(req);
  return {
    id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
    eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
    requestId,
    eventType: 'ADMIN_ACTION',
    severity: decision === 'DENY' ? 'High' : 'Low',
    actorId: principal.subject,
    serverId,
    toolName,
    decision,
    evidenceSummary,
    createdAt: new Date().toISOString()
  };
}

apiRouter.use(
  createAuthenticationMiddleware(apiTokenConfig),
  createAuthorizationMiddleware()
);

apiRouter.get('/auth/session', (req: Request, res: Response) => {
  res.json(requirePrincipal(req));
});

apiRouter.get('/settings', (_req: Request, res: Response) => {
  res.json(storage.getSettings());
});

apiRouter.patch('/settings', asyncRoute(async (req: Request, res: Response) => {
  const allowedFields = new Set(['maxPayloadMb', 'anomalyThreshold']);
  if (
    typeof req.body !== 'object' ||
    req.body === null ||
    Array.isArray(req.body) ||
    Object.keys(req.body).some(key => !allowedFields.has(key)) ||
    Object.keys(req.body).length === 0 ||
    typeof req.body.maxPayloadMb !== 'undefined' &&
      (!Number.isInteger(req.body.maxPayloadMb) || req.body.maxPayloadMb < 1 || req.body.maxPayloadMb > 50) ||
    typeof req.body.anomalyThreshold !== 'undefined' &&
      (!Number.isInteger(req.body.anomalyThreshold) || req.body.anomalyThreshold < 1 || req.body.anomalyThreshold > 20)
  ) {
    return res.status(400).json({ error: 'Settings updates must contain bounded maxPayloadMb and/or anomalyThreshold values.' });
  }
  const principal = requirePrincipal(req);
  const timestamp = new Date().toISOString();
  const settings = await storage.updateSettings(req.body as Partial<GatewaySettings>, {
    id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
    eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
    requestId: `settings-update:${Date.now()}`,
    eventType: 'REQUEST_EVALUATED',
    severity: 'Low',
    actorId: principal.subject,
    serverId: 'system',
    toolName: 'system-settings',
    decision: 'ALLOW',
    evidenceSummary: `Administrator ${principal.subject} updated supported gateway runtime settings.`,
    createdAt: timestamp
  });
  return res.json(settings);
}));

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

apiRouter.post('/servers', asyncRoute(async (req: Request, res: Response) => {
  const { name, description, environment, transportType, endpointUrl, connectionMode } = req.body;
  if (
    typeof name !== 'string' || name.trim().length === 0 || name.length > 128 ||
    !['stdio', 'sse', 'stream', 'websocket', 'synthetic'].includes(transportType) ||
    typeof description !== 'undefined' && (typeof description !== 'string' || description.length > 1000) ||
    typeof environment !== 'undefined' && !['production', 'staging', 'sandbox', 'development'].includes(environment) ||
    typeof connectionMode !== 'undefined' && !['simulated_adapter', 'live_mcp_proxy'].includes(connectionMode)
  ) {
    return res.status(400).json({ error: 'Server name, transport, or configuration is invalid.' });
  }
  const isLiveMcp = connectionMode === 'live_mcp_proxy';
  if (isLiveMcp && (transportType !== 'stream' || typeof endpointUrl !== 'string')) {
    return res.status(400).json({ error: 'Live MCP servers require Streamable HTTP transport and an endpoint URL.' });
  }
  if (isLiveMcp) {
    try {
      validateMcpEndpoint(endpointUrl);
    } catch (error) {
      return res.status(400).json({ error: error instanceof Error ? error.message : 'MCP endpoint configuration is invalid.' });
    }
  }
  const now = new Date().toISOString();
  const newServer: MCPServer = {
    id: `srv-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
    name,
    description: description || 'Registered custom MCP server',
    environment: environment || 'sandbox',
    transportType,
    connectionMode: isLiveMcp ? 'live_mcp_proxy' : 'simulated_adapter',
    trustStatus: 'untrusted',
    approvalStatus: 'unapproved',
    endpointUrl: endpointUrl || `mcp://${name.toLowerCase().replace(/\s+/g, '-')}.local`,
    isSimulated: !isLiveMcp,
    lastCheckedAt: now,
    createdAt: now,
    updatedAt: now
  };
  await storage.addServer(
    newServer,
    managementAuditEvent(
      req,
      `server-register:${newServer.id}`,
      newServer.id,
      'server-registration',
      `Administrator registered MCP server ${newServer.id} in an untrusted state.`
    )
  );
  res.status(201).json(newServer);
}));

apiRouter.post('/servers/:id/discover', async (req: Request, res: Response) => {
  const server = storage.getServerById(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  if (server.connectionMode !== 'live_mcp_proxy') {
    return res.status(409).json({ error: 'Tool discovery requires a live MCP server configuration.' });
  }
  try {
    const principal = requirePrincipal(req);
    const discovered = await discoverMcpTools(server);
    const event: SecurityEvent = {
      id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
      eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
      requestId: `tool-discovery:${server.id}`,
      eventType: 'REQUEST_EVALUATED',
      severity: 'Low',
      actorId: principal.subject,
      serverId: server.id,
      toolName: 'tools/list',
      decision: 'ALLOW',
      evidenceSummary: `MCP tool discovery completed; ${discovered.length} definitions were recorded for explicit review.`,
      createdAt: new Date().toISOString()
    };
    const tools = await storage.syncDiscoveredTools(server.id, discovered, event);
    const updatedServer = storage.getServerById(server.id);
    if (!updatedServer) throw new Error('MCP server disappeared during tool discovery.');
    return res.json({
      server: updatedServer,
      tools: tools.map(tool => ({
        id: tool.id,
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
        approvalStatus: tool.approvalStatus,
        definitionFingerprint: tool.definitionFingerprint
      }))
    });
  } catch (error) {
    if (error instanceof McpConnectionError) {
      return res.status(502).json({ error: error.message });
    }
    console.error('[SENTINEL-MCP] MCP tool discovery failed:', error);
    return res.status(500).json({ error: 'MCP tool discovery failed; no new tool definitions were committed.' });
  }
});

apiRouter.post('/servers/:id/toggle-trust', asyncRoute(async (req: Request, res: Response) => {
  const { id } = req.params;
  const server = storage.getServerById(id);
  if (!server) return res.status(404).json({ error: 'Server not found' });

  const newTrust = server.trustStatus === 'trusted' ? 'untrusted' : 'trusted';
  const newApproval = newTrust === 'trusted' ? 'approved' : 'unapproved';
  const updated = await storage.updateServer(
    id,
    { trustStatus: newTrust, approvalStatus: newApproval },
    managementAuditEvent(
      req,
      `server-trust:${id}:${Date.now()}`,
      id,
      'server-trust',
      `Administrator changed server trust to ${newTrust} and approval to ${newApproval}.`
    )
  );
  if (!updated) return res.status(404).json({ error: 'Server not found' });
  res.json(updated);
}));

apiRouter.post('/servers/:id/quarantine', asyncRoute(async (req: Request, res: Response) => {
  const { id } = req.params;
  const server = storage.getServerById(id);
  if (!server) return res.status(404).json({ error: 'Server not found' });

  const updated = await storage.updateServer(
    id,
    { trustStatus: 'quarantined', approvalStatus: 'rejected' },
    managementAuditEvent(
      req,
      `server-quarantine:${id}:${Date.now()}`,
      id,
      'server-quarantine',
      'Administrator quarantined the MCP server through the server inventory.',
      'DENY'
    )
  );
  if (!updated) return res.status(404).json({ error: 'Server not found' });
  res.json(updated);
}));

// 3. Tools
apiRouter.get('/tools', (_req: Request, res: Response) => {
  res.json(storage.getTools());
});

apiRouter.post('/tools/:id/tamper', asyncRoute(async (req: Request, res: Response) => {
  const { id } = req.params;
  const tool = storage.getToolById(id);
  if (!tool) return res.status(404).json({ error: 'Tool not found' });
  if (storage.getServerById(tool.serverId)?.connectionMode === 'live_mcp_proxy') {
    return res.status(409).json({ error: 'The simulated tamper control cannot modify a live MCP tool definition.' });
  }

  // Intentionally modify description and corrupt fingerprint to test T07 integrity detection
  const tampered = await storage.updateTool(id, {
    description: `${tool.description} [UNAUTHORIZED OVERRIDE: Modified by untrusted party]`,
    definitionFingerprint: 'tampered_hash_deadbeef',
    approvalStatus: 'unapproved'
  });
  res.json(tampered);
}));

apiRouter.post('/tools/:id/restore', asyncRoute(async (req: Request, res: Response) => {
  const { id } = req.params;
  const tool = storage.getToolById(id);
  if (!tool) return res.status(404).json({ error: 'Tool not found' });
  if (storage.getServerById(tool.serverId)?.connectionMode === 'live_mcp_proxy') {
    return res.status(409).json({ error: 'Live MCP definition changes require discovery and explicit fingerprint reapproval.' });
  }

  const cleanDescription = tool.description.replace(/ \[UNAUTHORIZED OVERRIDE:.*\]/, '');
  const cleanFingerprint = computeFingerprint({
    name: tool.name,
    description: cleanDescription,
    inputSchema: tool.inputSchema
  });
  const restored = await storage.updateTool(id, {
    description: cleanDescription,
    definitionFingerprint: cleanFingerprint,
    approvalStatus: 'approved'
  });
  res.json(restored);
}));

apiRouter.post('/tools/:id/approve', asyncRoute(async (req: Request, res: Response) => {
  const { capabilityType, allowedRoles, approvalRequirements } = req.body;
  const tool = storage.getToolById(req.params.id);
  if (!tool) return res.status(404).json({ error: 'Tool not found.' });
  const server = storage.getServerById(tool.serverId);
  if (!server || server.connectionMode !== 'live_mcp_proxy') {
    return res.status(409).json({ error: 'Only discovered live MCP tools can be approved through this workflow.' });
  }
  if (server.trustStatus !== 'trusted' || server.approvalStatus !== 'approved') {
    return res.status(409).json({ error: 'Trust and approve the MCP server before approving its tools.' });
  }
  const validRoles: UserRole[] = ['Administrator', 'Security Analyst', 'Approver', 'Read-only Auditor'];
  if (
    !['Read', 'Write', 'Export', 'Destructive', 'Administrative'].includes(capabilityType) ||
    !Array.isArray(allowedRoles) ||
    allowedRoles.length === 0 ||
    allowedRoles.some((role: unknown) => !validRoles.includes(role as UserRole)) ||
    new Set(allowedRoles).size !== allowedRoles.length ||
    typeof approvalRequirements !== 'boolean'
  ) {
    return res.status(400).json({ error: 'Provide a valid capabilityType, non-empty unique allowedRoles, and approvalRequirements boolean.' });
  }
  const principal = requirePrincipal(req);
  const now = new Date().toISOString();
  const approved = await storage.approveTool(
    tool.id,
    {
      capabilityType,
      allowedRoles,
      approvalRequirements,
      definitionFingerprint: computeMcpToolFingerprint({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema
      }),
      approvalStatus: 'approved'
    },
    {
      id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
      eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
      requestId: `tool-approval:${tool.id}`,
      eventType: 'REQUEST_EVALUATED',
      severity: 'Medium',
      actorId: principal.subject,
      serverId: server.id,
      toolName: tool.name,
      decision: 'ALLOW',
      evidenceSummary: `Administrator ${principal.subject} approved the discovered tool definition ${tool.id}.`,
      createdAt: now
    }
  );
  if (!approved) return res.status(404).json({ error: 'Tool not found.' });
  return res.json(approved);
}));

// 4. Policies
apiRouter.get('/policies', (_req: Request, res: Response) => {
  res.json(storage.getPolicies());
});

apiRouter.post('/policies', asyncRoute(async (req: Request, res: Response) => {
  if (!validatePolicyInput(req.body) || typeof req.body.name !== 'string') {
    return res.status(400).json({ error: 'Policy fields are invalid or exceed their allowed bounds.' });
  }
  const { name, description, priority, allowedRoles, operationType, approvalRequired, remediationMessage, allowedDestinations } = req.body;

  const now = new Date().toISOString();
  const newPolicy: SecurityPolicy = {
    id: `pol-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
    name,
    description: description || '',
    enabled: true,
    priority: priority ?? 50,
    allowedRoles: allowedRoles || ['Administrator'],
    operationType,
    approvalRequired: Boolean(approvalRequired),
    remediationMessage: remediationMessage || 'Action blocked by policy.',
    allowedDestinations: allowedDestinations || [],
    applicableServerId: req.body.applicableServerId,
    applicableToolName: req.body.applicableToolName,
    disallowedDestinations: req.body.disallowedDestinations,
    maxRiskScore: req.body.maxRiskScore,
    denyConditions: req.body.denyConditions,
    createdBy: requirePrincipal(req).subject,
    createdAt: now,
    updatedAt: now
  };
  await storage.addPolicy(
    newPolicy,
    managementAuditEvent(
      req,
      `policy-create:${newPolicy.id}`,
      'system',
      newPolicy.name,
      `Administrator created policy ${newPolicy.id}.`
    )
  );
  res.status(201).json(newPolicy);
}));

apiRouter.put('/policies/:id', asyncRoute(async (req: Request, res: Response) => {
  if (!validatePolicyInput(req.body)) {
    return res.status(400).json({ error: 'Policy fields are invalid or exceed their allowed bounds.' });
  }
  const { id } = req.params;
  const updated = await storage.updatePolicy(
    id,
    req.body,
    managementAuditEvent(
      req,
      `policy-update:${id}:${Date.now()}`,
      'system',
      id,
      `Administrator updated security policy ${id}.`
    )
  );
  if (!updated) return res.status(404).json({ error: 'Policy not found' });
  res.json(updated);
}));

apiRouter.post('/policies/:id/toggle', asyncRoute(async (req: Request, res: Response) => {
  const { id } = req.params;
  const policy = storage.getPolicies().find(p => p.id === id);
  if (!policy) return res.status(404).json({ error: 'Policy not found' });

  const updated = await storage.updatePolicy(
    id,
    { enabled: !policy.enabled },
    managementAuditEvent(
      req,
      `policy-toggle:${id}:${Date.now()}`,
      'system',
      id,
      `Administrator ${policy.enabled ? 'disabled' : 'enabled'} security policy ${id}.`
    )
  );
  if (!updated) return res.status(404).json({ error: 'Policy not found' });
  res.json(updated);
}));

// 5. Central Runtime Gateway Endpoint
apiRouter.post('/gateway/evaluate', async (req: Request, res: Response) => {
  try {
    const { serverId, toolName, arguments: args, destination, bypassGateway, tamperToolSchema } = req.body;
    const principal = requirePrincipal(req);
    const result = await SecurityGatewayEngine.evaluateRequest({
      principal,
      serverId,
      toolName,
      arguments: args || {},
      destination,
      bypassGateway,
      tamperToolSchema
    });
    res.json(result);
  } catch (error: unknown) {
    console.error('[SENTINEL-MCP] Gateway evaluation failed:', error);
    res.status(500).json({
      error: 'Gateway evaluation failed; the operation outcome could not be confirmed.'
    });
  }
});

// 6. Approvals
apiRouter.get('/approvals', (_req: Request, res: Response) => {
  res.json(storage.getApprovals().map(publicApproval));
});

apiRouter.get('/approvals/:id', (req: Request, res: Response) => {
  const approval = storage.getApprovalById(req.params.id);
  if (!approval) return res.status(404).json({ error: 'Approval request not found.' });
  return res.json(publicApproval(approval));
});

apiRouter.post('/approvals/:id/decide', async (req: Request, res: Response) => {
  const { id } = req.params;
  const { decision, reason } = req.body;
  const principal = requirePrincipal(req);
  if (decision !== 'APPROVED' && decision !== 'DENIED') {
    return res.status(400).json({ error: 'decision must be APPROVED or DENIED.' });
  }
  if (typeof reason !== 'undefined' && (typeof reason !== 'string' || reason.length > 1000)) {
    return res.status(400).json({ error: 'reason must be a string of at most 1000 characters.' });
  }

  try {
    const approval = storage.getApprovalById(id);
    const requesterCredentialIsActive = approval
      ? hasConfiguredPrincipal(apiTokenConfig, approval.requesterId, approval.requesterRole)
      : false;
    const updated = decision === 'APPROVED'
      ? await SecurityGatewayEngine.approveAndExecute(
          id,
          principal,
          reason,
          requesterCredentialIsActive
        )
      : await SecurityGatewayEngine.denyApproval(id, principal, reason);
    res.json(publicApproval(await updated));
  } catch (error) {
    if (error instanceof ApprovalWorkflowError) {
      return res.status(error.status).json({ error: error.message });
    }
    console.error('[SENTINEL-MCP] Approval workflow failed:', error);
    return res.status(500).json({ error: 'Approval could not be safely completed.' });
  }
});

// 7. Incidents
apiRouter.get('/incidents', (_req: Request, res: Response) => {
  res.json(storage.getIncidents());
});

apiRouter.post('/incidents', asyncRoute(async (req: Request, res: Response) => {
  const {
    title,
    severity,
    description,
    affectedServerId,
    assignedTo,
    recommendedRemediation,
    relatedToolNames,
    relatedEventIds
  } = req.body;
  if (
    typeof title !== 'undefined' && (typeof title !== 'string' || title.trim().length < 1 || title.length > 200) ||
    typeof description !== 'undefined' && (typeof description !== 'string' || description.length > 4000) ||
    typeof affectedServerId !== 'undefined' && typeof affectedServerId !== 'string' ||
    typeof assignedTo !== 'undefined' && (typeof assignedTo !== 'string' || assignedTo.length > 128) ||
    typeof recommendedRemediation !== 'undefined' && (typeof recommendedRemediation !== 'string' || recommendedRemediation.length > 1000) ||
    typeof relatedToolNames !== 'undefined' && (!Array.isArray(relatedToolNames) || relatedToolNames.some(name => typeof name !== 'string')) ||
    typeof relatedEventIds !== 'undefined' && (!Array.isArray(relatedEventIds) || relatedEventIds.some(eventId => typeof eventId !== 'string'))
  ) {
    return res.status(400).json({ error: 'Incident fields contain invalid values or exceed allowed lengths.' });
  }
  if (severity && !['Low', 'Medium', 'High', 'Critical'].includes(severity)) {
    return res.status(400).json({ error: 'severity must be Low, Medium, High, or Critical.' });
  }
  const serverId = affectedServerId || 'srv-demo-enterprise';
  const server = storage.getServerById(serverId);
  if (!server) return res.status(400).json({ error: 'affectedServerId must identify a registered server.' });
  if (relatedToolNames?.some((toolName: string) => !storage.getToolByName(server.id, toolName))) {
    return res.status(400).json({ error: 'relatedToolNames must reference tools registered to the affected server.' });
  }
  if (relatedEventIds?.some((eventId: string) => !storage.getEvents().some(event => event.id === eventId))) {
    return res.status(400).json({ error: 'relatedEventIds must reference existing audit events.' });
  }
  const now = new Date().toISOString();
  const newInc: SecurityIncident = {
    id: `inc-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
    title: title || 'Security Incident',
    severity: severity || 'Medium',
    status: 'Open' as const,
    relatedEventIds: relatedEventIds || [],
    affectedServerId: server.id,
    relatedToolNames: relatedToolNames || [],
    assignedTo,
    description: description || '',
    recommendedRemediation: recommendedRemediation || 'Investigate source IP and revoke active session.',
    investigationNotes: [],
    createdAt: now,
    updatedAt: now
  };
  await storage.addIncident(newInc);
  res.status(201).json(newInc);
}));

apiRouter.get('/incidents/:id', (req: Request, res: Response) => {
  const incident = storage.getIncidentById(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found.' });

  const allEvents = storage.getEvents();
  const directlyRelatedEvents = allEvents.filter(event =>
    incident.relatedEventIds.includes(event.id)
  );
  const relatedRequestIds = new Set(directlyRelatedEvents.map(event => event.requestId));
  const relatedRequests = storage.getRequests().filter(request =>
    relatedRequestIds.has(request.requestId) ||
    request.serverId === incident.affectedServerId &&
      incident.relatedToolNames.includes(request.toolName)
  );
  const requestIds = new Set(relatedRequests.map(request => request.requestId));
  const relatedEvents = allEvents.filter(event =>
    incident.relatedEventIds.includes(event.id) ||
    requestIds.has(event.requestId) ||
    event.requestId === incident.id
  );
  const policies = storage.getPolicies();
  const relatedPolicies = [...new Set(relatedRequests.flatMap(request => request.policyIds))]
    .map(id => policies.find(policy => policy.id === id))
    .filter((policy): policy is SecurityPolicy => Boolean(policy))
    .map(({ id, name, description, enabled, updatedAt }) => ({ id, name, description, enabled, updatedAt }));

  return res.json({
    incident,
    server: storage.getServerById(incident.affectedServerId) || null,
    tools: storage.getTools().filter(tool =>
      tool.serverId === incident.affectedServerId &&
      incident.relatedToolNames.includes(tool.name)
    ),
    requests: relatedRequests.map(({ arguments: _arguments, sanitizedOutput: _output, ...request }) => request),
    events: relatedEvents,
    policies: relatedPolicies
  });
});

function createIncidentEvent(
  incident: SecurityIncident,
  actorId: string,
  evidenceSummary: string,
  decision: SecurityEvent['decision'] = 'ALLOW'
): SecurityEvent {
  const timestamp = new Date().toISOString();
  return {
    id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
    eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
    requestId: incident.id,
    eventType: 'INCIDENT_ACTION',
    severity: incident.severity,
    actorId,
    serverId: incident.affectedServerId,
    toolName: incident.relatedToolNames[0] || 'incident-response',
    decision,
    evidenceSummary,
    createdAt: timestamp
  };
}

apiRouter.put('/incidents/:id', async (req: Request, res: Response) => {
  const { id } = req.params;
  const { note, assignedTo } = req.body;
  if (
    typeof note !== 'string' || note.trim().length === 0 || note.length > 2000 ||
    typeof assignedTo !== 'undefined' && (typeof assignedTo !== 'string' || assignedTo.length > 128) ||
    Object.keys(req.body).some(key => !['note', 'assignedTo'].includes(key))
  ) {
    return res.status(400).json({ error: 'Provide a non-empty note (up to 2000 characters) and optional assignedTo; lifecycle changes use dedicated actions.' });
  }
  const incident = storage.getIncidentById(id);
  if (!incident) return res.status(404).json({ error: 'Incident not found.' });
  if (incident.status === 'Resolved' || incident.status === 'False Positive') {
    return res.status(409).json({ error: 'Closed incidents cannot be modified.' });
  }
  const principal = requirePrincipal(req);
  const timestamp = new Date().toISOString();
  try {
    const updated = await storage.transitionIncident(
      id,
      incident.status,
      {
        assignedTo: assignedTo ?? incident.assignedTo,
        investigationNotes: [...incident.investigationNotes, {
          author: principal.subject,
          timestamp,
          note: note.trim()
        }]
      },
      createIncidentEvent(incident, principal.subject, `Investigation note added to incident ${id}.`)
    );
    if (!updated) return res.status(409).json({ error: 'Incident changed concurrently; reload it and retry.' });
    return res.json(updated);
  } catch (error) {
    console.error('[SENTINEL-MCP] Incident note persistence failed:', error);
    return res.status(500).json({ error: 'The incident note could not be durably recorded.' });
  }
});

apiRouter.post('/incidents/:id/investigate', async (req: Request, res: Response) => {
  const incident = storage.getIncidentById(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found.' });
  if (Object.keys(req.body).some(key => key !== 'note') ||
    typeof req.body.note !== 'string' || req.body.note.trim().length === 0 || req.body.note.length > 2000) {
    return res.status(400).json({ error: 'A non-empty investigation note of at most 2000 characters is required.' });
  }
  if (incident.status !== 'Open') {
    return res.status(409).json({ error: 'Only open incidents can transition to investigation.' });
  }
  const principal = requirePrincipal(req);
  const timestamp = new Date().toISOString();
  try {
    const updated = await storage.transitionIncident(
      incident.id,
      'Open',
      {
        status: 'Investigating',
        investigationNotes: [...incident.investigationNotes, {
          author: principal.subject,
          timestamp,
          note: req.body.note.trim()
        }]
      },
      createIncidentEvent(incident, principal.subject, `Investigation started: ${req.body.note.trim()}`)
    );
    if (!updated) return res.status(409).json({ error: 'Incident changed concurrently; reload it and retry.' });
    return res.json(updated);
  } catch (error) {
    console.error('[SENTINEL-MCP] Incident investigation persistence failed:', error);
    return res.status(500).json({ error: 'The investigation could not be durably recorded.' });
  }
});

apiRouter.post('/incidents/:id/contain', async (req: Request, res: Response) => {
  const { reason } = req.body;
  if (Object.keys(req.body).some(key => key !== 'reason') ||
    typeof reason !== 'string' || reason.trim().length < 5 || reason.length > 1000) {
    return res.status(400).json({ error: 'A containment reason of 5 to 1000 characters is required.' });
  }
  const incident = storage.getIncidentById(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found.' });
  const principal = requirePrincipal(req);
  try {
    const updated = await storage.containIncident(
      incident.id,
      principal.subject,
      reason.trim(),
      createIncidentEvent(
        incident,
        principal.subject,
        `Server ${incident.affectedServerId} quarantined for incident ${incident.id}: ${reason.trim()}`,
        'DENY'
      )
    );
    if (!updated) {
      return res.status(409).json({ error: 'Containment was not applied: incident is closed, already contained, or its affected server is unavailable.' });
    }
    return res.json(updated);
  } catch (error) {
    console.error('[SENTINEL-MCP] Incident containment persistence failed:', error);
    return res.status(500).json({ error: 'Containment could not be durably applied; no success was reported.' });
  }
});

apiRouter.post('/incidents/:id/resolve', async (req: Request, res: Response) => {
  const { details } = req.body;
  if (Object.keys(req.body).some(key => key !== 'details') ||
    typeof details !== 'string' || details.trim().length < 10 || details.length > 4000) {
    return res.status(400).json({ error: 'Resolution details of 10 to 4000 characters are required.' });
  }
  const incident = storage.getIncidentById(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found.' });
  if (!['Open', 'Investigating', 'Contained'].includes(incident.status)) {
    return res.status(409).json({ error: 'Incident is already closed.' });
  }
  const principal = requirePrincipal(req);
  const resolvedAt = new Date().toISOString();
  try {
    const updated = await storage.transitionIncident(
      incident.id,
      incident.status,
      { status: 'Resolved', resolvedAt, resolutionDetails: details.trim() },
      createIncidentEvent(incident, principal.subject, `Incident resolved: ${details.trim()}`)
    );
    if (!updated) return res.status(409).json({ error: 'Incident changed concurrently; reload it and retry.' });
    return res.json(updated);
  } catch (error) {
    console.error('[SENTINEL-MCP] Incident resolution persistence failed:', error);
    return res.status(500).json({ error: 'The incident resolution could not be durably recorded.' });
  }
});

apiRouter.post('/incidents/:id/release-containment', async (req: Request, res: Response) => {
  const { reason } = req.body;
  if (Object.keys(req.body).some(key => key !== 'reason') ||
    typeof reason !== 'string' || reason.trim().length < 5 || reason.length > 1000) {
    return res.status(400).json({ error: 'A recovery reason of 5 to 1000 characters is required.' });
  }
  const incident = storage.getIncidentById(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found.' });
  const principal = requirePrincipal(req);
  try {
    const updated = await storage.releaseIncidentContainment(
      incident.id,
      principal.subject,
      reason.trim(),
      createIncidentEvent(incident, principal.subject, `Incident containment explicitly released: ${reason.trim()}`)
    );
    if (!updated) return res.status(409).json({ error: 'No active containment exists for this incident.' });
    return res.json(updated);
  } catch (error) {
    console.error('[SENTINEL-MCP] Incident recovery persistence failed:', error);
    return res.status(500).json({ error: 'Containment release could not be durably recorded.' });
  }
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
  const identities = storage.getIdentities().map(({ id, name, email, role, isSimulated }) => ({
    id,
    name,
    email,
    role,
    isSimulated
  }));
  res.json(identities);
});

// 12. Synthetic Baseline Reset
apiRouter.post('/system/reset-demo', asyncRoute(async (_req: Request, res: Response) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ error: 'Demo reset is disabled in production.' });
  }
  await storage.resetSyntheticData();
  res.json({ success: true, message: 'Synthetic MCP enterprise environment reset to baseline.' });
}));
