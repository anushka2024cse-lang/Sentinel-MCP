import express, { Request, Response, Router } from 'express';
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
import { MCPServer, SecurityEvent, SecurityIncident, SecurityPolicy, UserRole } from '../types/index.js';
import {
  computeMcpToolFingerprint,
  discoverMcpTools,
  McpConnectionError,
  validateMcpEndpoint
} from './mcpClient.js';

export const apiRouter = Router();

const apiTokenConfig = loadApiTokenConfig(process.env);
initializeApprovalEncryptionKey();

function publicApproval(approval: NonNullable<ReturnType<typeof storage.getApprovalById>>) {
  const { encryptedArguments: _encryptedArguments, ...safeApproval } = approval;
  return safeApproval;
}

apiRouter.use(
  createAuthenticationMiddleware(apiTokenConfig),
  createAuthorizationMiddleware()
);

apiRouter.get('/auth/session', (req: Request, res: Response) => {
  res.json(requirePrincipal(req));
});

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
    id: `srv-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
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
  storage.addServer(newServer);
  res.status(201).json(newServer);
});

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
      id: `evt-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
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
    const tools = storage.syncDiscoveredTools(server.id, discovered, event);
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
  if (storage.getServerById(tool.serverId)?.connectionMode === 'live_mcp_proxy') {
    return res.status(409).json({ error: 'The simulated tamper control cannot modify a live MCP tool definition.' });
  }

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
  if (storage.getServerById(tool.serverId)?.connectionMode === 'live_mcp_proxy') {
    return res.status(409).json({ error: 'Live MCP definition changes require discovery and explicit fingerprint reapproval.' });
  }

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

apiRouter.post('/tools/:id/approve', (req: Request, res: Response) => {
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
  const approved = storage.approveTool(
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
      id: `evt-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
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
    createdBy: requirePrincipal(req).subject,
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
      ? SecurityGatewayEngine.approveAndExecute(
          id,
          principal,
          reason,
          requesterCredentialIsActive
        )
      : SecurityGatewayEngine.denyApproval(id, principal, reason);
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

apiRouter.post('/incidents', (req: Request, res: Response) => {
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
    id: `inc-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
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
  storage.addIncident(newInc);
  res.status(201).json(newInc);
});

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
    id: `evt-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
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

apiRouter.put('/incidents/:id', (req: Request, res: Response) => {
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
    const updated = storage.transitionIncident(
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

apiRouter.post('/incidents/:id/investigate', (req: Request, res: Response) => {
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
    const updated = storage.transitionIncident(
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

apiRouter.post('/incidents/:id/contain', (req: Request, res: Response) => {
  const { reason } = req.body;
  if (Object.keys(req.body).some(key => key !== 'reason') ||
    typeof reason !== 'string' || reason.trim().length < 5 || reason.length > 1000) {
    return res.status(400).json({ error: 'A containment reason of 5 to 1000 characters is required.' });
  }
  const incident = storage.getIncidentById(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found.' });
  const principal = requirePrincipal(req);
  try {
    const updated = storage.containIncident(
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

apiRouter.post('/incidents/:id/resolve', (req: Request, res: Response) => {
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
    const updated = storage.transitionIncident(
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

apiRouter.post('/incidents/:id/release-containment', (req: Request, res: Response) => {
  const { reason } = req.body;
  if (Object.keys(req.body).some(key => key !== 'reason') ||
    typeof reason !== 'string' || reason.trim().length < 5 || reason.length > 1000) {
    return res.status(400).json({ error: 'A recovery reason of 5 to 1000 characters is required.' });
  }
  const incident = storage.getIncidentById(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found.' });
  const principal = requirePrincipal(req);
  try {
    const updated = storage.releaseIncidentContainment(
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
apiRouter.post('/system/reset-demo', (_req: Request, res: Response) => {
  storage.resetSyntheticData();
  res.json({ success: true, message: 'Synthetic MCP enterprise environment reset to baseline.' });
});
