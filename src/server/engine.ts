import crypto from 'crypto';
import Ajv from 'ajv';
import {
  GatewayDecision,
  ExecutionStatus,
  RiskCategory,
  UserRole,
  SecurityRequest,
  SecurityEvent,
  SensitiveDataFinding,
  ApprovalRequest,
  SecurityIncident,
  MCPTool,
  MCPServer
} from '../types/index.js';
import { storage, computeFingerprint } from './storage.js';
import { callMcpTool, computeMcpToolFingerprint } from './mcpClient.js';
import { detectPromptInjection } from '../utils/detection.js';
import {
  canonicalJson,
  decryptApprovalArguments,
  encryptApprovalArguments,
  fingerprintApprovalOperation
} from './approvalCrypto.js';
import { hasPermission } from './auth.js';

const argumentSchemaValidator = new Ajv({ allErrors: true, strict: false });

export interface EvaluationInput {
  requestId?: string;
  principal?: {
    subject: string;
    role: UserRole;
  };
  actorId?: string;
  actorRole?: UserRole;
  authToken?: string;
  serverId: string;
  toolName: string;
  arguments: Record<string, unknown>;
  destination?: string;
  bypassGateway?: boolean;
  tamperToolSchema?: boolean;
  isTestRun?: boolean;
}

export interface EvaluationResult {
  decision: GatewayDecision;
  executionStatus: ExecutionStatus;
  riskScore: number;
  riskCategory: RiskCategory;
  riskFactors: string[];
  matchedPolicyIds: string[];
  remediationReason?: string;
  sanitizedOutput?: unknown;
  outputSummary?: string;
  sensitiveFindings: SensitiveDataFinding[];
  approvalRequestId?: string;
  incidentCreated?: boolean;
  auditEventId: string;
  toolExecuted: boolean;
  dataExfiltrated: boolean;
  executionEvidence: string;
}

export class ApprovalWorkflowError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'ApprovalWorkflowError';
  }
}

// Secret detection patterns (Synthetic and common credential heuristics)
const SECRET_PATTERNS = [
  {
    regex: /(?:sk-[a-zA-Z0-9_-]{16,40}|ghp_[a-zA-Z0-9]{36}|aws_secret_key_[a-zA-Z0-9]{20,})/gi,
    category: 'API_KEY' as const,
    severity: 'Critical' as const,
    label: 'API Key / Secret Token'
  },
  {
    regex: /(?:bearer\s+[a-zA-Z0-9\._-]{24,}|eyJh[a-zA-Z0-9\._-]{20,})/gi,
    category: 'ACCESS_TOKEN' as const,
    severity: 'High' as const,
    label: 'Bearer / JWT Access Token'
  },
  {
    regex: /(?:password|passwd|secret)\s*[:=]\s*["']?([^"' \n]{6,})["']?/gi,
    category: 'PASSWORD' as const,
    severity: 'Critical' as const,
    label: 'Plaintext Password'
  },
  {
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi,
    category: 'EMAIL' as const,
    severity: 'Medium' as const,
    label: 'PII Email Address'
  }
];

// Heuristic prompt injection patterns
const INJECTION_PATTERNS = [
  /system\s+override/i,
  /ignore\s+(all\s+)?(previous|prior)\s+(instructions|constraints|prompts)/i,
  /reveal\s+(the\s+)?(secret|master|api|system)\s+(key|token|prompt)/i,
  /you\s+are\s+now\s+in\s+unrestricted\s+mode/i,
  /bypass\s+security\s+filter/i,
  /purge\s+database/i
];

export class SecurityGatewayEngine {
  // Recent denied request memory for anomaly / rate-limiting detection
  private static recentDeniedAttempts: Array<{ actorId: string; timestamp: number }> = [];

  /**
   * Central evaluation workflow enforcing non-negotiable security steps
   */
  public static async evaluateRequest(input: EvaluationInput): Promise<EvaluationResult> {
    const now = new Date();
    const requestId = input.requestId || `req-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const actor = input.principal
      ? { id: input.principal.subject, role: input.principal.role }
      : input.isTestRun && input.actorId
        ? storage.getIdentityById(input.actorId)
        : undefined;
    const riskFactors: string[] = [];
    let riskScore = 10;
    const sensitiveFindings: SensitiveDataFinding[] = [];
    const matchedPolicyIds: string[] = [];
    let toolExecuted = false;
    let dataExfiltrated = false;
    let executionEvidence = '';

    // Step 0: Check for Direct Gateway Bypass attempt
    if (input.bypassGateway) {
      const event: SecurityEvent = {
        id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
        requestId,
        eventType: 'DIRECT_BYPASS_ATTEMPT',
        severity: 'Critical',
        actorId: actor?.id || 'unknown_intruder',
        serverId: input.serverId,
        toolName: input.toolName,
        decision: 'DENY',
        evidenceSummary: 'Direct route access attempt detected circumventing Sentinel gateway mediation. Call rejected.',
        createdAt: now.toISOString()
      };
      const secReq: SecurityRequest = {
        id: `sec-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        requestId,
        actorId: actor?.id || 'unknown_intruder',
        actorRole: actor?.role || 'Read-only Auditor',
        serverId: input.serverId,
        toolName: input.toolName,
        arguments: input.arguments || {},
        operation: 'Read',
        decision: 'DENY',
        riskScore: 95,
        policyIds: [],
        remediationReason: 'Direct access to MCP tool endpoints is prohibited; calls must route through verified gateway.',
        executionStatus: 'blocked',
        isTestRun: input.isTestRun,
        createdAt: now.toISOString()
      };
      await storage.recordGatewayOutcome(secReq, event);

      return {
        decision: 'DENY',
        executionStatus: 'blocked',
        riskScore: 95,
        riskCategory: 'Critical',
        riskFactors: ['Direct gateway circumvention attempt detected'],
        matchedPolicyIds: [],
        remediationReason: 'Direct access rejected. All MCP requests must traverse Sentinel Security Gateway.',
        sensitiveFindings: [],
        auditEventId: event.eventId,
        toolExecuted: false,
        dataExfiltrated: false,
        executionEvidence: 'Adapter verified gateway token absence; rejected direct connection with 403 Forbidden.'
      };
    }

    // Step 1: Authentication & Identity Check
    if (!actor) {
      riskFactors.push('Unauthenticated client: Missing identity profile');
      riskScore += 80;

      const event: SecurityEvent = {
        id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
        requestId,
        eventType: 'UNAUTHENTICATED_ACCESS',
        severity: 'High',
        actorId: 'UNAUTHENTICATED',
        serverId: input.serverId,
        toolName: input.toolName,
        decision: 'DENY',
        evidenceSummary: 'Request failed authentication check; zero client credentials established.',
        createdAt: now.toISOString()
      };
      const secReq: SecurityRequest = {
        id: `sec-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        requestId,
        actorId: 'UNAUTHENTICATED',
        actorRole: 'Read-only Auditor',
        serverId: input.serverId,
        toolName: input.toolName,
        arguments: input.arguments || {},
        operation: 'Read',
        decision: 'DENY',
        riskScore: 90,
        policyIds: [],
        remediationReason: 'Client identity could not be verified. Provide valid authentication bearer token.',
        executionStatus: 'blocked',
        isTestRun: input.isTestRun,
        createdAt: now.toISOString()
      };
      await storage.recordGatewayOutcome(secReq, event);

      return {
        decision: 'DENY',
        executionStatus: 'blocked',
        riskScore: 90,
        riskCategory: 'Critical',
        riskFactors,
        matchedPolicyIds: [],
        remediationReason: 'Authentication required. No valid client credentials provided.',
        sensitiveFindings: [],
        auditEventId: event.eventId,
        toolExecuted: false,
        dataExfiltrated: false,
        executionEvidence: 'Authentication filter denied access before tool resolution.'
      };
    }

    const resolvedRole: UserRole = actor.role;

    // Step 2: Server Resolution and Trust Check
    const server: MCPServer | undefined = storage.getServerById(input.serverId);
    if (!server) {
      riskFactors.push(`Unknown server ID: ${input.serverId}`);
      return this.rejectWithEvent({
        requestId,
        actorId: actor?.id || 'unknown',
        actorRole: resolvedRole,
        serverId: input.serverId,
        toolName: input.toolName,
        operation: 'Read',
        riskScore: 90,
        riskFactors,
        reason: 'Target MCP server is not registered in the system inventory.',
        eventType: 'TOOL_INVOCATION_DENIED',
        isTestRun: input.isTestRun
      });
    }

    const activeContainment = storage.getActiveIncidentContainment(server.id, input.toolName);
    if (activeContainment) {
      riskFactors.push(`Incident ${activeContainment.id} has an active server containment.`);
      return this.rejectWithEvent({
        requestId,
        actorId: actor?.id || 'unknown',
        actorRole: resolvedRole,
        serverId: server.id,
        toolName: input.toolName,
        operation: 'Read',
        riskScore: 100,
        riskFactors,
        reason: `Execution is blocked by active incident containment ${activeContainment.id}.`,
        eventType: 'TOOL_INVOCATION_DENIED',
        isTestRun: input.isTestRun
      });
    }

    if (server.trustStatus !== 'trusted' || server.approvalStatus !== 'approved') {
      riskFactors.push(`Untrusted or unapproved server: status=${server.trustStatus}/${server.approvalStatus}`);
      riskScore += 45;
      matchedPolicyIds.push('pol-001');

      return this.rejectWithEvent({
        requestId,
        actorId: actor?.id || 'unknown',
        actorRole: resolvedRole,
        serverId: server.id,
        toolName: input.toolName,
        operation: 'Read',
        riskScore,
        riskFactors,
        policyId: 'pol-001',
        reason: 'Target MCP server is unapproved or untrusted. Execution is blocked by policy pol-001.',
        eventType: 'TOOL_INVOCATION_DENIED',
        isTestRun: input.isTestRun
      });
    }

    // Step 3: Tool Resolution & Integrity Check
    const tool: MCPTool | undefined = storage.getToolByName(server.id, input.toolName);
    if (!tool) {
      riskFactors.push(`Tool not found: ${input.toolName} on server ${server.name}`);
      return this.rejectWithEvent({
        requestId,
        actorId: actor?.id || 'unknown',
        actorRole: resolvedRole,
        serverId: server.id,
        toolName: input.toolName,
        operation: 'Read',
        riskScore: 75,
        riskFactors,
        reason: `Tool '${input.toolName}' is not registered on server '${server.name}'.`,
        eventType: 'TOOL_INVOCATION_DENIED',
        isTestRun: input.isTestRun
      });
    }

    if (tool.approvalStatus !== 'approved') {
      riskFactors.push(`Tool '${tool.name}' is not explicitly approved for gateway execution.`);
      return this.rejectWithEvent({
        requestId,
        actorId: actor.id,
        actorRole: resolvedRole,
        serverId: server.id,
        toolName: tool.name,
        operation: tool.capabilityType,
        riskScore: 90,
        riskFactors,
        reason: 'Tool definition must be explicitly approved by an administrator before execution.',
        eventType: 'TOOL_INVOCATION_DENIED',
        isTestRun: input.isTestRun
      });
    }

    // Check Definition Tampering
    let currentFingerprint = tool.definitionFingerprint;
    if (input.tamperToolSchema) {
      // Simulate an unapproved out-of-band schema modification
      currentFingerprint = 'tampered_hash_9999';
    }

    const toolDefinition = {
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema
    };
    const baselineHash = server.connectionMode === 'live_mcp_proxy'
      ? computeMcpToolFingerprint(toolDefinition)
      : computeFingerprint(toolDefinition);

    if (currentFingerprint !== baselineHash || input.tamperToolSchema) {
      riskFactors.push('CRITICAL: Tool definition fingerprint mismatch detected (Integrity Violation)');
      riskScore = 95;
      matchedPolicyIds.push('pol-005');

      const event: SecurityEvent = {
        id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
        requestId,
        eventType: 'TOOL_DEFINITION_CHANGED',
        severity: 'Critical',
        actorId: actor?.id || 'unknown',
        serverId: server.id,
        toolName: tool.name,
        decision: 'DENY',
        policyId: 'pol-005',
        evidenceSummary: `Tool fingerprint altered from baseline '${baselineHash}' to '${currentFingerprint}'. Execution halted pending security review.`,
        createdAt: now.toISOString()
      };
      // Create an automatic security incident for tampering
      const incident: SecurityIncident = {
        id: `inc-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        title: `Tool Definition Tampering Detected: ${tool.name}`,
        severity: 'Critical',
        status: 'Open',
        relatedEventIds: [event.id],
        affectedServerId: server.id,
        relatedToolNames: [tool.name],
        description: `Cryptographic fingerprint of ${tool.name} diverged from approved registry. Potential tool poisoning attack.`,
        recommendedRemediation: 'Audit source server definitions, lock down server configuration, and re-approve definition.',
        investigationNotes: [],
        createdAt: now.toISOString(),
        updatedAt: now.toISOString()
      };

      const secReq: SecurityRequest = {
        id: `sec-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        requestId,
        actorId: actor?.id || 'unknown',
        actorRole: resolvedRole,
        serverId: server.id,
        toolName: tool.name,
        arguments: input.arguments || {},
        operation: tool.capabilityType,
        decision: 'DENY',
        riskScore: 95,
        policyIds: matchedPolicyIds,
        remediationReason: 'Tool definition integrity check failed. The tool description or schema was modified without re-approval.',
        executionStatus: 'blocked',
        isTestRun: input.isTestRun,
        createdAt: now.toISOString()
      };
      await storage.recordGatewayOutcome(secReq, event, [], incident);

      return {
        decision: 'DENY',
        executionStatus: 'blocked',
        riskScore: 95,
        riskCategory: 'Critical',
        riskFactors,
        matchedPolicyIds,
        remediationReason: 'Tool integrity violation: fingerprint has changed from approved baseline.',
        sensitiveFindings: [],
        incidentCreated: true,
        auditEventId: event.eventId,
        toolExecuted: false,
        dataExfiltrated: false,
        executionEvidence: `Tool execution was blocked prior to dispatch due to fingerprint divergence.`
      };
    }

    // Step 4: Validate Tool Arguments Schema
    const schemaValidation = this.validateArguments(input.arguments || {}, tool.inputSchema);
    if (!schemaValidation.valid) {
      riskFactors.push(`Schema violation: ${schemaValidation.error}`);
      riskScore += 40;

      const event: SecurityEvent = {
        id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
        requestId,
        eventType: 'SCHEMA_VIOLATION',
        severity: 'Medium',
        actorId: actor?.id || 'unknown',
        serverId: server.id,
        toolName: tool.name,
        decision: 'DENY',
        evidenceSummary: `Input arguments failed schema validation: ${schemaValidation.error}`,
        createdAt: now.toISOString()
      };
      const secReq: SecurityRequest = {
        id: `sec-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        requestId,
        actorId: actor?.id || 'unknown',
        actorRole: resolvedRole,
        serverId: server.id,
        toolName: tool.name,
        arguments: input.arguments || {},
        operation: tool.capabilityType,
        decision: 'DENY',
        riskScore: 65,
        policyIds: [],
        remediationReason: `Arguments failed schema validation: ${schemaValidation.error}`,
        executionStatus: 'blocked',
        isTestRun: input.isTestRun,
        createdAt: now.toISOString()
      };
      await storage.recordGatewayOutcome(secReq, event);

      return {
        decision: 'DENY',
        executionStatus: 'blocked',
        riskScore: 65,
        riskCategory: 'Medium',
        riskFactors,
        matchedPolicyIds: [],
        remediationReason: `Malformed arguments: ${schemaValidation.error}`,
        sensitiveFindings: [],
        auditEventId: event.eventId,
        toolExecuted: false,
        dataExfiltrated: false,
        executionEvidence: 'Schema validator halted execution before tool dispatch.'
      };
    }

    const argumentDestination = typeof input.arguments?.destination === 'string'
      ? input.arguments.destination
      : undefined;
    if (input.destination && argumentDestination && input.destination !== argumentDestination) {
      return this.rejectWithEvent({
        requestId,
        actorId: actor?.id || 'unknown',
        actorRole: resolvedRole,
        serverId: server.id,
        toolName: tool.name,
        operation: tool.capabilityType,
        riskScore: 90,
        riskFactors: ['The supplied destination does not match the destination in the tool arguments.'],
        policyId: 'pol-002',
        reason: 'Conflicting destinations were provided; the operation was blocked before execution.',
        eventType: 'TOOL_INVOCATION_DENIED',
        isTestRun: input.isTestRun
      });
    }
    const effectiveDestination = argumentDestination || input.destination;

    // Step 5: Prompt Injection / Tool Poisoning Inspection on Arguments & Context
    const injectionCheck = this.detectPromptInjection(input.arguments);
    if (injectionCheck.detected) {
      riskFactors.push(`Prompt injection indicator detected: ${injectionCheck.matchedSnippet}`);
      riskScore += 35;

      const event: SecurityEvent = {
        id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
        requestId,
        eventType: 'PROMPT_INJECTION_DETECTED',
        severity: 'High',
        actorId: actor?.id || 'unknown',
        serverId: server.id,
        toolName: tool.name,
        decision: 'ALLOW', // Note: we flag detection, but allow document retrieval while keeping independent policy guardrails active
        evidenceSummary: `Heuristic scan identified suspicious prompt-override pattern: "${injectionCheck.matchedSnippet}". Gateway maintains independent policy boundary.`,
        createdAt: now.toISOString()
      };
      await storage.addEvent(event);
    }

    // Step 6: Central Policy Engine Deterministic Evaluation
    const policies = storage.getPolicies().filter(p => p.enabled);

    // Factor in Tool Capability risk baseline
    if (tool.capabilityType === 'Destructive') riskScore += 50;
    if (tool.capabilityType === 'Export') riskScore += 40;
    if (tool.capabilityType === 'Write') riskScore += 25;

    // Check RBAC & Permissions on Tool
    if (!tool.allowedRoles.includes(resolvedRole)) {
      riskFactors.push(`Role '${resolvedRole}' is not authorized to execute tool '${tool.name}' (Required: ${tool.allowedRoles.join(', ')})`);
      riskScore += 50;
      matchedPolicyIds.push('pol-002', 'pol-003');

      // Record denied attempt for anomaly tracker
      this.recordDeniedAttempt(actor?.id || 'unknown');

      const anomalyTriggered = await this.checkAnomalyThreshold(actor?.id || 'unknown');
      if (anomalyTriggered) {
        riskFactors.push('ALERT: Rapid repeated unauthorized access attempts triggered rate limit/anomaly rule.');
      }

      return this.rejectWithEvent({
        requestId,
        actorId: actor?.id || 'unknown',
        actorRole: resolvedRole,
        serverId: server.id,
        toolName: tool.name,
        operation: tool.capabilityType,
        riskScore: Math.min(100, riskScore),
        riskFactors,
        policyId: tool.capabilityType === 'Export' ? 'pol-002' : 'pol-003',
        reason: `Role '${resolvedRole}' lacks required permissions for tool '${tool.name}'.`,
        eventType: anomalyTriggered ? 'RATE_LIMIT_TRIGGERED' : 'TOOL_INVOCATION_DENIED',
        isTestRun: input.isTestRun
      });
    }

    // Phase 1: Mandatory Deny Checks across all applicable policies
    for (const policy of policies) {
      if (policy.applicableToolName && policy.applicableToolName !== tool.name) continue;
      if (policy.applicableServerId && policy.applicableServerId !== server.id) continue;
      if (policy.operationType && policy.operationType !== tool.capabilityType) continue;

      // Check Read-only writes isolation
      if (policy.denyConditions?.disallowReadOnlyWrites && tool.capabilityType === 'Write' && resolvedRole === 'Read-only Auditor') {
        riskFactors.push('Policy pol-003: Read-only identities prohibited from mutating system state.');
        matchedPolicyIds.push(policy.id);
        return this.rejectWithEvent({
          requestId,
          actorId: actor?.id || 'unknown',
          actorRole: resolvedRole,
          serverId: server.id,
          toolName: tool.name,
          operation: 'Write',
          riskScore: 85,
          riskFactors,
          policyId: policy.id,
          reason: policy.remediationMessage,
          eventType: 'TOOL_INVOCATION_DENIED',
          isTestRun: input.isTestRun
        });
      }

      // Check Destination Allowlist for exports
      if (tool.capabilityType === 'Export') {
        const dest = (effectiveDestination || '').toLowerCase();
        if (policy.allowedDestinations && policy.allowedDestinations.length > 0) {
          const isAllowedDest = policy.allowedDestinations.some(d => dest.startsWith(d.toLowerCase()));
          if (!dest || !isAllowedDest) {
            riskFactors.push(`Destination '${dest || 'EMPTY'}' is not in approved corporate destination whitelist.`);
            riskScore = 90;
            matchedPolicyIds.push(policy.id);

            const event: SecurityEvent = {
              id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
              eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
              requestId,
              eventType: 'DATA_LEAK_PREVENTED',
              severity: 'Critical',
              actorId: actor?.id || 'unknown',
              serverId: server.id,
              toolName: tool.name,
              decision: 'DENY',
              policyId: policy.id,
              evidenceSummary: `Confidential export blocked: destination '${dest || 'EMPTY'}' was not recognized in approved compliance endpoints. Zero bytes exfiltrated.`,
              createdAt: now.toISOString()
            };
            const secReq: SecurityRequest = {
              id: `sec-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
              requestId,
              actorId: actor?.id || 'unknown',
              actorRole: resolvedRole,
              serverId: server.id,
              toolName: tool.name,
              arguments: input.arguments || {},
              operation: 'Export',
              destination: dest,
              decision: 'DENY',
              riskScore: 90,
              policyIds: matchedPolicyIds,
              remediationReason: policy.remediationMessage,
              executionStatus: 'blocked',
              isTestRun: input.isTestRun,
              createdAt: now.toISOString()
            };
            await storage.recordGatewayOutcome(secReq, event);

            return {
              decision: 'DENY',
              executionStatus: 'blocked',
              riskScore: 90,
              riskCategory: 'Critical',
              riskFactors,
              matchedPolicyIds,
              remediationReason: policy.remediationMessage,
              sensitiveFindings: [],
              auditEventId: event.eventId,
              toolExecuted: false,
              dataExfiltrated: false,
              executionEvidence: `Pre-flight destination inspection halted export before transmission. External transfer log confirmed 0 bytes sent.`
            };
          }
        }
      }
    }

    // Phase 2: Human Approval Gate (Only evaluated after all mandatory deny checks have passed)
    for (const policy of policies) {
      if (policy.applicableToolName && policy.applicableToolName !== tool.name) continue;
      if (policy.applicableServerId && policy.applicableServerId !== server.id) continue;
      if (policy.operationType && policy.operationType !== tool.capabilityType) continue;

      if (policy.approvalRequired || (tool.approvalRequirements && (!policy.applicableToolName || policy.applicableToolName === tool.name))) {
        matchedPolicyIds.push(policy.id);
        riskFactors.push(`Policy ${policy.name} requires two-person approval before execution.`);
        riskScore = Math.max(riskScore, 65);

        // Create Approval Request
        const approvalId = `appr-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`;
        const destination = effectiveDestination;
        const policyVersions = Object.fromEntries(
          policies
            .filter(candidate => matchedPolicyIds.includes(candidate.id))
            .map(candidate => [candidate.id, candidate.updatedAt])
        );
        const approvalFingerprint = fingerprintApprovalOperation({
          requestId,
          requesterId: actor.id,
          requesterRole: resolvedRole,
          serverId: server.id,
          toolId: tool.id,
          toolName: tool.name,
          toolFingerprint: baselineHash,
          arguments: input.arguments,
          destination,
          policyVersions
        });
        const approvalReq: ApprovalRequest = {
          id: approvalId,
          requestId,
          requesterId: actor.id,
          requesterRole: resolvedRole,
          serverId: server.id,
          toolName: tool.name,
          operation: tool.capabilityType,
          parametersRedacted: this.redactSensitiveObject(input.arguments),
          encryptedArguments: encryptApprovalArguments(input.arguments),
          toolId: tool.id,
          toolFingerprint: baselineHash,
          policyVersions,
          executionStatus: 'pending_approval',
          destination,
          riskFactors,
          riskScore,
          policyReason: policy.description,
          requestFingerprint: approvalFingerprint,
          status: 'PENDING',
          expiresAt: new Date(Date.now() + 3600000).toISOString(), // 1 hour expiry
          createdAt: now.toISOString()
        };

        const event: SecurityEvent = {
          id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
          eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
          requestId,
          eventType: 'APPROVAL_DISPATCHED',
          severity: 'High',
          actorId: actor.id,
          serverId: server.id,
          toolName: tool.name,
          decision: 'REQUIRE_APPROVAL',
          policyId: policy.id,
          evidenceSummary: `Execution suspended pending approval by compliance team. Approval Ticket: ${approvalReq.id}.`,
          createdAt: now.toISOString()
        };
        const secReq: SecurityRequest = {
          id: `sec-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
          requestId,
          actorId: actor.id,
          actorRole: resolvedRole,
          serverId: server.id,
          toolName: tool.name,
          arguments: this.redactSensitiveObject(input.arguments || {}),
          operation: tool.capabilityType,
          decision: 'REQUIRE_APPROVAL',
          riskScore,
          policyIds: matchedPolicyIds,
          remediationReason: 'Action requires explicit approval in Sentinel Approval Centre before execution.',
          executionStatus: 'pending_approval',
          isTestRun: input.isTestRun,
          createdAt: now.toISOString()
        };
        await storage.createPendingApproval(approvalReq, secReq, event);

        return {
          decision: 'REQUIRE_APPROVAL',
          executionStatus: 'pending_approval',
          riskScore,
          riskCategory: 'High',
          riskFactors,
          matchedPolicyIds,
          remediationReason: 'Operation placed on hold. Awaiting approver sign-off.',
          sensitiveFindings: [],
          approvalRequestId: approvalReq.id,
          auditEventId: event.eventId,
          toolExecuted: false,
          dataExfiltrated: false,
          executionEvidence: `Execution queue intercepted call. State remains unchanged until approval resolution.`
        };
      }
    }


    // Step 7: Execute Protected MCP Tool (Only reached when fully permitted!)
    let rawExecutionResult: { data: unknown; evidence: string };
    try {
      rawExecutionResult = await this.executeToolAdapter(server, tool, input.arguments);
    } catch (error) {
      const executionUncertain = error instanceof Error &&
        'executionUncertain' in error && error.executionUncertain === true;
      const executionDispatched = error instanceof Error &&
        'executionDispatched' in error && error.executionDispatched === true;
      const outcome = executionUncertain
        ? 'The live MCP call may have reached the server; its outcome could not be confirmed and will not be retried.'
        : 'The protected tool adapter rejected or could not complete the request.';
      riskFactors.push(outcome);
      const failedAt = new Date().toISOString();
      const event: SecurityEvent = {
        id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
        requestId,
        eventType: 'REQUEST_EVALUATED',
        severity: 'High',
        actorId: actor.id,
        serverId: server.id,
        toolName: tool.name,
        decision: 'DENY',
        evidenceSummary: outcome,
        createdAt: failedAt
      };
      await storage.recordGatewayOutcome({
        id: `sec-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        requestId,
        actorId: actor.id,
        actorRole: resolvedRole,
        serverId: server.id,
        toolName: tool.name,
        arguments: this.redactSensitiveObject(input.arguments),
        operation: tool.capabilityType,
        destination: effectiveDestination,
        decision: 'DENY',
        riskScore: Math.max(riskScore, 70),
        policyIds: matchedPolicyIds,
        remediationReason: outcome,
        executionStatus: executionUncertain ? 'uncertain' : 'failed',
        isTestRun: input.isTestRun,
        createdAt: failedAt
      }, event);
      return {
        decision: 'DENY',
        executionStatus: executionUncertain ? 'uncertain' : 'failed',
        riskScore: Math.max(riskScore, 70),
        riskCategory: 'High',
        riskFactors,
        matchedPolicyIds,
        remediationReason: outcome,
        sensitiveFindings,
        auditEventId: event.eventId,
        toolExecuted: executionDispatched,
        dataExfiltrated: false,
        executionEvidence: outcome
      };
    }
    toolExecuted = true;
    executionEvidence = rawExecutionResult.evidence;

    // Step 8: Secure Output Validation & Sensitive Data Redaction
    const outputInspection = this.inspectAndSanitizeOutput(rawExecutionResult.data, requestId);
    const finalDecision: GatewayDecision = outputInspection.wasRedacted ? 'SANITIZE_AND_ALLOW' : 'ALLOW';
    const finalExecutionStatus: ExecutionStatus = outputInspection.wasRedacted ? 'sanitized' : 'executed';

    if (outputInspection.findings.length > 0) {
      sensitiveFindings.push(...outputInspection.findings);
      matchedPolicyIds.push('pol-006');
    }

    const event: SecurityEvent = {
      id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
      eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
      requestId,
      eventType: 'REQUEST_EVALUATED',
      severity: outputInspection.wasRedacted ? 'High' : (riskScore > 50 ? 'Medium' : 'Low'),
      actorId: actor?.id || 'unknown',
      serverId: server.id,
      toolName: tool.name,
      decision: finalDecision,
      evidenceSummary: outputInspection.wasRedacted
        ? `Tool response contained ${outputInspection.findings.length} sensitive secret(s); redacted in flight before delivery to client.`
        : `Tool execution permitted and validated under policies [${matchedPolicyIds.join(', ') || 'default'}].`,
      createdAt: now.toISOString()
    };
    const secReq: SecurityRequest = {
      id: `sec-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
      requestId,
      actorId: actor?.id || 'unknown',
      actorRole: resolvedRole,
      serverId: server.id,
      toolName: tool.name,
      arguments: this.redactSensitiveObject(input.arguments),
      operation: tool.capabilityType,
      decision: finalDecision,
      riskScore: Math.min(100, riskScore),
      policyIds: matchedPolicyIds,
      executionStatus: finalExecutionStatus,
      outputSummary: typeof outputInspection.sanitized === 'string' ? outputInspection.sanitized.substring(0, 150) : JSON.stringify(outputInspection.sanitized).substring(0, 150),
      sanitizedOutput: outputInspection.sanitized,
      isTestRun: input.isTestRun,
      createdAt: now.toISOString()
    };
    await storage.recordGatewayOutcome(secReq, event, outputInspection.findings);

    return {
      decision: finalDecision,
      executionStatus: finalExecutionStatus,
      riskScore: Math.min(100, riskScore),
      riskCategory: this.calculateRiskCategory(riskScore),
      riskFactors,
      matchedPolicyIds,
      sanitizedOutput: outputInspection.sanitized,
      outputSummary: secReq.outputSummary,
      sensitiveFindings,
      auditEventId: event.eventId,
      toolExecuted: true,
      dataExfiltrated: false,
      executionEvidence
    };
  }

  public static async approveAndExecute(
    approvalId: string,
    reviewer: { subject: string; role: UserRole },
    reason: string | undefined,
    requesterCredentialIsActive: boolean
  ): Promise<ApprovalRequest> {
    const approval = storage.getApprovalById(approvalId);
    if (!approval) throw new ApprovalWorkflowError(404, 'Approval request not found.');
    if (approval.status !== 'PENDING') {
      throw new ApprovalWorkflowError(409, `Approval is already ${approval.status.toLowerCase()}.`);
    }

    const now = new Date();
    const event = (decision: GatewayDecision, evidenceSummary: string): SecurityEvent => ({
      id: `evt-${now.getTime()}-${crypto.randomBytes(4).toString('hex')}`,
      eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
      requestId: approval.requestId,
      eventType: 'REQUEST_EVALUATED',
      severity: decision === 'DENY' ? 'High' : 'Low',
      actorId: reviewer.subject,
      serverId: approval.serverId,
      toolName: approval.toolName,
      decision,
      evidenceSummary,
      createdAt: now.toISOString()
    });

    const expire = async () => {
      const expired = await storage.transitionApproval(
        approval.id,
        'PENDING',
        {
          status: 'EXPIRED',
          executionStatus: 'expired',
          executionOutcome: 'Approval expired before execution.'
        },
        event('DENY', `Approval ${approval.id} expired before execution.`),
        {
          decision: 'DENY',
          executionStatus: 'blocked',
          remediationReason: 'Approval expired before execution.'
        }
      );
      if (!expired) throw new ApprovalWorkflowError(409, 'Approval state changed before it could expire.');
      throw new ApprovalWorkflowError(409, 'Approval has expired and cannot be executed.');
    };

    if (Date.parse(approval.expiresAt) <= now.getTime()) await expire();
    if (reviewer.subject === approval.requesterId) {
      throw new ApprovalWorkflowError(403, 'A requester cannot approve their own operation.');
    }
    if (!requesterCredentialIsActive) {
      throw new ApprovalWorkflowError(409, 'The requester credential is no longer active.');
    }
    if (
      !approval.encryptedArguments ||
      !approval.toolId ||
      !approval.toolFingerprint ||
      !approval.policyVersions ||
      !storage.getRequestByRequestId(approval.requestId)
    ) {
      throw new ApprovalWorkflowError(409, 'Approval is missing its original request binding and cannot be executed.');
    }

    let args: Record<string, unknown>;
    try {
      args = decryptApprovalArguments(approval.encryptedArguments);
    } catch {
      throw new ApprovalWorkflowError(409, 'The protected request payload cannot be verified; execution was not attempted.');
    }

    const request = storage.getRequestByRequestId(approval.requestId);
    if (
      !request ||
      request.decision !== 'REQUIRE_APPROVAL' ||
      request.executionStatus !== 'pending_approval' ||
      request.actorId !== approval.requesterId ||
      request.actorRole !== approval.requesterRole ||
      request.serverId !== approval.serverId ||
      request.toolName !== approval.toolName
    ) {
      throw new ApprovalWorkflowError(409, 'The original gateway request is no longer pending or does not match this approval.');
    }
    if (!hasPermission(approval.requesterRole, 'gateway.execute')) {
      throw new ApprovalWorkflowError(403, 'The requester no longer has permission to execute this operation.');
    }

    const server = storage.getServerById(approval.serverId);
    const tool = storage.getToolById(approval.toolId);
    if (
      !server ||
      server.trustStatus !== 'trusted' ||
      server.approvalStatus !== 'approved' ||
      !tool ||
      tool.serverId !== approval.serverId ||
      tool.name !== approval.toolName ||
      tool.approvalStatus !== 'approved'
    ) {
      throw new ApprovalWorkflowError(409, 'The approved server or tool is unavailable, untrusted, or no longer approved.');
    }

    const toolDefinition = {
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema
    };
    const toolFingerprint = server.connectionMode === 'live_mcp_proxy'
      ? computeMcpToolFingerprint(toolDefinition)
      : computeFingerprint(toolDefinition);
    if (toolFingerprint !== approval.toolFingerprint || tool.definitionFingerprint !== approval.toolFingerprint) {
      throw new ApprovalWorkflowError(409, 'The tool definition changed after approval; execution was not attempted.');
    }

    const validation = this.validateArguments(args, tool.inputSchema);
    if (!validation.valid) {
      throw new ApprovalWorkflowError(409, `The approved arguments no longer validate: ${validation.error}`);
    }

    const fingerprint = fingerprintApprovalOperation({
      requestId: approval.requestId,
      requesterId: approval.requesterId,
      requesterRole: approval.requesterRole,
      serverId: approval.serverId,
      toolId: tool.id,
      toolName: tool.name,
      toolFingerprint,
      arguments: args,
      destination: approval.destination,
      policyVersions: approval.policyVersions
    });
    const storedFingerprint = Buffer.from(approval.requestFingerprint, 'hex');
    const actualFingerprint = Buffer.from(fingerprint, 'hex');
    if (
      storedFingerprint.length !== actualFingerprint.length ||
      !crypto.timingSafeEqual(storedFingerprint, actualFingerprint)
    ) {
      throw new ApprovalWorkflowError(409, 'The original operation fingerprint does not match; execution was not attempted.');
    }

    const policies = storage.getPolicies().filter(policy => policy.enabled);
    for (const [policyId, version] of Object.entries(approval.policyVersions)) {
      const policy = policies.find(candidate => candidate.id === policyId);
      if (!policy || policy.updatedAt !== version) {
        throw new ApprovalWorkflowError(409, 'A policy used to approve this operation has changed or been disabled.');
      }
    }

    for (const policy of policies) {
      if (policy.applicableToolName && policy.applicableToolName !== tool.name) continue;
      if (policy.applicableServerId && policy.applicableServerId !== server.id) continue;
      if (policy.operationType && policy.operationType !== tool.capabilityType) continue;

      if (
        policy.denyConditions?.disallowReadOnlyWrites &&
        tool.capabilityType === 'Write' &&
        approval.requesterRole === 'Read-only Auditor'
      ) {
        throw new ApprovalWorkflowError(403, 'A current security policy denies this write operation.');
      }
      if (tool.capabilityType === 'Export') {
        const destination = (approval.destination || '').toLowerCase();
        if (
          policy.allowedDestinations?.length &&
          (!destination || !policy.allowedDestinations.some(allowed => destination.startsWith(allowed.toLowerCase())))
        ) {
          throw new ApprovalWorkflowError(403, 'A current security policy denies this export destination.');
        }
        if (policy.disallowedDestinations?.some(blocked => destination.startsWith(blocked.toLowerCase()))) {
          throw new ApprovalWorkflowError(403, 'A current security policy denies this export destination.');
        }
      }
    }

    const claimTime = new Date().toISOString();
    const claimed = await storage.transitionApproval(
      approval.id,
      'PENDING',
      {
        status: 'APPROVED',
        approverId: reviewer.subject,
        approverReason: reason?.trim() || 'Approved after request revalidation.',
        decidedAt: claimTime,
        executionStatus: 'executing',
        executionOutcome: 'Approval recorded; the original operation is being executed.'
      },
      event('REQUIRE_APPROVAL', `Reviewer ${reviewer.subject} approved and claimed execution for ${approval.id}.`),
      { executionStatus: 'pending_approval' }
    );
    if (!claimed) throw new ApprovalWorkflowError(409, 'Approval was already decided or claimed by another reviewer.');

    try {
      const rawResult = await this.executeToolAdapter(server, tool, args);
      const inspected = this.inspectAndSanitizeOutput(rawResult.data, approval.requestId);

      const status = inspected.wasRedacted ? 'sanitized' : 'executed';
      const decision = inspected.wasRedacted ? 'SANITIZE_AND_ALLOW' : 'ALLOW';
      const outcome = inspected.wasRedacted
        ? 'Original operation executed; sensitive output was redacted before delivery.'
        : 'Original operation executed successfully.';
      const serializedOutput = typeof inspected.sanitized === 'string'
        ? inspected.sanitized
        : JSON.stringify(inspected.sanitized);
      const completedAt = new Date().toISOString();
      const completed = await storage.transitionApproval(
        approval.id,
        'APPROVED',
        {
          executionStatus: status,
          executionOutcome: outcome
        },
        event(decision, outcome),
        {
          decision,
          executionStatus: status,
          sanitizedOutput: inspected.sanitized,
          outputSummary: serializedOutput.slice(0, 150),
          remediationReason: undefined,
          createdAt: completedAt
        },
        inspected.findings
      );
      if (!completed) throw new Error('Approval execution claim was lost before recording its outcome.');
      return completed;
    } catch {
      const uncertainOutcome = 'Execution outcome is uncertain; the operation will not be retried automatically.';
      await storage.transitionApproval(
        approval.id,
        'APPROVED',
        {
          executionStatus: 'uncertain',
          executionOutcome: uncertainOutcome
        },
        event('DENY', uncertainOutcome),
        {
          executionStatus: 'failed',
          remediationReason: uncertainOutcome
        }
      );
      throw new ApprovalWorkflowError(500, uncertainOutcome);
    }
  }

  public static async denyApproval(
    approvalId: string,
    reviewer: { subject: string; role: UserRole },
    reason?: string
  ): Promise<ApprovalRequest> {
    const approval = storage.getApprovalById(approvalId);
    if (!approval) throw new ApprovalWorkflowError(404, 'Approval request not found.');
    if (approval.status !== 'PENDING') {
      throw new ApprovalWorkflowError(409, `Approval is already ${approval.status.toLowerCase()}.`);
    }
    if (Date.parse(approval.expiresAt) <= Date.now()) {
      throw new ApprovalWorkflowError(409, 'Approval has expired and cannot be decided.');
    }
    if (reviewer.subject === approval.requesterId) {
      throw new ApprovalWorkflowError(403, 'A requester cannot decide their own approval.');
    }

    const now = new Date().toISOString();
    const denied = await storage.transitionApproval(
      approvalId,
      'PENDING',
      {
        status: 'DENIED',
        approverId: reviewer.subject,
        approverReason: reason?.trim() || 'Rejected by an authorized reviewer.',
        decidedAt: now,
        executionStatus: 'blocked',
        executionOutcome: 'Operation rejected; the tool was not executed.'
      },
      {
        id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
        requestId: approval.requestId,
        eventType: 'REQUEST_EVALUATED',
        severity: 'Medium',
        actorId: reviewer.subject,
        serverId: approval.serverId,
        toolName: approval.toolName,
        decision: 'DENY',
        evidenceSummary: `Reviewer ${reviewer.subject} rejected approval ${approvalId}; the tool was not executed.`,
        createdAt: now
      },
      {
        decision: 'DENY',
        executionStatus: 'blocked',
        remediationReason: 'Operation rejected by an authorized reviewer.'
      }
    );
    if (!denied) throw new ApprovalWorkflowError(409, 'Approval was already decided by another reviewer.');
    return denied;
  }

  /**
   * Safe execution dispatcher for synthetic MCP tools
   */
  private static async executeToolAdapter(
    server: MCPServer,
    tool: MCPTool,
    args: Record<string, unknown>
  ): Promise<{ data: unknown; evidence: string }> {
    if (server.connectionMode === 'live_mcp_proxy') {
      return callMcpTool(server, tool, args);
    }
    const syn = storage.getSyntheticData();

    switch (tool.name) {
      case 'get_shipment_status': {
        const tracking = String(args.trackingNumber || '');
        const found = syn.shipments.find(s => s.trackingNumber.toLowerCase() === tracking.toLowerCase());
        if (found) {
          return {
            data: { ...found, checkedAt: new Date().toISOString() },
            evidence: `Retrieved shipment details for ${found.trackingNumber} with status ${found.status}.`
          };
        }
        return {
          data: { error: 'Shipment not found', query: tracking },
          evidence: `Shipment query executed for ${tracking}; record not present.`
        };
      }

      case 'get_inventory_summary': {
        return {
          data: {
            totalSkuCount: syn.inventory.length,
            items: syn.inventory.map(i => ({ sku: i.sku, name: i.name, stock: i.quantity, location: i.location }))
          },
          evidence: `Retrieved inventory snapshot across ${syn.inventory.length} SKUs.`
        };
      }

      case 'update_inventory': {
        const sku = String(args.sku || '');
        const adj = Number(args.adjustment || 0);
        const item = syn.inventory.find(i => i.sku === sku);
        if (item) {
          await storage.mutateInventory(sku, adj);
          return {
            data: { sku, previousQuantity: item.quantity - adj, currentQuantity: item.quantity, status: 'SUCCESS' },
            evidence: `Inventory for ${sku} adjusted by ${adj}. Current stock: ${item.quantity}.`
          };
        }
        return { data: { error: 'SKU not found' }, evidence: `SKU ${sku} not found.` };
      }

      case 'search_documents': {
        const rawQuery = String(args.query || '').toLowerCase();
        const normalized = rawQuery.replace(/_/g, ' ');
        const matches = syn.documents.filter(d => {
          const t = d.title.toLowerCase();
          const c = d.content.toLowerCase();
          return t.includes(rawQuery) || c.includes(rawQuery) || t.includes(normalized) || c.includes(normalized);
        });
        return {
          data: {
            resultCount: matches.length,
            documents: matches.map(m => ({ id: m.id, title: m.title, classification: m.classification, content: m.content }))
          },
          evidence: `Document search for '${rawQuery}' yielded ${matches.length} document(s).`
        };
      }

      case 'export_financial_report': {
        const quarter = String(args.quarter || 'Q3-2026');
        const dest = String(args.destination || 'https://compliance-vault.internal.corp');
        const report = syn.financialReports.find(f => f.quarter === quarter) || syn.financialReports[0];
        await storage.recordExternalTransfer(dest, `Exported financial ledger for ${quarter}`);
        return {
          data: {
            quarter: report.quarter,
            revenue: report.revenue,
            confidentialNotes: args.includeConfidentialNotes ? report.confidentialNotes : '[OMITTED]',
            exportedTo: dest,
            exportTimestamp: new Date().toISOString()
          },
          evidence: `Financial ledger for ${quarter} transferred to ${dest}.`
        };
      }

      case 'delete_test_record': {
        return {
          data: { status: 'DELETED', recordId: args.recordId, confirmation: 'CONFIRMED' },
          evidence: `Test record ${args.recordId} purged from staging storage.`
        };
      }

      case 'inspect_manifest': {
        return {
          data: {
            scanned: true,
            fixtureDetected: true,
            notice: 'Static analysis executed. Test fixture findings reported.'
          },
          evidence: 'Manifest parser completed static AST scan; test fixture identified.'
        };
      }

      default:
        return {
          data: { tool: tool.name, result: 'OK', simulatedExecution: true },
          evidence: `Simulated tool ${tool.name} executed cleanly.`
        };
    }
  }

  /**
   * Argument validation against schema
   */
  private static validateArguments(args: Record<string, unknown>, schema: MCPTool['inputSchema']): { valid: boolean; error?: string } {
    try {
      const validate = argumentSchemaValidator.compile(schema);
      if (validate(args)) return { valid: true };
      const error = validate.errors?.[0];
      return {
        valid: false,
        error: error
          ? `${error.instancePath || '/'} ${error.message || 'does not match the tool schema'}`
          : 'Arguments do not match the tool schema.'
      };
    } catch {
      return { valid: false, error: 'The trusted tool schema could not be compiled.' };
    }
  }

  /**
   * Prompt injection heuristic detector
   */
  public static detectPromptInjection(args: Record<string, unknown>): { detected: boolean; matchedSnippet?: string } {
    return detectPromptInjection(args);
  }

  /**
   * DLP Output Inspector: scans tool output, redacts secrets, avoids plaintext leak
   */
  private static inspectAndSanitizeOutput(raw: unknown, requestId: string): { sanitized: unknown; wasRedacted: boolean; findings: SensitiveDataFinding[] } {
    let rawStr = typeof raw === 'string' ? raw : JSON.stringify(raw);
    let wasRedacted = false;
    const findings: SensitiveDataFinding[] = [];

    for (const pattern of SECRET_PATTERNS) {
      const matches = rawStr.match(pattern.regex);
      if (matches) {
        for (const secretVal of matches) {
          wasRedacted = true;
          const masked = `[REDACTED_${pattern.category}_${secretVal.substring(0, 3)}***]`;
          rawStr = rawStr.replace(secretVal, masked);

          findings.push({
            id: `find-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
            requestId,
            category: pattern.category,
            severity: pattern.severity,
            redactedPreview: `${secretVal.substring(0, 4)}...[REDACTED]`,
            matchedPattern: pattern.label,
            location: 'tool_output',
            appliedAction: 'REDACT',
            createdAt: new Date().toISOString()
          });
        }
      }
    }

    let sanitized = raw;
    if (wasRedacted) {
      try {
        sanitized = JSON.parse(rawStr);
      } catch {
        sanitized = rawStr;
      }
    }

    return { sanitized, wasRedacted, findings };
  }

  /**
   * Redact sensitive fields in input objects before persisting to audit trail
   */
  private static redactSensitiveObject(obj: Record<string, unknown>): Record<string, unknown> {
    const copy: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'string') {
        let masked = v;
        for (const pattern of SECRET_PATTERNS) {
          masked = masked.replace(pattern.regex, '[REDACTED_SECRET]');
        }
        copy[k] = masked;
      } else if (v && typeof v === 'object' && !Array.isArray(v)) {
        copy[k] = this.redactSensitiveObject(v as Record<string, unknown>);
      } else {
        copy[k] = v;
      }
    }
    return copy;
  }

  private static calculateRiskCategory(score: number): RiskCategory {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 30) return 'Medium';
    return 'Low';
  }

  private static recordDeniedAttempt(actorId: string): void {
    const now = Date.now();
    this.recentDeniedAttempts.push({ actorId, timestamp: now });
    this.recentDeniedAttempts = this.recentDeniedAttempts.filter(a => now - a.timestamp < 60000);
  }

  private static async checkAnomalyThreshold(actorId: string): Promise<boolean> {
    const recentFromActor = this.recentDeniedAttempts.filter(a => a.actorId === actorId);
    if (recentFromActor.length >= storage.getSettings().anomalyThreshold) {
      // Trigger security incident
      await storage.addIncident({
        id: `inc-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
        title: `Repeated Unauthorized Access Anomaly (${actorId})`,
        severity: 'High',
        status: 'Open',
        relatedEventIds: [],
        affectedServerId: 'srv-demo-enterprise',
        relatedToolNames: ['export_financial_report'],
        description: `Actor '${actorId}' triggered ${recentFromActor.length} denied requests within 60 seconds. Rate limit and anomaly threshold exceeded.`,
        recommendedRemediation: 'Temporarily lock client session and inspect access token origin.',
        investigationNotes: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });
      return true;
    }
    return false;
  }

  private static async rejectWithEvent(params: {
    requestId: string;
    actorId: string;
    actorRole: UserRole;
    serverId: string;
    toolName: string;
    operation: MCPTool['capabilityType'];
    riskScore: number;
    riskFactors: string[];
    policyId?: string;
    reason: string;
    eventType: SecurityEvent['eventType'];
    isTestRun?: boolean;
  }): Promise<EvaluationResult> {
    const now = new Date().toISOString();

    const event: SecurityEvent = {
      id: `evt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
      eventId: `EVT-${crypto.randomBytes(8).toString('hex')}`,
      requestId: params.requestId,
      eventType: params.eventType,
      severity: params.riskScore >= 80 ? 'Critical' : (params.riskScore >= 60 ? 'High' : 'Medium'),
      actorId: params.actorId,
      serverId: params.serverId,
      toolName: params.toolName,
      decision: 'DENY',
      policyId: params.policyId,
      evidenceSummary: params.reason,
      createdAt: now
    };
    const secReq: SecurityRequest = {
      id: `sec-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
      requestId: params.requestId,
      actorId: params.actorId,
      actorRole: params.actorRole,
      serverId: params.serverId,
      toolName: params.toolName,
      arguments: {},
      operation: params.operation,
      decision: 'DENY',
      riskScore: params.riskScore,
      policyIds: params.policyId ? [params.policyId] : [],
      remediationReason: params.reason,
      executionStatus: 'blocked',
      isTestRun: params.isTestRun,
      createdAt: now
    };
    await storage.recordGatewayOutcome(secReq, event);

    return {
      decision: 'DENY',
      executionStatus: 'blocked',
      riskScore: params.riskScore,
      riskCategory: this.calculateRiskCategory(params.riskScore),
      riskFactors: params.riskFactors,
      matchedPolicyIds: params.policyId ? [params.policyId] : [],
      remediationReason: params.reason,
      sensitiveFindings: [],
      auditEventId: event.eventId,
      toolExecuted: false,
      dataExfiltrated: false,
      executionEvidence: `Gateway policy engine rejected request. Tool '${params.toolName}' was NOT invoked.`
    };
  }
}
