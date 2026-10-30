export type UserRole = 'Administrator' | 'Security Analyst' | 'Approver' | 'Read-only Auditor';

export type TransportType = 'stdio' | 'sse' | 'stream' | 'websocket' | 'synthetic';
export type ConnectionStatus = 'connected' | 'disconnected' | 'quarantined' | 'error';
export type TrustStatus = 'trusted' | 'untrusted' | 'quarantined';
export type ApprovalStatus = 'approved' | 'pending' | 'unapproved' | 'rejected';

export type ToolCapability = 'Read' | 'Write' | 'Export' | 'Destructive' | 'Administrative';
export type RiskCategory = 'Low' | 'Medium' | 'High' | 'Critical';
export type GatewayDecision = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'SANITIZE_AND_ALLOW';
export type ExecutionStatus = 'executed' | 'blocked' | 'pending_approval' | 'expired' | 'failed' | 'uncertain' | 'sanitized';

export type IncidentStatus = 'Open' | 'Investigating' | 'Contained' | 'Resolved' | 'False Positive';
export type IncidentSeverity = 'Low' | 'Medium' | 'High' | 'Critical';

export type TestStatus = 'PASS' | 'FAIL' | 'INCONCLUSIVE' | 'PENDING' | 'RUNNING';

export interface MCPServer {
  id: string;
  name: string;
  description: string;
  environment: 'production' | 'staging' | 'sandbox' | 'development';
  transportType: TransportType;
  connectionMode: 'simulated_adapter' | 'live_mcp_proxy';
  trustStatus: TrustStatus;
  approvalStatus: ApprovalStatus;
  endpointUrl?: string;
  isSimulated: boolean;
  lastCheckedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface ToolInputSchema {
  type: string;
  properties: Record<string, {
    type: string;
    description?: string;
    enum?: string[];
    default?: unknown;
  }>;
  required?: string[];
}

export interface MCPTool {
  id: string;
  serverId: string;
  name: string;
  description: string;
  inputSchema: ToolInputSchema;
  capabilityType: ToolCapability;
  riskCategory: RiskCategory;
  requiredPermissions: string[];
  allowedRoles: UserRole[];
  approvalRequirements: boolean;
  definitionFingerprint: string;
  approvalStatus: ApprovalStatus;
  lastObservedAt: string;
  createdAt: string;
  updatedAt: string;
  version: number;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number; // lower number = higher priority
  applicableServerId?: string; // empty means all servers
  applicableToolName?: string; // empty means all tools
  allowedRoles: UserRole[];
  allowedDestinations?: string[]; // for export tools
  disallowedDestinations?: string[];
  operationType?: ToolCapability;
  maxRiskScore?: number;
  approvalRequired: boolean;
  denyConditions?: {
    field?: string;
    containsSensitive?: boolean;
    requireKnownDestination?: boolean;
    disallowReadOnlyWrites?: boolean;
  };
  remediationMessage: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface SecurityRequest {
  id: string;
  requestId: string;
  actorId: string;
  actorRole: UserRole;
  serverId: string;
  toolName: string;
  arguments: Record<string, unknown>;
  operation: ToolCapability;
  destination?: string;
  decision: GatewayDecision;
  riskScore: number;
  policyIds: string[];
  triggeredPolicyName?: string;
  remediationReason?: string;
  executionStatus: ExecutionStatus;
  outputSummary?: string;
  sanitizedOutput?: unknown;
  isTestRun?: boolean;
  createdAt: string;
}

export interface SecurityEvent {
  id: string;
  eventId: string;
  requestId: string;
  eventType: 'REQUEST_EVALUATED' | 'TOOL_INVOCATION_DENIED' | 'UNAUTHENTICATED_ACCESS' | 'DATA_LEAK_PREVENTED' | 'PROMPT_INJECTION_DETECTED' | 'TOOL_DEFINITION_CHANGED' | 'RATE_LIMIT_TRIGGERED' | 'SCHEMA_VIOLATION' | 'APPROVAL_DISPATCHED' | 'DIRECT_BYPASS_ATTEMPT' | 'INCIDENT_ACTION';
  severity: RiskCategory;
  actorId: string;
  serverId: string;
  toolName: string;
  decision: GatewayDecision;
  policyId?: string;
  evidenceSummary: string;
  createdAt: string;
}

export interface SensitiveDataFinding {
  id: string;
  requestId: string;
  category: 'API_KEY' | 'ACCESS_TOKEN' | 'PASSWORD' | 'EMAIL' | 'PHONE' | 'INTERNAL_CREDENTIAL' | 'FINANCIAL_RECORD';
  severity: RiskCategory;
  redactedPreview: string;
  matchedPattern: string;
  location: 'arguments' | 'document_payload' | 'tool_output';
  appliedAction: 'DETECT_ONLY' | 'REDACT' | 'BLOCK' | 'REQUIRE_APPROVAL';
  createdAt: string;
}

export interface ApprovalRequest {
  id: string;
  requestId: string;
  requesterId: string;
  requesterRole: UserRole;
  serverId: string;
  toolName: string;
  operation: ToolCapability;
  parametersRedacted: Record<string, unknown>;
  encryptedArguments?: {
    iv: string;
    authTag: string;
    ciphertext: string;
  };
  toolId?: string;
  toolFingerprint?: string;
  policyVersions?: Record<string, string>;
  executionStatus?: 'pending_approval' | 'executing' | 'executed' | 'sanitized' | 'expired' | 'failed' | 'blocked' | 'uncertain';
  executionOutcome?: string;
  destination?: string;
  riskFactors: string[];
  riskScore: number;
  policyReason: string;
  requestFingerprint: string;
  status: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED';
  approverId?: string;
  approverReason?: string;
  expiresAt: string;
  decidedAt?: string;
  createdAt: string;
}

export interface SecurityIncident {
  id: string;
  title: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  relatedEventIds: string[];
  affectedServerId: string;
  relatedToolNames: string[];
  assignedTo?: string;
  description: string;
  recommendedRemediation: string;
  investigationNotes: {
    author: string;
    timestamp: string;
    note: string;
  }[];
  containment?: {
    type: 'server_quarantine';
    active: boolean;
    initiatedBy: string;
    reason: string;
    startedAt: string;
    releasedBy?: string;
    releaseReason?: string;
    releasedAt?: string;
  };
  resolutionDetails?: string;
  createdAt: string;
  updatedAt: string;
  resolvedAt?: string;
}

export interface SecurityTestScenario {
  id: string;
  testId: string; // T01, T02, etc.
  name: string;
  category: 'Authentication' | 'Authorization' | 'Data Protection' | 'Prompt Injection' | 'Integrity' | 'Anomaly' | 'Validation' | 'Supply Chain' | 'Approval' | 'Bypass';
  description: string;
  preconditions: string;
  syntheticInput: {
    actorId?: string;
    actorRole?: UserRole;
    serverId: string;
    toolName: string;
    arguments: Record<string, unknown>;
    destination?: string;
    bypassGateway?: boolean;
    tamperToolSchema?: boolean;
  };
  expectedDecision: GatewayDecision;
  expectedOutcome: string;
  passCriteria: string;
  failureCriteria: string;
  enabled: boolean;
}

export interface SecurityTestRun {
  id: string;
  testRunId: string;
  scenarioId: string;
  testId: string;
  status: TestStatus;
  expectedDecision: GatewayDecision;
  actualDecision: GatewayDecision;
  expectedResult: string;
  actualResult: string;
  toolExecuted: boolean;
  dataExfiltrated: boolean;
  sensitiveDataLeaked: boolean;
  auditEventCreated: boolean;
  verificationEvidence: {
    checkpoint: string;
    expected: string;
    observed: string;
    verified: boolean;
  }[];
  failureReason?: string;
  durationMs: number;
  createdAt: string;
  completedAt: string;
}

export interface ServerAssessment {
  id: string;
  serverId: string;
  overallStatus: 'Secure' | 'Needs Review' | 'Vulnerable' | 'Quarantined';
  postureScore: number;
  findings: {
    severity: RiskCategory;
    title: string;
    description: string;
  }[];
  assessedAt: string;
}

export interface IdentityProfile {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  isSimulated: boolean;
  ephemeralToken?: {
    token: string;
    issuedAt: string;
    expiresAt: string;
  };
}

export interface SystemStats {
  totalServers: number;
  approvedServers: number;
  unapprovedServers: number;
  totalTools: number;
  totalRequests: number;
  allowedRequests: number;
  deniedRequests: number;
  pendingApprovals: number;
  sensitiveFindingsCount: number;
  activeIncidentsCount: number;
  totalTestsRun: number;
  passedTests: number;
  failedTests: number;
  inconclusiveTests: number;
  testPassRate: number;
}
