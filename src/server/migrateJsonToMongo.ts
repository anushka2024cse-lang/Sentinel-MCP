import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import Ajv from 'ajv';
import { Document } from 'mongodb';
import { closeMongo, getMongoDatabase } from './mongo.js';
import { storage } from './storage.js';
import { IdentityProfile, GatewaySettings } from '../types/index.js';
import { fileURLToPath } from 'node:url';

type LegacyCollectionName =
  | 'servers'
  | 'tools'
  | 'policies'
  | 'requests'
  | 'events'
  | 'findings'
  | 'approvals'
  | 'incidents'
  | 'scenarios'
  | 'testRuns'
  | 'identities';

interface LegacyDatabase {
  servers: Array<Record<string, unknown> & { id: string }>;
  tools: Array<Record<string, unknown> & { id: string; serverId: string }>;
  policies: Array<Record<string, unknown> & { id: string }>;
  requests: Array<Record<string, unknown> & { id: string; requestId: string }>;
  events: Array<Record<string, unknown> & { id: string; eventId: string; requestId: string }>;
  findings: Array<Record<string, unknown> & { id: string }>;
  approvals: Array<Record<string, unknown> & { id: string; requestId: string }>;
  incidents: Array<Record<string, unknown> & { id: string; affectedServerId: string }>;
  scenarios: Array<Record<string, unknown> & { id: string; testId: string }>;
  testRuns: Array<Record<string, unknown> & { id: string; testRunId: string }>;
  identities: Array<Record<string, unknown> & { id: string }>;
  syntheticData: Record<string, unknown>;
}

export interface MigrationReport {
  imported: number;
  skipped: number;
  failed: number;
  dryRun: boolean;
  failedDocuments: string[];
}

const collectionTargets: Record<LegacyCollectionName, string> = {
  servers: 'mcp_servers',
  tools: 'mcp_tools',
  policies: 'security_policies',
  requests: 'security_requests',
  events: 'audit_events',
  findings: 'security_findings',
  approvals: 'approval_requests',
  incidents: 'security_incidents',
  scenarios: 'security_test_scenarios',
  testRuns: 'security_test_runs',
  identities: 'identity_profiles'
};
type MigrationDocument = Document & { _id: string };

const requiredFields: Record<LegacyCollectionName, string[]> = {
  servers: ['id', 'name', 'description', 'environment', 'transportType', 'connectionMode', 'trustStatus', 'approvalStatus', 'isSimulated', 'lastCheckedAt', 'createdAt', 'updatedAt'],
  tools: ['id', 'serverId', 'name', 'description', 'inputSchema', 'capabilityType', 'riskCategory', 'requiredPermissions', 'allowedRoles', 'approvalRequirements', 'definitionFingerprint', 'approvalStatus', 'lastObservedAt', 'createdAt', 'updatedAt', 'version'],
  policies: ['id', 'name', 'description', 'enabled', 'priority', 'allowedRoles', 'approvalRequired', 'remediationMessage', 'createdBy', 'createdAt', 'updatedAt'],
  requests: ['id', 'requestId', 'actorId', 'actorRole', 'serverId', 'toolName', 'arguments', 'operation', 'decision', 'riskScore', 'policyIds', 'executionStatus', 'createdAt'],
  events: ['id', 'eventId', 'requestId', 'eventType', 'severity', 'actorId', 'serverId', 'toolName', 'decision', 'evidenceSummary', 'createdAt'],
  findings: ['id', 'requestId', 'category', 'severity', 'redactedPreview', 'matchedPattern', 'location', 'appliedAction', 'createdAt'],
  approvals: ['id', 'requestId', 'requesterId', 'requesterRole', 'serverId', 'toolName', 'operation', 'parametersRedacted', 'riskFactors', 'riskScore', 'policyReason', 'requestFingerprint', 'status', 'expiresAt', 'createdAt'],
  incidents: ['id', 'title', 'severity', 'status', 'relatedEventIds', 'affectedServerId', 'relatedToolNames', 'description', 'recommendedRemediation', 'investigationNotes', 'createdAt', 'updatedAt'],
  scenarios: ['id', 'testId', 'name', 'category', 'description', 'preconditions', 'syntheticInput', 'expectedDecision', 'expectedOutcome', 'passCriteria', 'failureCriteria', 'enabled'],
  testRuns: ['id', 'testRunId', 'scenarioId', 'testId', 'status', 'expectedDecision', 'actualDecision', 'expectedResult', 'actualResult', 'toolExecuted', 'dataExfiltrated', 'sensitiveDataLeaked', 'auditEventCreated', 'verificationEvidence', 'durationMs', 'createdAt', 'completedAt'],
  identities: ['id', 'name', 'email', 'role', 'isSimulated']
};
const arrayFields = new Set([
  'requiredPermissions', 'allowedRoles', 'policyIds', 'riskFactors', 'relatedEventIds',
  'relatedToolNames', 'investigationNotes', 'verificationEvidence'
]);
const objectFields = new Set([
  'inputSchema', 'arguments', 'parametersRedacted', 'syntheticInput'
]);
const booleanFields = new Set([
  'isSimulated', 'approvalRequirements', 'approvalRequired', 'enabled',
  'toolExecuted', 'dataExfiltrated', 'sensitiveDataLeaked', 'auditEventCreated'
]);
const numberFields = new Set(['priority', 'riskScore', 'version', 'durationMs']);
const collectionProperties = Object.fromEntries(
  Object.entries(requiredFields).map(([name, required]) => [
    name,
    {
      type: 'array',
      items: {
        type: 'object',
        required,
        properties: Object.fromEntries(required.map(field => [
          field,
          field === 'id'
            ? { type: 'string', minLength: 1 }
            : arrayFields.has(field)
              ? { type: 'array' }
              : objectFields.has(field)
                ? { type: 'object' }
                : booleanFields.has(field)
                  ? { type: 'boolean' }
                  : numberFields.has(field)
                    ? { type: 'number' }
                    : { type: 'string' }
        ])),
        additionalProperties: true
      }
    }
  ])
);

const legacySchema = {
  type: 'object',
  required: [...Object.keys(collectionTargets), 'syntheticData'],
  properties: {
    ...collectionProperties,
    syntheticData: {
      type: 'object',
      required: ['inventory', 'shipments', 'documents', 'financialReports', 'externalTransferLog'],
      properties: Object.fromEntries(
        ['inventory', 'shipments', 'documents', 'financialReports', 'externalTransferLog'].map(key => [
          key,
          {
            type: 'array',
            items: {
              type: 'object',
              required: ['id'],
              properties: { id: { type: 'string', minLength: 1 } },
              additionalProperties: true
            }
          }
        ])
      ),
      additionalProperties: false
    }
  },
  additionalProperties: false
} as const;

const validator = new Ajv({ allErrors: true }).compile(legacySchema);

export function getLegacyDatabaseValidationErrors(value: unknown): string[] {
  const errors: string[] = [];
  if (!validator(value)) {
    errors.push(...(validator.errors || []).map(error => `${error.instancePath || '/'} ${error.message || 'is invalid'}`));
    return errors;
  }
  const data = value as unknown as LegacyDatabase;
  for (const collectionName of Object.keys(collectionTargets) as LegacyCollectionName[]) {
    const records = data[collectionName];
    const identifiers = new Set<string>();
    for (const record of records) {
      if (typeof record.id !== 'string' || record.id.length === 0 || identifiers.has(record.id)) {
        errors.push(`${collectionName} contains an empty or duplicate id.`);
        break;
      }
      identifiers.add(record.id);
    }
  }
  const serverIds = new Set(data.servers.map(server => server.id));
  const toolKeys = new Set<string>();
  for (const tool of data.tools) {
    if (!serverIds.has(tool.serverId)) errors.push(`tool ${tool.id} references a missing server.`);
    const key = `${tool.serverId}\u0000${String(tool.name)}`;
    if (toolKeys.has(key)) errors.push(`tools contains duplicate server/name registration for ${tool.serverId}.`);
    toolKeys.add(key);
  }
  if (data.requests.some(request => !serverIds.has(String(request.serverId)))) {
    errors.push('requests contains a serverId with no matching server.');
  }
  const policyIds = new Set(data.policies.map(policy => policy.id));
  if (data.requests.some(request =>
    Array.isArray(request.policyIds) && request.policyIds.some(policyId => !policyIds.has(String(policyId)))
  )) errors.push('requests contains a policyIds entry with no matching policy.');
  const requestIds = new Set(data.requests.map(request => request.requestId));
  if (requestIds.size !== data.requests.length) errors.push('requests contains duplicate requestId values.');
  const auditEventIds = new Set(data.events.map(event => event.eventId));
  if (auditEventIds.size !== data.events.length) errors.push('events contains duplicate eventId values.');
  const testIds = new Set(data.scenarios.map(scenario => scenario.testId));
  if (testIds.size !== data.scenarios.length) errors.push('scenarios contains duplicate testId values.');
  const testRunIds = new Set(data.testRuns.map(run => run.testRunId));
  if (testRunIds.size !== data.testRuns.length) errors.push('testRuns contains duplicate testRunId values.');
  const approvalRequestIds = new Set(data.approvals.map(approval => approval.requestId));
  if (approvalRequestIds.size !== data.approvals.length) errors.push('approvals contains duplicate requestId values.');
  if (data.approvals.some(approval => !requestIds.has(String(approval.requestId)))) {
    errors.push('approvals contains a requestId with no matching request.');
  }
  if (data.incidents.some(incident => !serverIds.has(incident.affectedServerId))) {
    errors.push('incidents contains an affectedServerId with no matching server.');
  }
  const eventIds = new Set(data.events.map(event => event.id));
  if (data.incidents.some(incident =>
    Array.isArray(incident.relatedEventIds) && incident.relatedEventIds.some(eventId => !eventIds.has(String(eventId)))
  )) errors.push('incidents contains a relatedEventId with no matching audit event.');
  const scenarioIds = new Set(data.scenarios.map(scenario => scenario.id));
  if (data.testRuns.some(run => !scenarioIds.has(String(run.scenarioId)))) {
    errors.push('testRuns contains a scenarioId with no matching scenario.');
  }
  return errors;
}

export function validateLegacyDatabase(value: unknown): value is LegacyDatabase {
  return getLegacyDatabaseValidationErrors(value).length === 0;
}

function migrationRecord(record: Record<string, unknown> & { id: string }, collection: LegacyCollectionName) {
  const safeRecord = collection === 'identities'
    ? (({ ephemeralToken: _ephemeralToken, ...identity }) => identity)(record as IdentityProfile & Record<string, unknown>)
    : collection === 'requests'
      ? (() => {
          const { sanitizedOutput: _sanitizedOutput, ...request } = record;
          return { ...request, arguments: {} };
        })()
      : record;
  return { ...safeRecord, _id: record.id };
}

export async function migrateLegacyDatabase(
  database: ReturnType<typeof getMongoDatabase>,
  source: LegacyDatabase,
  dryRun = false
): Promise<MigrationReport> {
  const report: MigrationReport = { imported: 0, skipped: 0, failed: 0, dryRun, failedDocuments: [] };

  for (const [sourceName, targetName] of Object.entries(collectionTargets) as Array<[LegacyCollectionName, string]>) {
    const collection = database.collection<MigrationDocument>(targetName);
    for (const record of source[sourceName]) {
      try {
        const document = migrationRecord(record, sourceName);
        if (dryRun) {
          const exists = await collection.findOne({ _id: record.id }, { projection: { _id: 1 } });
          if (exists) report.skipped += 1;
          else report.imported += 1;
          continue;
        }
        const result = await collection.updateOne(
          { _id: record.id },
          { $setOnInsert: document },
          { upsert: true, writeConcern: { w: 'majority' } }
        );
        if (result.upsertedCount === 1) report.imported += 1;
        else report.skipped += 1;
      } catch {
        report.failed += 1;
        report.failedDocuments.push(`${sourceName}:${record.id}`);
      }
    }
  }

  const settings = database.collection<MigrationDocument>('system_settings');
  const settingsDocuments = [
    {
      _id: 'gateway-runtime',
      key: 'gateway-runtime',
      value: { defaultDeny: true, maxPayloadMb: 10, anomalyThreshold: 3 } satisfies GatewaySettings,
      updatedAt: new Date().toISOString()
    },
    {
      _id: 'synthetic-data',
      key: 'synthetic-data',
      value: source.syntheticData,
      updatedAt: new Date().toISOString()
    }
  ];
  for (const document of settingsDocuments) {
    try {
      if (dryRun) {
        const exists = await settings.findOne({ _id: document._id }, { projection: { _id: 1 } });
        if (exists) report.skipped += 1;
        else report.imported += 1;
      } else {
        const result = await settings.updateOne(
          { _id: document._id },
          { $setOnInsert: document },
          { upsert: true, writeConcern: { w: 'majority' } }
        );
        if (result.upsertedCount === 1) report.imported += 1;
        else report.skipped += 1;
      }
    } catch {
      report.failed += 1;
      report.failedDocuments.push(`system_settings:${document._id}`);
    }
  }
  return report;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');
  const fileArgument = args.find(argument => argument.startsWith('--file='));
  if (args.some(argument => argument !== '--dry-run' && !argument.startsWith('--file='))) {
    throw new Error('Supported migration options are --dry-run and --file=<path>.');
  }
  const sourcePath = path.resolve(
    process.cwd(),
    fileArgument?.slice('--file='.length) || path.join('data', 'sentinel-db.json')
  );
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Migration source file does not exist: ${sourcePath}`);
  }

  const parsed: unknown = JSON.parse(fs.readFileSync(sourcePath, 'utf8'));
  const validationErrors = getLegacyDatabaseValidationErrors(parsed);
  if (validationErrors.length > 0) throw new Error(`Migration source validation failed: ${validationErrors.join('; ')}`);
  if (!validateLegacyDatabase(parsed)) throw new Error('Migration source validation failed.');
  await storage.initialize();
  const report = await migrateLegacyDatabase(getMongoDatabase(), parsed, dryRun);
  console.log(JSON.stringify({ source: sourcePath, ...report }, null, 2));
  if (report.failed > 0) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main()
    .catch(error => {
      console.error('[SENTINEL-MCP] Migration failed:', error instanceof Error ? error.message : 'Unexpected migration error.');
      process.exitCode = 1;
    })
    .finally(() => closeMongo());
}
