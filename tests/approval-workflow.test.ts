import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { test } from 'node:test';
import express from 'express';
import { decryptApprovalArguments } from '../src/server/approvalCrypto.js';

const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-approval-'));
const databaseFile = path.join(temporaryDirectory, 'sentinel-db.json');
const adminToken = '1'.repeat(64);
const approverToken = '2'.repeat(64);
const analystToken = '4'.repeat(64);

process.env.NODE_ENV = 'test';
process.env.SENTINEL_DB_FILE = databaseFile;
process.env.SENTINEL_APPROVAL_ENCRYPTION_KEY = '3'.repeat(64);
process.env.SENTINEL_API_TOKENS = JSON.stringify([
  { token: adminToken, subject: 'admin-requester', role: 'Administrator' },
  { token: approverToken, subject: 'separate-approver', role: 'Approver' },
  { token: analystToken, subject: 'incident-analyst', role: 'Security Analyst' }
]);

test('approval is bound, revalidated, atomically claimed and executes the original simulated operation once', async (t) => {
  const [{ apiRouter }, { storage, StorageEngine }] = await Promise.all([
    import('../src/server/routes.js'),
    import('../src/server/storage.js')
  ]);
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use('/api', apiRouter);
  const server = app.listen(0, '127.0.0.1');

  t.after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
    });
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  });
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const baseUrl = `http://127.0.0.1:${address.port}/api`;
  const transferCount = () => storage.getSyntheticData().externalTransferLog.length;

  const post = (route: string, token: string, body: unknown) => fetch(`${baseUrl}${route}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  const createRequest = () => post('/gateway/evaluate', adminToken, {
    actorId: 'spoofed-approver',
    actorRole: 'Approver',
    serverId: 'srv-finance-vault',
    toolName: 'export_financial_report',
    arguments: {
      quarter: 'Q3-2026',
      destination: 'https://compliance-vault.internal.corp'
    },
    destination: 'https://compliance-vault.internal.corp'
  });

  const initialTransfers = transferCount();
  const conflictingDestination = await post('/gateway/evaluate', adminToken, {
    serverId: 'srv-finance-vault',
    toolName: 'export_financial_report',
    arguments: {
      quarter: 'Q3-2026',
      destination: 'https://untrusted.example'
    },
    destination: 'https://compliance-vault.internal.corp'
  });
  assert.equal(conflictingDestination.status, 200);
  assert.equal((await conflictingDestination.json() as { decision: string }).decision, 'DENY');
  assert.equal(transferCount(), initialTransfers);

  const evaluation = await createRequest();
  assert.equal(evaluation.status, 200);
  const evaluationBody = await evaluation.json() as { decision: string; toolExecuted: boolean; approvalRequestId: string };
  assert.equal(evaluationBody.decision, 'REQUIRE_APPROVAL');
  assert.equal(evaluationBody.toolExecuted, false);
  assert.equal(transferCount(), initialTransfers);

  const pendingResponse = await fetch(`${baseUrl}/approvals`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const pendingApprovals = await pendingResponse.json() as Array<Record<string, unknown>>;
  const approval = pendingApprovals.find(item => item.id === evaluationBody.approvalRequestId);
  assert.ok(approval);
  assert.equal('encryptedArguments' in approval, false);
  const reopenedStorage = new StorageEngine(databaseFile);
  const persistedApproval = reopenedStorage.getApprovalById(evaluationBody.approvalRequestId);
  assert.ok(persistedApproval?.encryptedArguments);
  assert.deepEqual(decryptApprovalArguments(persistedApproval.encryptedArguments), {
    quarter: 'Q3-2026',
    destination: 'https://compliance-vault.internal.corp'
  });

  const detailResponse = await fetch(`${baseUrl}/approvals/${evaluationBody.approvalRequestId}`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(detailResponse.status, 200);
  const approvalDetail = await detailResponse.json() as Record<string, unknown>;
  assert.equal('encryptedArguments' in approvalDetail, false);

  const selfApproval = await post(`/approvals/${evaluationBody.approvalRequestId}/decide`, adminToken, {
    decision: 'APPROVED'
  });
  assert.equal(selfApproval.status, 403);
  assert.equal(transferCount(), initialTransfers);

  const reviewerDecision = await post(`/approvals/${evaluationBody.approvalRequestId}/decide`, approverToken, {
    decision: 'APPROVED',
    approverId: 'spoofed-admin',
    approverRole: 'Administrator'
  });
  assert.equal(reviewerDecision.status, 200);
  const execution = await reviewerDecision.json() as {
    approverId: string;
    status: string;
    executionStatus: string;
    executionOutcome: string;
  };
  assert.equal(execution.approverId, 'separate-approver');
  assert.equal(execution.status, 'APPROVED');
  assert.equal(execution.executionStatus, 'executed');
  assert.match(execution.executionOutcome, /executed successfully/);
  assert.equal(transferCount(), initialTransfers + 1);

  const duplicateDecision = await post(`/approvals/${evaluationBody.approvalRequestId}/decide`, approverToken, {
    decision: 'APPROVED'
  });
  assert.equal(duplicateDecision.status, 409);
  assert.equal(transferCount(), initialTransfers + 1);

  const secondEvaluation = await createRequest();
  const secondBody = await secondEvaluation.json() as { approvalRequestId: string };
  const competingDecisions = await Promise.all([
    post(`/approvals/${secondBody.approvalRequestId}/decide`, approverToken, { decision: 'APPROVED' }),
    post(`/approvals/${secondBody.approvalRequestId}/decide`, approverToken, { decision: 'APPROVED' })
  ]);
  assert.deepEqual(competingDecisions.map(response => response.status).sort(), [200, 409]);
  assert.equal(transferCount(), initialTransfers + 2);

  const rejectedEvaluation = await createRequest();
  const rejectedBody = await rejectedEvaluation.json() as { approvalRequestId: string };
  const rejection = await post(`/approvals/${rejectedBody.approvalRequestId}/decide`, approverToken, {
    decision: 'DENIED'
  });
  assert.equal(rejection.status, 200);
  const deniedApproval = await rejection.json() as { executionStatus: string };
  assert.equal(deniedApproval.executionStatus, 'blocked');
  assert.equal(transferCount(), initialTransfers + 2);

  const stalePolicyEvaluation = await createRequest();
  const stalePolicyBody = await stalePolicyEvaluation.json() as { approvalRequestId: string };
  const stalePolicyApproval = storage.getApprovalById(stalePolicyBody.approvalRequestId);
  assert.ok(stalePolicyApproval?.policyVersions);
  const [policyId] = Object.keys(stalePolicyApproval.policyVersions);
  const policy = storage.getPolicies().find(item => item.id === policyId);
  assert.ok(policy);
  await new Promise(resolve => setTimeout(resolve, 2));
  storage.updatePolicy(policy.id, { description: `${policy.description} Updated after request.` });
  const stalePolicyDecision = await post(`/approvals/${stalePolicyBody.approvalRequestId}/decide`, approverToken, {
    decision: 'APPROVED'
  });
  assert.equal(stalePolicyDecision.status, 409);
  assert.equal(transferCount(), initialTransfers + 2);

  const expiredEvaluation = await createRequest();
  const expiredBody = await expiredEvaluation.json() as { approvalRequestId: string };
  const storedApproval = storage.getApprovalById(expiredBody.approvalRequestId);
  assert.ok(storedApproval);
  storage.updateApproval(storedApproval.id, { expiresAt: new Date(Date.now() - 1000).toISOString() });
  const expiredDecision = await post(`/approvals/${expiredBody.approvalRequestId}/decide`, approverToken, {
    decision: 'APPROVED'
  });
  assert.equal(expiredDecision.status, 409);
  assert.equal(storage.getApprovalById(expiredBody.approvalRequestId)?.status, 'EXPIRED');
  assert.equal(transferCount(), initialTransfers + 2);

  const tamperedEvaluation = await createRequest();
  const tamperedBody = await tamperedEvaluation.json() as { approvalRequestId: string };
  const tamperedApproval = storage.getApprovalById(tamperedBody.approvalRequestId);
  assert.ok(tamperedApproval?.encryptedArguments);
  const ciphertext = tamperedApproval.encryptedArguments.ciphertext;
  storage.updateApproval(tamperedApproval.id, {
    encryptedArguments: {
      ...tamperedApproval.encryptedArguments,
      ciphertext: `${ciphertext[0] === 'A' ? 'B' : 'A'}${ciphertext.slice(1)}`
    }
  });
  const tamperedDecision = await post(`/approvals/${tamperedBody.approvalRequestId}/decide`, approverToken, {
    decision: 'APPROVED'
  });
  assert.equal(tamperedDecision.status, 409);
  assert.equal(transferCount(), initialTransfers + 2);

  const trustEvaluation = await createRequest();
  const trustBody = await trustEvaluation.json() as { approvalRequestId: string };
  storage.updateServer('srv-finance-vault', { trustStatus: 'quarantined' });
  const trustDecision = await post(`/approvals/${trustBody.approvalRequestId}/decide`, approverToken, {
    decision: 'APPROVED'
  });
  assert.equal(trustDecision.status, 409);
  assert.equal(transferCount(), initialTransfers + 2);

  storage.updateServer('srv-finance-vault', { trustStatus: 'trusted', approvalStatus: 'approved' });
  const staleToolEvaluation = await createRequest();
  const staleToolBody = await staleToolEvaluation.json() as { approvalRequestId: string };
  const staleToolApproval = storage.getApprovalById(staleToolBody.approvalRequestId);
  assert.ok(staleToolApproval?.toolId);
  storage.updateTool(staleToolApproval.toolId, { description: 'Tool definition changed after approval.' });
  const staleToolDecision = await post(`/approvals/${staleToolBody.approvalRequestId}/decide`, approverToken, {
    decision: 'APPROVED'
  });
  assert.equal(staleToolDecision.status, 409);
  assert.equal(transferCount(), initialTransfers + 2);

  const relatedGatewayRequest = await post('/gateway/evaluate', adminToken, {
    serverId: 'srv-demo-enterprise',
    toolName: 'get_shipment_status',
    arguments: { trackingNumber: 'TRK-99214' }
  });
  assert.equal(relatedGatewayRequest.status, 200);

  const incidentCreate = await post('/incidents', adminToken, {
    title: 'Containment enforcement test',
    severity: 'High',
    description: 'Verify incident evidence and actual gateway containment.',
    affectedServerId: 'srv-demo-enterprise',
    relatedToolNames: ['get_shipment_status']
  });
  assert.equal(incidentCreate.status, 201);
  const incident = await incidentCreate.json() as { id: string; status: string };
  const investigation = await post(`/incidents/${incident.id}/investigate`, analystToken, {
    note: 'Reviewing the affected server activity and linked request evidence.'
  });
  assert.equal(investigation.status, 200);
  const investigating = await investigation.json() as { status: string; investigationNotes: Array<{ author: string }> };
  assert.equal(investigating.status, 'Investigating');
  assert.equal(investigating.investigationNotes[0].author, 'incident-analyst');

  const incidentDetailsResponse = await fetch(`${baseUrl}/incidents/${incident.id}`, {
    headers: { Authorization: `Bearer ${analystToken}` }
  });
  assert.equal(incidentDetailsResponse.status, 200);
  const incidentDetails = await incidentDetailsResponse.json() as {
    incident: { id: string };
    server: { id: string };
    tools: Array<{ name: string }>;
    requests: unknown[];
    events: Array<{ eventType: string }>;
  };
  assert.equal(incidentDetails.incident.id, incident.id);
  assert.equal(incidentDetails.server.id, 'srv-demo-enterprise');
  assert.ok(incidentDetails.tools.some(tool => tool.name === 'get_shipment_status'));
  assert.ok(incidentDetails.requests.length > 0);
  assert.ok(incidentDetails.events.some(event => event.eventType === 'INCIDENT_ACTION'));

  const analystContainment = await post(`/incidents/${incident.id}/contain`, analystToken, {
    reason: 'Analyst is not authorized to quarantine.'
  });
  assert.equal(analystContainment.status, 403);
  assert.notEqual(storage.getIncidentById(incident.id)?.status, 'Contained');

  const containment = await post(`/incidents/${incident.id}/contain`, adminToken, {
    reason: 'Contain suspicious activity on the affected server.'
  });
  assert.equal(containment.status, 200);
  const containedIncident = await containment.json() as {
    status: string;
    containment: { active: boolean; initiatedBy: string };
  };
  assert.equal(containedIncident.status, 'Contained');
  assert.equal(containedIncident.containment.active, true);
  assert.equal(containedIncident.containment.initiatedBy, 'admin-requester');
  assert.equal(storage.getServerById('srv-demo-enterprise')?.trustStatus, 'quarantined');

  const containedGatewayRequest = await post('/gateway/evaluate', adminToken, {
    serverId: 'srv-demo-enterprise',
    toolName: 'get_shipment_status',
    arguments: { trackingNumber: 'TRK-99214' }
  });
  assert.equal(containedGatewayRequest.status, 200);
  const containedGatewayResult = await containedGatewayRequest.json() as { decision: string; toolExecuted: boolean };
  assert.equal(containedGatewayResult.decision, 'DENY');
  assert.equal(containedGatewayResult.toolExecuted, false);

  const attemptedServerTrustRestore = await post('/servers/srv-demo-enterprise/toggle-trust', adminToken, {});
  assert.equal(attemptedServerTrustRestore.status, 200);
  assert.equal(storage.getServerById('srv-demo-enterprise')?.trustStatus, 'trusted');
  const incidentStillEnforced = await post('/gateway/evaluate', adminToken, {
    serverId: 'srv-demo-enterprise',
    toolName: 'get_shipment_status',
    arguments: { trackingNumber: 'TRK-99214' }
  });
  assert.equal((await incidentStillEnforced.json() as { decision: string }).decision, 'DENY');

  const resolution = await post(`/incidents/${incident.id}/resolve`, adminToken, {
    details: 'Reviewed the incident evidence and completed containment verification.'
  });
  assert.equal(resolution.status, 200);
  const resolvedIncident = await resolution.json() as {
    status: string;
    containment: { active: boolean };
    resolutionDetails: string;
  };
  assert.equal(resolvedIncident.status, 'Resolved');
  assert.equal(resolvedIncident.containment.active, true);
  assert.ok(resolvedIncident.resolutionDetails.includes('completed containment'));

  const stillContainedAfterResolution = await post('/gateway/evaluate', adminToken, {
    serverId: 'srv-demo-enterprise',
    toolName: 'get_shipment_status',
    arguments: { trackingNumber: 'TRK-99214' }
  });
  assert.equal((await stillContainedAfterResolution.json() as { decision: string }).decision, 'DENY');

  const released = await post(`/incidents/${incident.id}/release-containment`, adminToken, {
    reason: 'Recovery approved after incident review.'
  });
  assert.equal(released.status, 200);
  const releasedIncident = await released.json() as { status: string; containment: { active: boolean; releasedBy?: string } };
  assert.equal(releasedIncident.containment.active, false);
  assert.equal(releasedIncident.containment.releasedBy, 'admin-requester');
  const afterExplicitRecovery = await post('/gateway/evaluate', adminToken, {
    serverId: 'srv-demo-enterprise',
    toolName: 'get_shipment_status',
    arguments: { trackingNumber: 'TRK-99214' }
  });
  const recoveredExecution = await afterExplicitRecovery.json() as { decision: string; toolExecuted: boolean };
  assert.equal(recoveredExecution.decision, 'ALLOW');
  assert.equal(recoveredExecution.toolExecuted, true);
});
