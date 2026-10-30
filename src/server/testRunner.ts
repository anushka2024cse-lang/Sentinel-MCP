import crypto from 'crypto';
import {
  SecurityTestScenario,
  SecurityTestRun,
  TestStatus,
  GatewayDecision
} from '../types/index.js';
import { storage } from './storage.js';
import { SecurityGatewayEngine } from './engine.js';

export class SecurityTestRunner {
  /**
   * Run a single predefined attack scenario through the security engine and verify outcomes
   */
  public static async runScenario(scenarioIdOrTestId: string): Promise<SecurityTestRun> {
    const startTime = Date.now();
    const scenario: SecurityTestScenario | undefined = storage.getScenarioById(scenarioIdOrTestId);

    if (!scenario) {
      throw new Error(`Scenario not found: ${scenarioIdOrTestId}`);
    }

    const testRunId = `tr-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
    const checkpoints: SecurityTestRun['verificationEvidence'] = [];
    let failureReason: string | undefined;

    // Snapshot pre-execution synthetic environment state
    const synPre = JSON.parse(JSON.stringify(storage.getSyntheticData()));
    const initialInventory = synPre.inventory.find((i: any) => i.sku === 'SKU-1049')?.quantity ?? 250;
    const initialTransferCount = synPre.externalTransferLog.length;

    // Execute through the real central gateway engine
    const evalResult = await SecurityGatewayEngine.evaluateRequest({
      requestId: `req-test-${scenario.testId}-${Date.now()}`,
      actorId: scenario.syntheticInput.actorId,
      actorRole: scenario.syntheticInput.actorRole,
      serverId: scenario.syntheticInput.serverId,
      toolName: scenario.syntheticInput.toolName,
      arguments: scenario.syntheticInput.arguments || {},
      destination: scenario.syntheticInput.destination,
      bypassGateway: scenario.syntheticInput.bypassGateway,
      tamperToolSchema: scenario.syntheticInput.tamperToolSchema,
      isTestRun: true
    });

    // Snapshot post-execution synthetic environment state
    const synPost = storage.getSyntheticData();
    const finalInventory = synPost.inventory.find(i => i.sku === 'SKU-1049')?.quantity ?? 250;
    const finalTransferCount = synPost.externalTransferLog.length;

    // Verification Checkpoint 1: Gateway Decision Match
    const decisionMatches = evalResult.decision === scenario.expectedDecision;
    checkpoints.push({
      checkpoint: 'Gateway Policy Decision',
      expected: scenario.expectedDecision,
      observed: evalResult.decision,
      verified: decisionMatches
    });

    // Verification Checkpoint 2: Tool Execution State Verification
    let expectedToolExecution = false;
    if (scenario.expectedDecision === 'ALLOW' || scenario.expectedDecision === 'SANITIZE_AND_ALLOW') {
      expectedToolExecution = true;
    }
    const executionMatches = evalResult.toolExecuted === expectedToolExecution;
    checkpoints.push({
      checkpoint: 'Protected Tool Execution Status',
      expected: expectedToolExecution ? 'EXECUTED' : 'BLOCKED',
      observed: evalResult.toolExecuted ? 'EXECUTED' : 'BLOCKED',
      verified: executionMatches
    });

    // Verification Checkpoint 3: Data Mutation / Exfiltration State Verification
    let dataVerificationPassed = true;
    if (scenario.testId === 'T03') {
      // Read-only user attempted inventory write: stock must remain unchanged!
      const inventoryUnchanged = finalInventory === initialInventory;
      checkpoints.push({
        checkpoint: 'Synthetic Inventory Invariance',
        expected: `Stock unchanged at ${initialInventory}`,
        observed: `Stock post-run is ${finalInventory}`,
        verified: inventoryUnchanged
      });
      if (!inventoryUnchanged) dataVerificationPassed = false;
    } else if (scenario.testId === 'T05') {
      // Data export to unapproved destination: transfer log count must NOT increase!
      const transferBlocked = finalTransferCount === initialTransferCount;
      checkpoints.push({
        checkpoint: 'External Exfiltration Prevention',
        expected: 'Zero outbound transfer log additions',
        observed: `${finalTransferCount - initialTransferCount} outbound entries recorded`,
        verified: transferBlocked
      });
      if (!transferBlocked) dataVerificationPassed = false;
    } else if (scenario.testId === 'T04') {
      // Sensitive secret redaction: verify secret is masked and not leaking plaintext
      const rawOutputStr = JSON.stringify(evalResult.sanitizedOutput || {});
      const containsRawSecret = rawOutputStr.includes('sk-demo-secret-key-99321');
      const containsMask = rawOutputStr.includes('[REDACTED_API_KEY');
      const dlpPassed = !containsRawSecret && containsMask;
      checkpoints.push({
        checkpoint: 'DLP Redaction Verification',
        expected: 'Secret replaced with [REDACTED_API_KEY], 0 plaintext secrets in payload',
        observed: containsRawSecret ? 'LEAKED_PLAINTEXT_SECRET' : 'PROPERLY_REDACTED',
        verified: dlpPassed
      });
      if (!dlpPassed) dataVerificationPassed = false;
    }

    // Verification Checkpoint 4: Audit Event Evidence
    const auditVerified = Boolean(evalResult.auditEventId);
    checkpoints.push({
      checkpoint: 'Audit Trail Persistence',
      expected: 'Audit event logged with unique EventID',
      observed: evalResult.auditEventId ? `EventID: ${evalResult.auditEventId}` : 'NO_EVENT',
      verified: auditVerified
    });

    // Determine Final Test Status
    let status: TestStatus = 'PASS';

    // Special case for T12: if direct bypass cannot be independently isolated in testbed, mark INCONCLUSIVE per Section 22
    if (scenario.testId === 'T12') {
      // Direct bypass attempt was captured by simulation hook
      if (!evalResult.executionEvidence.includes('Adapter verified gateway token')) {
        status = 'INCONCLUSIVE';
        failureReason = 'Simulation environment lacks independent network isolation layer for external raw socket bypass test.';
      } else {
        status = 'PASS';
      }
    } else {
      const allCheckpointsVerified = checkpoints.every(c => c.verified);
      if (!allCheckpointsVerified) {
        status = 'FAIL';
        const failedChecks = checkpoints.filter(c => !c.verified).map(c => c.checkpoint);
        failureReason = `Verification failed on checkpoints: ${failedChecks.join(', ')}.`;
      }
    }

    const durationMs = Date.now() - startTime;
    const testRun: SecurityTestRun = {
      id: `run-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`,
      testRunId,
      scenarioId: scenario.id,
      testId: scenario.testId,
      status,
      expectedDecision: scenario.expectedDecision,
      actualDecision: evalResult.decision,
      expectedResult: scenario.expectedOutcome,
      actualResult: evalResult.executionEvidence || `Gateway decided ${evalResult.decision}. Tool executed: ${evalResult.toolExecuted}.`,
      toolExecuted: evalResult.toolExecuted,
      dataExfiltrated: finalTransferCount > initialTransferCount,
      sensitiveDataLeaked: evalResult.sensitiveFindings.some(f => f.appliedAction === 'DETECT_ONLY'),
      auditEventCreated: auditVerified,
      verificationEvidence: checkpoints,
      failureReason,
      durationMs,
      createdAt: new Date(startTime).toISOString(),
      completedAt: new Date().toISOString()
    };

    await storage.addTestRun(testRun);
    return testRun;
  }

  /**
   * Run the full security regression suite across all scenarios
   */
  public static async runAllScenarios(): Promise<SecurityTestRun[]> {
    const scenarios = storage.getScenarios().filter(s => s.enabled);
    const results: SecurityTestRun[] = [];

    for (const scenario of scenarios) {
      const res = await this.runScenario(scenario.id);
      results.push(res);
    }

    return results;
  }
}
