import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { test } from 'node:test';
import express from 'express';
import { Server as McpServer } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { validateMcpEndpoint } from '../src/server/mcpClient.js';

const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-mcp-proxy-'));
const adminToken = '5'.repeat(64);
const approverToken = '6'.repeat(64);
const upstreamBearerToken = 'controlled-mcp-upstream-token';
process.env.NODE_ENV = 'test';
process.env.SENTINEL_DB_FILE = path.join(temporaryDirectory, 'sentinel-db.json');
process.env.SENTINEL_STORAGE_DRIVER = 'json-fixture';
process.env.SENTINEL_TEST_SEED_DEMO = 'true';
process.env.SENTINEL_APPROVAL_ENCRYPTION_KEY = '7'.repeat(64);
process.env.SENTINEL_API_TOKENS = JSON.stringify([
  { token: adminToken, subject: 'proxy-admin', role: 'Administrator' },
  { token: approverToken, subject: 'proxy-approver', role: 'Approver' }
]);

test('real Streamable HTTP MCP discovery and tool calls are mediated by gateway authorization', async t => {
  let executions = 0;
  let toolDescription = 'Return a controlled echo response.';
  let secretOutput: string | undefined;
  const mcpApp = express();
  mcpApp.use((req, res, next) => {
    if (req.get('authorization') !== `Bearer ${upstreamBearerToken}`) {
      res.status(401).end();
      return;
    }
    next();
  });
  mcpApp.use(express.json());
  mcpApp.post('/mcp', async (req, res) => {
    const mcpServer = new McpServer(
      { name: 'sentinel-controlled-test-server', version: '1.0.0' },
      { capabilities: { tools: { listChanged: true } } }
    );
    const mcpTransport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [{
        name: 'echo_text',
        description: toolDescription,
        inputSchema: {
          type: 'object',
          properties: { text: { type: 'string', minLength: 1 } },
          required: ['text'],
          additionalProperties: false
        }
      }]
    }));
    mcpServer.setRequestHandler(CallToolRequestSchema, async request => {
      executions += 1;
      return {
        content: [{
          type: 'text',
          text: secretOutput || `echo:${String(request.params.arguments?.text)}`
        }]
      };
    });
    try {
      await mcpServer.connect(mcpTransport);
      await mcpTransport.handleRequest(req, res, req.body);
    } catch {
      if (!res.headersSent) res.status(500).end();
    } finally {
      await mcpTransport.close();
      await mcpServer.close();
    }
  });
  mcpApp.get('/mcp', (_req, res) => res.status(405).end());
  mcpApp.delete('/mcp', (_req, res) => res.status(405).end());
  const mcpHttpServer = mcpApp.listen(0, '127.0.0.1');
  await once(mcpHttpServer, 'listening');
  const mcpAddress = mcpHttpServer.address();
  assert.ok(mcpAddress && typeof mcpAddress !== 'string');

  const [{ apiRouter }, { storage }] = await Promise.all([
    import('../src/server/routes.js'),
    import('../src/server/storage.js')
  ]);
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use('/api', apiRouter);
  const gatewayServer = app.listen(0, '127.0.0.1');
  await once(gatewayServer, 'listening');
  const gatewayAddress = gatewayServer.address();
  assert.ok(gatewayAddress && typeof gatewayAddress !== 'string');
  const baseUrl = `http://127.0.0.1:${gatewayAddress.port}/api`;
  const mcpEndpoint = `http://127.0.0.1:${mcpAddress.port}/mcp`;
  const post = (route: string, token: string, body: unknown) => fetch(`${baseUrl}${route}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  t.after(async () => {
    await new Promise<void>((resolve, reject) => {
      gatewayServer.close(error => error ? reject(error) : resolve());
    });
    await new Promise<void>((resolve, reject) => {
      mcpHttpServer.close(error => error ? reject(error) : resolve());
    });
    delete process.env.SENTINEL_MCP_SERVER_TOKENS;
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  });

  assert.throws(
    () => validateMcpEndpoint('http://127.0.0.1/mcp', { NODE_ENV: 'production', SENTINEL_MCP_ALLOWED_HOSTS: '127.0.0.1' }),
    /must use HTTPS/
  );
  assert.throws(
    () => validateMcpEndpoint('http://example.org/mcp', { NODE_ENV: 'test' }),
    /restricted to loopback/
  );

  const registeredResponse = await post('/servers', adminToken, {
    name: 'Controlled MCP integration server',
    description: 'Local test-only Streamable HTTP MCP server',
    environment: 'development',
    transportType: 'stream',
    connectionMode: 'live_mcp_proxy',
    endpointUrl: mcpEndpoint
  });
  assert.equal(registeredResponse.status, 201);
  const registered = await registeredResponse.json() as { id: string; trustStatus: string };
  assert.equal(registered.trustStatus, 'untrusted');
  const registrationEvent = storage.getEvents().find(event =>
    event.requestId === `server-register:${registered.id}`
  );
  assert.equal(registrationEvent?.eventType, 'ADMIN_ACTION');
  assert.equal(registrationEvent?.actorId, 'proxy-admin');
  process.env.SENTINEL_MCP_SERVER_TOKENS = JSON.stringify({
    [registered.id]: upstreamBearerToken
  });

  const discoveryResponse = await post(`/servers/${registered.id}/discover`, adminToken, {});
  const discoveryPayload = await discoveryResponse.json() as {
    tools: Array<{ id: string; name: string; approvalStatus: string }>;
    error?: string;
  };
  assert.equal(discoveryResponse.status, 200, discoveryPayload.error);
  const discovery = discoveryPayload;
  const discoveredTool = discovery.tools.find(tool => tool.name === 'echo_text');
  assert.ok(discoveredTool);
  assert.equal(discoveredTool.approvalStatus, 'unapproved');
  assert.equal(executions, 0);

  const simulatedTamper = await post(`/tools/${discoveredTool.id}/tamper`, adminToken, {});
  const simulatedRestore = await post(`/tools/${discoveredTool.id}/restore`, adminToken, {});
  assert.equal(simulatedTamper.status, 409);
  assert.equal(simulatedRestore.status, 409);

  const trustResponse = await post(`/servers/${registered.id}/toggle-trust`, adminToken, {});
  assert.equal(trustResponse.status, 200);
  const trustEvent = storage.getEvents().find(event =>
    event.requestId.startsWith(`server-trust:${registered.id}:`)
  );
  assert.equal(trustEvent?.eventType, 'ADMIN_ACTION');
  assert.equal(trustEvent?.actorId, 'proxy-admin');
  const unapprovedCall = await post('/gateway/evaluate', adminToken, {
    serverId: registered.id,
    toolName: 'echo_text',
    arguments: { text: 'blocked until approved' }
  });
  assert.equal((await unapprovedCall.json() as { decision: string }).decision, 'DENY');
  assert.equal(executions, 0);

  const approvalResponse = await post(`/tools/${discoveredTool.id}/approve`, adminToken, {
    capabilityType: 'Read',
    allowedRoles: ['Administrator'],
    approvalRequirements: false
  });
  assert.equal(approvalResponse.status, 200);

  const invalidCall = await post('/gateway/evaluate', adminToken, {
    serverId: registered.id,
    toolName: 'echo_text',
    arguments: { text: 10 }
  });
  assert.equal((await invalidCall.json() as { decision: string }).decision, 'DENY');
  assert.equal(executions, 0);

  const allowedCall = await post('/gateway/evaluate', adminToken, {
    serverId: registered.id,
    toolName: 'echo_text',
    arguments: { text: 'verified request' }
  });
  assert.equal(allowedCall.status, 200);
  const allowedResult = await allowedCall.json() as {
    decision: string;
    executionStatus: string;
    toolExecuted: boolean;
    sanitizedOutput: Array<{ text: string }>;
  };
  assert.equal(allowedResult.decision, 'ALLOW');
  assert.equal(allowedResult.executionStatus, 'executed');
  assert.equal(allowedResult.toolExecuted, true);
  assert.match(allowedResult.sanitizedOutput[0].text, /echo:verified request/);
  assert.equal(executions, 1);
  assert.equal(storage.getEvents().some(event =>
    event.requestId && event.toolName === 'echo_text' && event.decision === 'ALLOW'
  ), true);

  const unauthorizedRoleCall = await post('/gateway/evaluate', approverToken, {
    serverId: registered.id,
    toolName: 'echo_text',
    arguments: { text: 'role must not be enough' }
  });
  assert.equal(unauthorizedRoleCall.status, 403);
  assert.equal(executions, 1);

  const leakedCredential = `ghp_${'a'.repeat(36)}`;
  secretOutput = `Sensitive tool response ${leakedCredential}`;
  const dlpResponse = await post('/gateway/evaluate', adminToken, {
    serverId: registered.id,
    toolName: 'echo_text',
    arguments: { text: 'inspect and redact output' }
  });
  const dlpResult = await dlpResponse.json() as {
    decision: string;
    executionStatus: string;
    sanitizedOutput: unknown;
  };
  assert.equal(dlpResult.decision, 'SANITIZE_AND_ALLOW');
  assert.equal(dlpResult.executionStatus, 'sanitized');
  assert.equal(JSON.stringify(dlpResult.sanitizedOutput).includes(leakedCredential), false);
  assert.equal(executions, 2);
  secretOutput = undefined;

  toolDescription = 'Definition changed after administrator approval.';
  const driftedCall = await post('/gateway/evaluate', adminToken, {
    serverId: registered.id,
    toolName: 'echo_text',
    arguments: { text: 'must not forward' }
  });
  assert.equal(driftedCall.status, 200);
  const driftedResult = await driftedCall.json() as {
    decision: string;
    executionStatus: string;
    toolExecuted: boolean;
  };
  assert.equal(driftedResult.decision, 'DENY');
  assert.equal(driftedResult.executionStatus, 'failed');
  assert.equal(driftedResult.toolExecuted, false);
  assert.equal(executions, 2);
});
