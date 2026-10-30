import assert from 'node:assert/strict';
import { once } from 'node:events';
import { test } from 'node:test';
import express from 'express';
import {
  createApiTokenConfig,
  createAuthenticationMiddleware,
  createAuthorizationMiddleware,
  loadApiTokenConfig
} from '../src/server/auth.js';

const adminToken = 'a'.repeat(64);
const analystToken = 'b'.repeat(64);
const auditorToken = 'c'.repeat(64);

test('API credentials are validated and production fails closed without configuration', () => {
  assert.throws(() => createApiTokenConfig([]), /non-empty array/);
  assert.throws(() => createApiTokenConfig([
    { token: 'short', subject: 'admin', role: 'Administrator' }
  ]), /64-character hexadecimal token/);
  assert.throws(() => loadApiTokenConfig({ NODE_ENV: 'production' }, () => {}), /must be configured/);

  const logged: string[] = [];
  const localConfig = loadApiTokenConfig({}, (message) => logged.push(message));
  assert.equal(localConfig.credentials.length, 2);
  assert.match(logged[0], /Temporary local administrator token/);
  assert.match(logged[1], /Temporary local approver token/);
});

test('API authentication and RBAC ignore caller-supplied identity and role claims', async (t) => {
  const config = createApiTokenConfig([
    { token: adminToken, subject: 'security-admin', role: 'Administrator' },
    { token: analystToken, subject: 'soc-analyst', role: 'Security Analyst' },
    { token: auditorToken, subject: 'audit-reader', role: 'Read-only Auditor' }
  ]);
  const app = express();
  app.use(express.json());
  app.use('/api', createAuthenticationMiddleware(config), createAuthorizationMiddleware());
  app.get('/api/auth/session', (request, response) => response.json(request.authPrincipal));
  app.get('/api/servers', (_request, response) => response.json({ servers: [] }));
  app.post('/api/servers', (_request, response) => response.status(201).json({ created: true }));
  app.post('/api/gateway/evaluate', (request, response) => response.json({
    principal: request.authPrincipal,
    submittedActorId: request.body.actorId,
    submittedActorRole: request.body.actorRole
  }));

  const server = app.listen(0, '127.0.0.1');
  t.after(() => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const baseUrl = `http://127.0.0.1:${address.port}/api`;

  const missingAuth = await fetch(`${baseUrl}/auth/session`);
  assert.equal(missingAuth.status, 401);

  const invalidAuth = await fetch(`${baseUrl}/auth/session`, {
    headers: { Authorization: `Bearer ${'f'.repeat(64)}` }
  });
  assert.equal(invalidAuth.status, 401);

  const session = await fetch(`${baseUrl}/auth/session`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.deepEqual(await session.json(), { subject: 'security-admin', role: 'Administrator' });

  const spoofedEvaluation = await fetch(`${baseUrl}/gateway/evaluate`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${analystToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ actorId: 'security-admin', actorRole: 'Administrator' })
  });
  assert.equal(spoofedEvaluation.status, 200);
  assert.deepEqual(await spoofedEvaluation.json(), {
    principal: { subject: 'soc-analyst', role: 'Security Analyst' },
    submittedActorId: 'security-admin',
    submittedActorRole: 'Administrator'
  });

  const analystCannotManageServers = await fetch(`${baseUrl}/servers`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${analystToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({})
  });
  assert.equal(analystCannotManageServers.status, 403);

  const auditorCannotExecute = await fetch(`${baseUrl}/gateway/evaluate`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${auditorToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({})
  });
  assert.equal(auditorCannotExecute.status, 403);

  const auditorCanReadServers = await fetch(`${baseUrl}/servers`, {
    headers: { Authorization: `Bearer ${auditorToken}` }
  });
  assert.equal(auditorCanReadServers.status, 200);
});
