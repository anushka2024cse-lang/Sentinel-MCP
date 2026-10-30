import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Db, MongoClient, MongoClientOptions } from 'mongodb';

class MemoryCollection {
  public readonly documents = new Map<string, Record<string, unknown>>();
  public readonly indexes: string[] = [];

  async createIndex(_keys: Record<string, number>, options: { name: string }): Promise<string> {
    this.indexes.push(options.name);
    return options.name;
  }

  find(): { toArray: () => Promise<Array<Record<string, unknown>>> } {
    return { toArray: async () => [...this.documents.values()].map(document => structuredClone(document)) };
  }

  async findOne(filter: Record<string, unknown>): Promise<Record<string, unknown> | null> {
    const document = this.documents.get(String(filter._id));
    return document ? structuredClone(document) : null;
  }

  async bulkWrite(operations: Array<Record<string, unknown>>): Promise<{
    matchedCount: number;
    modifiedCount: number;
    upsertedCount: number;
  }> {
    let matchedCount = 0;
    let upsertedCount = 0;
    for (const operation of operations) {
      if ('replaceOne' in operation) {
        const replaceOne = operation.replaceOne as {
          filter: Record<string, unknown>;
          replacement: Record<string, unknown>;
          upsert: boolean;
        };
        const id = String(replaceOne.filter._id);
        const existing = this.documents.get(id);
        const matches = existing && Object.entries(replaceOne.filter).every(([key, expected]) => {
          if (typeof expected === 'object' && expected !== null && '$exists' in expected) {
            return (key in existing) === (expected as { $exists: boolean }).$exists;
          }
          return existing[key] === expected;
        });
        if (matches) {
          this.documents.set(id, structuredClone(replaceOne.replacement));
          matchedCount += 1;
        } else if (!existing && replaceOne.upsert) {
          this.documents.set(id, structuredClone(replaceOne.replacement));
          upsertedCount += 1;
        } else if (existing && replaceOne.upsert) {
          throw new Error('Duplicate key');
        }
      } else if ('deleteOne' in operation) {
        const deleteOne = operation.deleteOne as { filter: { _id: string } };
        this.documents.delete(deleteOne.filter._id);
      }
    }
    return { matchedCount, modifiedCount: matchedCount, upsertedCount };
  }

  async updateOne(
    filter: { _id: string },
    update: { $setOnInsert: Record<string, unknown> },
    options: { upsert: boolean }
  ): Promise<{ upsertedCount: number }> {
    if (this.documents.has(filter._id) || !options.upsert) return { upsertedCount: 0 };
    this.documents.set(filter._id, structuredClone(update.$setOnInsert));
    return { upsertedCount: 1 };
  }
}

class MemoryDatabase {
  public readonly collections = new Map<string, MemoryCollection>();
  public transactionCount = 0;
  public readonly client = {
    startSession: () => ({
      withTransaction: async (callback: () => Promise<void>) => {
        this.transactionCount += 1;
        await callback();
      },
      endSession: async () => undefined
    })
  };

  collection(name: string): MemoryCollection {
    let collection = this.collections.get(name);
    if (!collection) {
      collection = new MemoryCollection();
      this.collections.set(name, collection);
    }
    return collection;
  }
}

process.env.NODE_ENV = 'test';

test('Mongo storage initializes indexes and persists CRUD and settings across engine instances', async () => {
  const { StorageEngine } = await import('../src/server/storage.js');
  const database = new MemoryDatabase();
  const first = new StorageEngine(undefined, false, database as unknown as Db);
  await first.initialize();

  const now = new Date().toISOString();
  await first.addServer({
    id: 'mongo-server',
    name: 'Mongo test server',
    description: 'isolated persistence fixture',
    environment: 'development',
    transportType: 'synthetic',
    connectionMode: 'simulated_adapter',
    trustStatus: 'untrusted',
    approvalStatus: 'unapproved',
    isSimulated: true,
    lastCheckedAt: now,
    createdAt: now,
    updatedAt: now
  });
  await first.updateSettings({ maxPayloadMb: 4, anomalyThreshold: 5 });

  const second = new StorageEngine(undefined, false, database as unknown as Db);
  await second.initialize();
  assert.equal(second.getServerById('mongo-server')?.name, 'Mongo test server');
  assert.deepEqual(second.getSettings(), {
    defaultDeny: true,
    maxPayloadMb: 4,
    anomalyThreshold: 5
  });
  assert.ok(database.collections.get('mcp_tools')?.indexes.includes('server_tool_unique'));
});

test('related approval, request, and audit writes use a transaction and omit raw payloads', async () => {
  const { StorageEngine } = await import('../src/server/storage.js');
  const database = new MemoryDatabase();
  const storage = new StorageEngine(undefined, false, database as unknown as Db);
  await storage.initialize();
  const createdAt = new Date().toISOString();

  await storage.createPendingApproval(
    {
      id: 'approval-1',
      requestId: 'request-1',
      requesterId: 'requester',
      requesterRole: 'Administrator',
      serverId: 'server-1',
      toolName: 'write_record',
      operation: 'Write',
      parametersRedacted: {},
      riskFactors: [],
      riskScore: 60,
      policyReason: 'Review required',
      requestFingerprint: 'fingerprint',
      status: 'PENDING',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      createdAt
    },
    {
      id: 'security-request-1',
      requestId: 'request-1',
      actorId: 'requester',
      actorRole: 'Administrator',
      serverId: 'server-1',
      toolName: 'write_record',
      arguments: { secret: 'must not be persisted' },
      operation: 'Write',
      decision: 'REQUIRE_APPROVAL',
      riskScore: 60,
      policyIds: [],
      executionStatus: 'pending_approval',
      sanitizedOutput: { token: 'must not be persisted' },
      createdAt
    },
    {
      id: 'event-1',
      eventId: 'event-id-1',
      requestId: 'request-1',
      eventType: 'APPROVAL_DISPATCHED',
      severity: 'Medium',
      actorId: 'requester',
      serverId: 'server-1',
      toolName: 'write_record',
      decision: 'REQUIRE_APPROVAL',
      evidenceSummary: 'Approval requested.',
      createdAt
    }
  );

  const storedRequest = database.collections.get('security_requests')?.documents.get('security-request-1');
  assert.deepEqual(storedRequest?.arguments, {});
  assert.equal('sanitizedOutput' in (storedRequest || {}), false);
  assert.equal(database.transactionCount, 1);
  const reopened = new StorageEngine(undefined, false, database as unknown as Db);
  await reopened.initialize();
  assert.equal(reopened.getApprovalById('approval-1')?.status, 'PENDING');
  assert.equal(reopened.getEvents()[0]?.eventId, 'event-id-1');
});

test('Mongo configuration errors are explicit, redacted, and client connections are reused', async () => {
  const { closeMongo, initializeMongo } = await import('../src/server/mongo.js');
  await closeMongo();
  await assert.rejects(
    initializeMongo({}),
    /MONGODB_URI and MONGODB_DB_NAME must be configured/
  );

  let factoryCalls = 0;
  let closeCalls = 0;
  const fakeDatabase = { command: async () => ({ ok: 1 }) };
  const fakeClient = {
    on: () => fakeClient,
    connect: async () => fakeClient,
    db: () => fakeDatabase,
    close: async () => { closeCalls += 1; }
  };
  const factory = (_uri: string, _options: MongoClientOptions) => {
    factoryCalls += 1;
    return fakeClient as unknown as MongoClient;
  };
  const env = {
    MONGODB_URI: 'mongodb://user:password@localhost:27017',
    MONGODB_DB_NAME: 'sentinel_test'
  };
  const first = await initializeMongo(env, {}, factory);
  const second = await initializeMongo(env, {}, factory);
  assert.equal(first, second);
  assert.equal(factoryCalls, 1);
  await closeMongo();
  assert.equal(closeCalls, 1);

  await assert.rejects(
    initializeMongo(env, {}, () => {
      throw new Error('mongodb://user:password@localhost leaked');
    }),
    error => {
      assert.match((error as Error).message, /Failed to connect to MongoDB/);
      assert.equal((error as Error).message.includes('password'), false);
      return true;
    }
  );
  await closeMongo();
});

test('JSON migration validates input and uses repeatable insert-only upserts', async () => {
  const { migrateLegacyDatabase, validateLegacyDatabase } = await import('../src/server/migrateJsonToMongo.js');
  const database = new MemoryDatabase();
  const now = new Date().toISOString();
  const source = {
    servers: [{
      id: 'legacy-server',
      name: 'Legacy server',
      description: 'migration fixture',
      environment: 'development',
      transportType: 'synthetic',
      connectionMode: 'simulated_adapter',
      trustStatus: 'untrusted',
      approvalStatus: 'unapproved',
      isSimulated: true,
      lastCheckedAt: now,
      createdAt: now,
      updatedAt: now
    }],
    tools: [],
    policies: [],
    requests: [],
    events: [],
    findings: [],
    approvals: [],
    incidents: [],
    scenarios: [],
    testRuns: [],
    identities: [],
    syntheticData: {
      inventory: [],
      shipments: [],
      documents: [],
      financialReports: [],
      externalTransferLog: []
    }
  };
  assert.equal(validateLegacyDatabase(source), true);
  assert.equal(validateLegacyDatabase({ ...source, servers: [{ ...source.servers[0], id: '' }] }), false);

  const first = await migrateLegacyDatabase(database as unknown as Db, source, false);
  const second = await migrateLegacyDatabase(database as unknown as Db, source, false);
  assert.equal(first.imported, 3);
  assert.equal(first.skipped, 0);
  assert.equal(second.imported, 0);
  assert.equal(second.skipped, 3);
  assert.equal(second.failed, 0);
  assert.equal(database.collections.get('mcp_servers')?.documents.size, 1);
});
