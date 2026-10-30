import { Db, MongoClient, MongoClientOptions } from 'mongodb';

let client: MongoClient | undefined;
let database: Db | undefined;
let connection: Promise<Db> | undefined;

export async function initializeMongo(
  env: NodeJS.ProcessEnv = process.env,
  options: Pick<MongoClientOptions, 'connectTimeoutMS' | 'serverSelectionTimeoutMS'> = {},
  clientFactory: (uri: string, options: MongoClientOptions) => MongoClient =
    (uri, clientOptions) => new MongoClient(uri, clientOptions)
): Promise<Db> {
  if (database) return database;
  if (connection) return connection;

  const uri = env.MONGODB_URI;
  const databaseName = env.MONGODB_DB_NAME;
  if (!uri || !databaseName?.trim()) {
    throw new Error('MONGODB_URI and MONGODB_DB_NAME must be configured before starting Sentinel-MCP.');
  }

  connection = (async () => {
    let mongoClient: MongoClient | undefined;
    try {
      mongoClient = clientFactory(uri, {
        connectTimeoutMS: options.connectTimeoutMS ?? 10_000,
        serverSelectionTimeoutMS: options.serverSelectionTimeoutMS ?? 10_000,
        socketTimeoutMS: 45_000,
        maxPoolSize: 20,
        retryWrites: true
      });
      client = mongoClient;
      mongoClient.on('error', () => {
        console.error('[SENTINEL-MCP] MongoDB connection error.');
      });
      await mongoClient.connect();
      const db = mongoClient.db(databaseName);
      await db.command({ ping: 1 });
      database = db;
      return db;
    } catch (error) {
      client = undefined;
      if (mongoClient) {
        try {
          await mongoClient.close();
        } catch {
          console.error('[SENTINEL-MCP] MongoDB connection cleanup failed.');
        }
      }
      throw new Error('Failed to connect to MongoDB. Verify database availability and connection settings.', {
        cause: error
      });
    }
  })();

  try {
    return await connection;
  } catch (error) {
    connection = undefined;
    throw error;
  }
}

export function getMongoDatabase(): Db {
  if (!database) {
    throw new Error('MongoDB has not been initialized.');
  }
  return database;
}

export async function closeMongo(): Promise<void> {
  const activeClient = client;
  client = undefined;
  database = undefined;
  connection = undefined;
  if (activeClient) await activeClient.close();
}
