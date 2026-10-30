import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import Ajv from 'ajv';
import crypto from 'node:crypto';
import type { MCPServer, MCPTool, ToolInputSchema } from '../types/index.js';

const MCP_REQUEST_TIMEOUT_MS = 15_000;
const MAX_MCP_RESPONSE_BYTES = 2 * 1024 * 1024;
const schemaValidator = new Ajv({ allErrors: true, strict: false });

export class McpConnectionError extends Error {
  constructor(
    message: string,
    public readonly executionUncertain = false,
    public readonly executionDispatched = false,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = 'McpConnectionError';
  }
}

export interface DiscoveredMcpTool {
  name: string;
  description: string;
  inputSchema: ToolInputSchema;
  fingerprint: string;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
}

export function validateMcpEndpoint(endpoint: string, env: NodeJS.ProcessEnv = process.env): URL {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new McpConnectionError('The configured MCP endpoint is not a valid URL.');
  }

  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.hash ||
    url.hostname.length === 0
  ) {
    throw new McpConnectionError('MCP endpoints must be HTTP(S) URLs without embedded credentials or fragments.');
  }

  const isProduction = env.NODE_ENV === 'production';
  if (isProduction) {
    if (url.protocol !== 'https:') {
      throw new McpConnectionError('Production MCP endpoints must use HTTPS.');
    }
    const allowedHosts = (env.SENTINEL_MCP_ALLOWED_HOSTS || '')
      .split(',')
      .map(host => host.trim().toLowerCase())
      .filter(Boolean);
    if (allowedHosts.length === 0 || !allowedHosts.includes(url.host.toLowerCase())) {
      throw new McpConnectionError('The MCP endpoint host is not present in SENTINEL_MCP_ALLOWED_HOSTS.');
    }
  } else if (url.protocol !== 'https:' && !isLoopbackHost(url.hostname)) {
    throw new McpConnectionError('Development HTTP MCP endpoints are restricted to loopback hosts.');
  }
  return url;
}

function serverToken(serverId: string): string | undefined {
  const configured = process.env.SENTINEL_MCP_SERVER_TOKENS;
  if (!configured) return undefined;
  let tokens: unknown;
  try {
    tokens = JSON.parse(configured);
  } catch {
    throw new McpConnectionError('SENTINEL_MCP_SERVER_TOKENS must contain a JSON object.');
  }
  if (typeof tokens !== 'object' || tokens === null || Array.isArray(tokens)) {
    throw new McpConnectionError('SENTINEL_MCP_SERVER_TOKENS must contain a JSON object.');
  }
  const token = (tokens as Record<string, unknown>)[serverId];
  if (
    typeof token !== 'undefined' &&
    (typeof token !== 'string' || token.length < 16 || token.length > 4096 || /[\r\n]/.test(token))
  ) {
    throw new McpConnectionError(`The configured MCP credential for server ${serverId} is invalid.`);
  }
  return token as string | undefined;
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJson);
  if (typeof value !== 'object' || value === null) {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new McpConnectionError('MCP tool definitions must contain only finite JSON numbers.');
    }
    if (typeof value === 'undefined' || typeof value === 'function' || typeof value === 'bigint') {
      throw new McpConnectionError('MCP tool definitions must be JSON serializable.');
    }
    return value;
  }
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = sortJson((value as Record<string, unknown>)[key]);
  }
  return sorted;
}

export function computeMcpToolFingerprint(tool: {
  name: string;
  description: string;
  inputSchema: ToolInputSchema;
}): string {
  const canonicalTool = sortJson(tool);
  return crypto.createHash('sha256').update(JSON.stringify(canonicalTool)).digest('hex');
}

function normalizeToolSchema(value: unknown): ToolInputSchema {
  if (
    typeof value !== 'object' || value === null || Array.isArray(value) ||
    (value as Record<string, unknown>).type !== 'object' ||
    typeof (value as Record<string, unknown>).properties !== 'object' ||
    (value as Record<string, unknown>).properties === null ||
    Array.isArray((value as Record<string, unknown>).properties)
  ) {
    throw new McpConnectionError('The MCP server returned an invalid tool input schema.');
  }
  const normalized = sortJson(value) as ToolInputSchema;
  if (normalized.required && (
    !Array.isArray(normalized.required) ||
    normalized.required.some(field => typeof field !== 'string')
  )) {
    throw new McpConnectionError('The MCP server returned an invalid required-field list.');
  }
  try {
    schemaValidator.compile(normalized);
  } catch (error) {
    throw new McpConnectionError('The MCP server returned a tool schema that cannot be validated.', false, false, { cause: error });
  }
  return normalized;
}

async function withClient<T>(server: MCPServer, operation: (client: Client) => Promise<T>): Promise<T> {
  if (!server.endpointUrl) throw new McpConnectionError('No MCP endpoint is configured for this server.');
  const url = validateMcpEndpoint(server.endpointUrl);
  const token = serverToken(server.id);
  const abortController = new AbortController();
  const timeout = setTimeout(() => abortController.abort(), MCP_REQUEST_TIMEOUT_MS);
  const client = new Client(
    { name: 'sentinel-mcp-gateway', version: '1.0.0' },
    { capabilities: {}, enforceStrictCapabilities: true }
  );
  const transport = new StreamableHTTPClientTransport(url, {
    requestInit: {
      redirect: 'error',
      signal: abortController.signal,
      headers: token ? { Authorization: `Bearer ${token}` } : undefined
    },
    reconnectionOptions: {
      maxReconnectionDelay: 1000,
      initialReconnectionDelay: 100,
      reconnectionDelayGrowFactor: 1,
      maxRetries: 0
    }
  });

  try {
    await client.connect(transport, { timeout: MCP_REQUEST_TIMEOUT_MS, signal: abortController.signal });
    return await operation(client);
  } catch (error) {
    if (error instanceof McpConnectionError) throw error;
    throw new McpConnectionError('The protected MCP server request failed before tool execution.', false, false, { cause: error });
  } finally {
    clearTimeout(timeout);
    await client.close();
  }
}

function mapDiscoveredTool(tool: {
  name: string;
  description?: string;
  inputSchema: unknown;
}): DiscoveredMcpTool {
  if (!/^[a-zA-Z0-9_.-]{1,128}$/.test(tool.name)) {
    throw new McpConnectionError('The MCP server returned a tool with an invalid name.');
  }
  const inputSchema = normalizeToolSchema(tool.inputSchema);
  const description = typeof tool.description === 'string' ? tool.description.slice(0, 4000) : '';
  return {
    name: tool.name,
    description,
    inputSchema,
    fingerprint: computeMcpToolFingerprint({ name: tool.name, description, inputSchema })
  };
}

export async function discoverMcpTools(server: MCPServer): Promise<DiscoveredMcpTool[]> {
  return withClient(server, async client => {
    const result = await client.listTools({}, {
      timeout: MCP_REQUEST_TIMEOUT_MS,
      maxTotalTimeout: MCP_REQUEST_TIMEOUT_MS
    });
    if (!Array.isArray(result.tools) || result.tools.length > 500) {
      throw new McpConnectionError('The MCP server returned an invalid or oversized tool list.');
    }
    const names = new Set<string>();
    return result.tools.map(tool => {
      const discovered = mapDiscoveredTool(tool);
      if (names.has(discovered.name)) {
        throw new McpConnectionError('The MCP server returned duplicate tool names.');
      }
      names.add(discovered.name);
      return discovered;
    });
  });
}

export async function callMcpTool(
  server: MCPServer,
  expectedTool: MCPTool,
  args: Record<string, unknown>
): Promise<{ data: unknown; evidence: string }> {
  return withClient(server, async client => {
    const listed = await client.listTools({}, {
      timeout: MCP_REQUEST_TIMEOUT_MS,
      maxTotalTimeout: MCP_REQUEST_TIMEOUT_MS
    });
    const remoteTool = listed.tools.find(tool => tool.name === expectedTool.name);
    if (!remoteTool) throw new McpConnectionError('The approved MCP tool is no longer available.');
    const observed = mapDiscoveredTool(remoteTool);
    if (observed.fingerprint !== expectedTool.definitionFingerprint) {
      throw new McpConnectionError('The MCP tool definition changed after approval; execution was blocked.');
    }

    let result;
    try {
      result = await client.callTool(
        { name: expectedTool.name, arguments: args },
        undefined,
        { timeout: MCP_REQUEST_TIMEOUT_MS, maxTotalTimeout: MCP_REQUEST_TIMEOUT_MS }
      );
    } catch (error) {
      throw new McpConnectionError(
        'The MCP tool call failed after dispatch; the remote execution outcome may be uncertain.',
        true,
        true,
        { cause: error }
      );
    }
    if (result.isError) {
      throw new McpConnectionError('The MCP server reported a tool execution error.', false, true);
    }
    const serialized = JSON.stringify(result);
    if (Buffer.byteLength(serialized, 'utf8') > MAX_MCP_RESPONSE_BYTES) {
      throw new McpConnectionError(
        'The MCP tool response exceeded the configured size limit; execution will not be retried.',
        true,
        true
      );
    }
    return {
      data: result.structuredContent ?? result.content,
      evidence: `Live MCP tool ${expectedTool.name} was invoked through the Sentinel gateway.`
    };
  });
}
