import crypto from 'crypto';
import type { NextFunction, Request, Response } from 'express';
import type { UserRole } from '../types/index.js';

export type Permission =
  | 'gateway.read'
  | 'gateway.execute'
  | 'servers.read'
  | 'servers.manage'
  | 'tools.read'
  | 'tools.manage'
  | 'policies.read'
  | 'policies.manage'
  | 'approvals.read'
  | 'approvals.decide'
  | 'incidents.read'
  | 'incidents.investigate'
  | 'incidents.contain'
  | 'incidents.resolve'
  | 'incidents.recover'
  | 'audit.read'
  | 'identities.read'
  | 'identities.manage'
  | 'security-tests.read'
  | 'security-tests.run'
  | 'supply-chain.scan'
  | 'system.manage';

export interface AuthenticatedPrincipal {
  subject: string;
  role: UserRole;
}

interface ApiCredential {
  tokenHash: Buffer;
  principal: AuthenticatedPrincipal;
}

export interface ApiTokenConfig {
  credentials: ApiCredential[];
}

declare global {
  namespace Express {
    interface Request {
      authPrincipal?: AuthenticatedPrincipal;
    }
  }
}

const VALID_ROLES: readonly UserRole[] = [
  'Administrator',
  'Security Analyst',
  'Approver',
  'Read-only Auditor'
];

const ROLE_PERMISSIONS: Record<UserRole, ReadonlySet<Permission>> = {
  Administrator: new Set([
    'gateway.read', 'gateway.execute',
    'servers.read', 'servers.manage',
    'tools.read', 'tools.manage',
    'policies.read', 'policies.manage',
    'approvals.read', 'approvals.decide',
    'incidents.read', 'incidents.investigate', 'incidents.contain', 'incidents.resolve', 'incidents.recover',
    'audit.read', 'identities.read', 'identities.manage',
    'security-tests.read', 'security-tests.run',
    'supply-chain.scan', 'system.manage'
  ]),
  'Security Analyst': new Set([
    'gateway.read', 'gateway.execute',
    'servers.read', 'tools.read', 'policies.read', 'approvals.read',
    'incidents.read', 'incidents.investigate',
    'audit.read', 'identities.read',
    'security-tests.read', 'security-tests.run', 'supply-chain.scan'
  ]),
  Approver: new Set([
    'gateway.read', 'servers.read', 'tools.read', 'policies.read',
    'approvals.read', 'approvals.decide',
    'incidents.read', 'audit.read', 'security-tests.read'
  ]),
  'Read-only Auditor': new Set([
    'gateway.read', 'servers.read', 'tools.read', 'policies.read',
    'approvals.read', 'incidents.read', 'audit.read',
    'security-tests.read', 'identities.read'
  ])
};

function hashToken(token: string): Buffer {
  return crypto.createHash('sha256').update(token, 'utf8').digest();
}

export function createApiTokenConfig(entries: unknown): ApiTokenConfig {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > 100) {
    throw new Error('SENTINEL_API_TOKENS must be a non-empty array with at most 100 credentials.');
  }

  const credentials: ApiCredential[] = [];
  const subjects = new Map<string, UserRole>();

  for (const entry of entries) {
    if (typeof entry !== 'object' || entry === null) {
      throw new Error('Each API credential must have a 64-character hexadecimal token, a valid subject, and a supported role.');
    }

    const candidate = entry as Record<string, unknown>;
    if (
      typeof candidate.token !== 'string' ||
      !/^[a-f0-9]{64}$/i.test(candidate.token) ||
      typeof candidate.subject !== 'string' ||
      !/^[a-zA-Z0-9._:@-]{1,128}$/.test(candidate.subject) ||
      typeof candidate.role !== 'string' ||
      !VALID_ROLES.includes(candidate.role as UserRole)
    ) {
      throw new Error('Each API credential must have a 64-character hexadecimal token, a valid subject, and a supported role.');
    }

    const role = candidate.role as UserRole;
    const token = candidate.token;
    const subject = candidate.subject;
    const existingRole = subjects.get(subject);
    if (existingRole && existingRole !== role) {
      throw new Error('An API credential subject cannot be configured with multiple roles.');
    }

    const tokenHash = hashToken(token);
    if (credentials.some((credential) => crypto.timingSafeEqual(credential.tokenHash, tokenHash))) {
      throw new Error('API credential tokens must be unique.');
    }

    subjects.set(subject, role);
    credentials.push({
      tokenHash,
      principal: { subject, role }
    });
  }

  return { credentials };
}

export function loadApiTokenConfig(
  env: NodeJS.ProcessEnv,
  log: (message: string) => void = console.info
): ApiTokenConfig {
  const configuredTokens = env.SENTINEL_API_TOKENS;
  if (configuredTokens) {
    let entries: unknown;
    try {
      entries = JSON.parse(configuredTokens);
    } catch {
      throw new Error('SENTINEL_API_TOKENS must contain valid JSON.');
    }
    return createApiTokenConfig(entries);
  }

  if (env.NODE_ENV === 'production') {
    throw new Error('SENTINEL_API_TOKENS must be configured before starting in production.');
  }

  const token = crypto.randomBytes(32).toString('hex');
  const approverToken = crypto.randomBytes(32).toString('hex');
  const config = createApiTokenConfig([{
    token,
    subject: 'local-admin',
    role: 'Administrator'
  }, {
    token: approverToken,
    subject: 'local-approver',
    role: 'Approver'
  }]);
  log(`[SENTINEL-MCP] Temporary local administrator token (not saved): ${token}`);
  log(`[SENTINEL-MCP] Temporary local approver token (not saved): ${approverToken}`);
  return config;
}

export function resolveBearerPrincipal(
  authorizationHeader: string | undefined,
  config: ApiTokenConfig
): AuthenticatedPrincipal | undefined {
  const match = authorizationHeader?.match(/^Bearer ([^\s]+)$/i);
  if (!match || !/^[a-f0-9]{64}$/i.test(match[1])) return undefined;

  const suppliedHash = hashToken(match[1]);
  let principal: AuthenticatedPrincipal | undefined;
  for (const credential of config.credentials) {
    if (crypto.timingSafeEqual(suppliedHash, credential.tokenHash)) {
      principal = credential.principal;
    }
  }
  return principal;
}

export function hasPermission(role: UserRole, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].has(permission);
}

export function hasConfiguredPrincipal(
  config: ApiTokenConfig,
  subject: string,
  role: UserRole
): boolean {
  return config.credentials.some(credential =>
    credential.principal.subject === subject && credential.principal.role === role
  );
}

function permissionForRequest(request: Request): Permission {
  const { method, path } = request;

  if (method === 'GET') {
    if (path === '/stats' || path === '/auth/session' || path === '/requests' || path === '/findings') return 'gateway.read';
    if (path === '/settings') return 'gateway.read';
    if (path === '/servers') return 'servers.read';
    if (path === '/tools') return 'tools.read';
    if (path === '/policies') return 'policies.read';
    if (path === '/approvals' || /^\/approvals\/[^/]+$/.test(path)) return 'approvals.read';
    if (path === '/incidents' || /^\/incidents\/[^/]+$/.test(path)) return 'incidents.read';
    if (path === '/audit-logs') return 'audit.read';
    if (path === '/tests/scenarios' || path === '/tests/runs') return 'security-tests.read';
    if (path === '/identities') return 'identities.read';
  }

  if (method === 'PATCH' && path === '/settings') return 'system.manage';

  if (method === 'POST') {
    if (path === '/servers' || /^\/servers\/[^/]+\/(?:toggle-trust|quarantine|discover)$/.test(path)) return 'servers.manage';
    if (/^\/tools\/[^/]+\/(?:tamper|restore|approve)$/.test(path)) return 'tools.manage';
    if (path === '/policies' || /^\/policies\/[^/]+\/toggle$/.test(path)) return 'policies.manage';
    if (/^\/policies\/[^/]+$/.test(path) && method === 'POST') return 'policies.manage';
    if (path === '/gateway/evaluate') return 'gateway.execute';
    if (/^\/approvals\/[^/]+\/decide$/.test(path)) return 'approvals.decide';
    if (path === '/incidents') return 'incidents.investigate';
    if (/^\/incidents\/[^/]+\/investigate$/.test(path)) return 'incidents.investigate';
    if (/^\/incidents\/[^/]+\/contain$/.test(path)) return 'incidents.contain';
    if (/^\/incidents\/[^/]+\/resolve$/.test(path)) return 'incidents.resolve';
    if (/^\/incidents\/[^/]+\/release-containment$/.test(path)) return 'incidents.recover';
    if (path === '/tests/run' || path === '/tests/run-all') return 'security-tests.run';
    if (path === '/scanner/scan') return 'supply-chain.scan';
    if (path === '/system/reset-demo') return 'system.manage';
  }

  if (method === 'PUT') {
    if (/^\/policies\/[^/]+$/.test(path)) return 'policies.manage';
    if (/^\/incidents\/[^/]+$/.test(path)) return 'incidents.investigate';
  }

  return 'system.manage';
}

export function createAuthenticationMiddleware(config: ApiTokenConfig) {
  return (request: Request, response: Response, next: NextFunction): void => {
    const principal = resolveBearerPrincipal(request.get('authorization'), config);
    if (!principal) {
      response.setHeader('WWW-Authenticate', 'Bearer realm="Sentinel-MCP"');
      response.status(401).json({ error: 'Authentication required or credentials are invalid.' });
      return;
    }

    request.authPrincipal = principal;
    next();
  };
}

export function createAuthorizationMiddleware() {
  return (request: Request, response: Response, next: NextFunction): void => {
    const principal = request.authPrincipal;
    if (!principal || !hasPermission(principal.role, permissionForRequest(request))) {
      response.status(403).json({ error: 'The authenticated identity is not authorized for this operation.' });
      return;
    }
    next();
  };
}

export function requirePrincipal(request: Request): AuthenticatedPrincipal {
  if (!request.authPrincipal) {
    throw new Error('Authenticated principal is missing after API authentication middleware.');
  }
  return request.authPrincipal;
}
