import crypto from 'crypto';

let key: Buffer | undefined;

function getKey(): Buffer {
  if (key) return key;

  const configuredKey = process.env.SENTINEL_APPROVAL_ENCRYPTION_KEY;
  if (configuredKey) {
    if (!/^[a-f0-9]{64}$/i.test(configuredKey)) {
      throw new Error('SENTINEL_APPROVAL_ENCRYPTION_KEY must be exactly 64 hexadecimal characters.');
    }
    key = Buffer.from(configuredKey, 'hex');
    return key;
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error('SENTINEL_APPROVAL_ENCRYPTION_KEY must be configured before starting in production.');
  }

  key = crypto.randomBytes(32);
  console.warn('[SENTINEL-MCP] Approval arguments use a temporary process-local encryption key; pending approvals cannot be resumed after restart unless SENTINEL_APPROVAL_ENCRYPTION_KEY is configured.');
  return key;
}

export function initializeApprovalEncryptionKey(): void {
  getKey();
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  const entries = Object.keys(record).sort().map((entry) => (
    `${JSON.stringify(entry)}:${canonicalJson(record[entry])}`
  ));
  return `{${entries.join(',')}}`;
}

export function encryptApprovalArguments(arguments_: Record<string, unknown>) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  const ciphertext = Buffer.concat([
    cipher.update(canonicalJson(arguments_), 'utf8'),
    cipher.final()
  ]);
  return {
    iv: iv.toString('hex'),
    authTag: cipher.getAuthTag().toString('hex'),
    ciphertext: ciphertext.toString('hex')
  };
}

export function decryptApprovalArguments(encrypted: {
  iv: string;
  authTag: string;
  ciphertext: string;
}): Record<string, unknown> {
  if (
    !/^[a-f0-9]{24}$/i.test(encrypted.iv) ||
    !/^[a-f0-9]{32}$/i.test(encrypted.authTag) ||
    !/^(?:[a-f0-9]{2})*$/i.test(encrypted.ciphertext)
  ) {
    throw new Error('Stored approval arguments are malformed.');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), Buffer.from(encrypted.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(encrypted.authTag, 'hex'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, 'hex')),
    decipher.final()
  ]).toString('utf8');
  const parsed: unknown = JSON.parse(plaintext);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Stored approval arguments are not a valid object.');
  }
  return parsed as Record<string, unknown>;
}

export function fingerprintApprovalOperation(operation: {
  requestId: string;
  requesterId: string;
  requesterRole: string;
  serverId: string;
  toolId: string;
  toolName: string;
  toolFingerprint: string;
  arguments: Record<string, unknown>;
  destination?: string;
  policyVersions: Record<string, string>;
}): string {
  return crypto.createHash('sha256').update(canonicalJson(operation)).digest('hex');
}
