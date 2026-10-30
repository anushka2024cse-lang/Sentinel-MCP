# SENTINEL-MCP

Sentinel-MCP is a React dashboard and Express-based security gateway prototype for inspecting MCP-style tool requests.

## Run locally

**Prerequisite:** Node.js 20.19+ or 22.12+.

Runtime storage requires MongoDB. Configure `MONGODB_URI` and `MONGODB_DB_NAME` in a local `.env` file or your process environment. The URI is only read by the backend and must not be added to any `VITE_` variable. Use a replica set (including a single-node development replica set) or a sharded cluster: approval and incident state changes that span multiple documents are committed in MongoDB transactions.

```powershell
npm ci
$env:MONGODB_URI = "mongodb://127.0.0.1:27017/?replicaSet=rs0"
$env:MONGODB_DB_NAME = "sentinel_mcp"
npm run dev
```

For an existing JSON installation, first validate the migration without writing, then import it:

```powershell
npm run db:migrate -- --dry-run
npm run db:migrate
npm run dev
```

The migration reads `data/sentinel-db.json` without changing or deleting it. Override its location with `--file=<path>`. It validates collection shape, IDs, uniqueness, and server references, uses insert-only upserts, and reports imported, skipped, and failed document counts. Rerunning it will not overwrite MongoDB records. If the file is absent, skip migration; startup initializes an empty MongoDB database and does not seed demo data automatically.

The current `data/sentinel-db.json` contains duplicate request document IDs, so migration validation rejects it before connecting to MongoDB. Resolve the duplicate IDs in a reviewed copy and pass that copy with `--file=<path>`; the migration intentionally does not rewrite the source.

In development, the server binds to `127.0.0.1` and creates separate temporary Administrator and Approver API tokens for that process. Copy the desired token printed in the VS Code terminal into the sign-in page. Tokens are not saved and become invalid when the server restarts.

To configure fixed credentials instead, set `SENTINEL_API_TOKENS` to a JSON array of 64-character hexadecimal bearer tokens and server-assigned identities/roles. For example:

```powershell
$env:SENTINEL_API_TOKENS = '[{"token":"<64-hex-character-secret>","subject":"admin","role":"Administrator"}]'
npm run dev
```

Generate a token with:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Supported roles are `Administrator`, `Security Analyst`, `Approver`, and `Read-only Auditor`. Tokens are hashed in memory and never returned by the API. In production, `SENTINEL_API_TOKENS` and `SENTINEL_APPROVAL_ENCRYPTION_KEY` are required; provide them through a deployment secret manager, not a committed `.env` file. The encryption key must remain stable to resume pending approvals after restart. Rotating or revoking a configured API token currently requires changing the configuration and restarting the server. Use TLS at the deployment boundary.

Approvals bind encrypted original arguments to the requester, request, tool definition, and policy versions. A distinct authorized reviewer can approve and dispatch that exact operation after server-side revalidation; rejection, expiry, stale policy/tool/server state, and repeated decisions do not dispatch it. The API does not expose the encrypted argument payload. The current tool adapter remains simulated and is not a live MCP connection.

## Live MCP proxy

The gateway supports real MCP **Streamable HTTP** connections using `@modelcontextprotocol/sdk`. In the UI, register a server in `Live MCP · Streamable HTTP` mode with its endpoint, discover its tools, trust/approve the server, then review each discovered tool's capability, allowed roles, and approval requirement. Newly discovered tools remain unapproved and cannot execute until an administrator explicitly approves their current definition.

Every live call connects through the backend, verifies the server endpoint and current remote tool fingerprint, validates arguments against the registered JSON Schema, invokes the SDK tool call only after gateway checks, inspects the response, and records the result. Calls use a 15-second timeout and a 2 MiB response limit; automatic retry is disabled. A failure after dispatch is reported as an uncertain outcome to avoid duplicate side effects.

Production live MCP configuration requires `SENTINEL_MCP_ALLOWED_HOSTS` (comma-separated exact `host[:port]` values), HTTPS endpoints, and deployment-level network egress controls. Optional upstream bearer credentials are loaded from `SENTINEL_MCP_SERVER_TOKENS`, a JSON object keyed by Sentinel server ID; do not store these in the database. Configure upstream host and credential secrets in the deployment secret manager. Development allows HTTP only for loopback MCP endpoints. stdio, legacy SSE, and WebSocket servers are not currently connected as live transports; they remain simulation metadata only.

Deployment topology: callers authenticate to Sentinel's API; only the Sentinel backend should have network access to protected MCP endpoints. Enforce that boundary with firewall/security-group/egress proxy rules so callers cannot bypass Sentinel and connect directly. Host allowlisting alone does not prevent a compromised DNS or a network-level bypass.

Incident investigations expose correlated request, tool, policy, and audit evidence while keeping stored request arguments and outputs out of the incident detail response. Admin-only containment quarantines the affected server and is checked by the gateway independently of the server trust flag. Resolution preserves the containment lock; an administrator must explicitly release it, and server trust must also be re-established before calls are accepted.

MongoDB is the runtime system of record. The backend reuses one MongoDB client, initializes indexes at startup, and fails closed if the database is unavailable or configuration is missing. Related multi-document writes require transaction support; MongoDB standalone deployments will return an explicit transaction-support error when such a write is attempted. API bearer tokens, upstream MCP credentials, and approval encryption keys remain server-side configuration and are not persisted to MongoDB. Identity bearer-token material and full request arguments/output payloads are excluded from MongoDB documents.

The Settings page persists the maximum JSON payload size and denied-request anomaly threshold. The default-deny setting is a non-configurable security invariant and cannot be disabled. Runtime payload-size enforcement reads the persisted setting for each request; anomaly detection uses its saved threshold.

The old JSON format is retained only as an explicit migration source and isolated test fixture. Do not configure it as the runtime database. Run one gateway process per database for now: storage reads are loaded into a process-local cache at startup, so cross-process cache invalidation is not implemented.

## Checks

```powershell
npm test
npm run lint
npm run build
```

## Current limitations

- API identity is based on server-configured bearer credentials; there is no OIDC provider, user-facing credential issuance, token expiry, or live revocation.
- The identity and MCP server records currently stored in `data/sentinel-db.json` include prototype/demo data. Configured API identities, not those records or client-supplied role fields, determine API access.
- Real Streamable HTTP MCP calls are supported through the gateway; stdio, legacy SSE, and WebSocket transports remain simulated/unsupported.
- Incident notes, lifecycle transitions, server quarantine, and explicit containment recovery are persisted with audit events, but do not yet have durable database transactions across multiple processes.
- MongoDB transaction support depends on a replica set or sharded cluster. Cross-process cache invalidation and multi-instance operation are not implemented.
- Development uses a process-local fallback approval-encryption key; pending encrypted approvals cannot be resumed after a server restart unless a stable key is configured.
