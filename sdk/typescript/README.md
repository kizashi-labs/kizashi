# @kizashi-edr/client — TypeScript SDK

Official TypeScript client for the **Kizashi** REST API.

## Requirements

- Node.js >= 18 (uses the built-in `fetch` API)
- TypeScript >= 5.0 (for type-checking source directly)

## Installation

```bash
npm install @kizashi-edr/client
```

## Development

```bash
npm install       # installs vitest as a devDependency
npm run typecheck
npm test          # runs the vitest suite (src/client.test.ts)
```

CI runs both this suite and the Python SDK's `pytest` suite in the `sdk-test` job
(`.github/workflows/ci.yml`).

## Authentication

The SDK uses **Bearer token** authentication. Obtain a token by calling
`POST /api/v1/auth/login`, then pass it as `apiKey` to the constructor.
The token is sent as `Authorization: Bearer <apiKey>` on every request.

```typescript
import { KizashiEDRClient } from '@kizashi-edr/client';

const client = new KizashiEDRClient({
  baseUrl: 'https://api.kizashi-edr.example.com',
  apiKey: 'edr_your_jwt_token_here',
  timeout: 15_000, // optional, default 30 000 ms
});
```

## Usage examples

### Alerts

```typescript
// List open alerts with high or critical severity
const { data: alerts, total } = await client.alerts.list({
  status: 'open',
  severity: 'high',
  limit: 20,
  offset: 0,
});
console.log(`${total} alerts found`);

// Fetch a single alert
const alert = await client.alerts.get('3fa85f64-5717-4562-b3fc-2c963f66afa6');

// Update alert status
const updated = await client.alerts.update(alert.id, {
  status: 'investigating',
  assigned_to: 'analyst@example.com',
});
```

### Agents

```typescript
// List all online agents
const { data: agents } = await client.agents.list({ status: 'online' });

// Fetch a single agent
const agent = await client.agents.get('3fa85f64-5717-4562-b3fc-2c963f66afa6');

// Isolate a compromised endpoint
await client.agents.isolate(agent.id);

// Lift isolation after remediation
await client.agents.release(agent.id);
```

### Incidents

```typescript
// List all incidents
const { data: incidents } = await client.incidents.list();

// Create a new incident
const incident = await client.incidents.create({
  title: 'Ransomware suspected on DESKTOP-ABC',
  severity: 'critical',
  description: 'Multiple encrypted files detected alongside lateral movement.',
});

// Fetch a single incident
const detail = await client.incidents.get(incident.id);
```

### Detection Rules

```typescript
// List Sigma rules
const sigmaRules = await client.rules.listSigma();

// List YARA rules
const yaraRules = await client.rules.listYara();

// Create a new detection rule
const rule = await client.rules.create({
  name: 'Suspicious PowerShell Encoded Command',
  type: 'sigma',
  severity: 'high',
  condition: '| encodedCommand',
  enabled: true,
});
```

### Indicators of Compromise (IOC)

```typescript
// List existing IOC entries
const iocList = await client.ioc.list();

// Import new IOCs in bulk
await client.ioc.import([
  { type: 'ip', value: '198.51.100.42', severity: 'high', description: 'C2 server' },
  { type: 'domain', value: 'malicious.example.net', severity: 'critical' },
  { type: 'sha256', value: 'e3b0c44298fc1c149afb...', severity: 'medium' },
]);
```

## Error handling

```typescript
import { EDRAPIError } from '@kizashi-edr/client';

try {
  const alert = await client.alerts.get('nonexistent-id');
} catch (err) {
  if (err instanceof EDRAPIError) {
    console.error(`API error ${err.status}: ${err.message}`);
    // err.status — HTTP status code (e.g. 404, 401, 403)
    // err.body   — raw response body
  } else {
    throw err; // network / timeout errors
  }
}
```

## API reference

All methods are fully typed. Hover over any method in your editor to see
parameter and return-type documentation generated from JSDoc comments.

| Namespace | Methods |
|-----------|---------|
| `client.alerts` | `list(filter?)`, `get(id)`, `update(id, data)` |
| `client.agents` | `list(filter?)`, `get(id)`, `isolate(id)`, `release(id)` |
| `client.incidents` | `list()`, `get(id)`, `create(data)` |
| `client.rules` | `listSigma()`, `listYara()`, `create(data)` |
| `client.ioc` | `list()`, `import(entries[])` |
