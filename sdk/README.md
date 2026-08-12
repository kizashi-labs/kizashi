# Kizashi — Client SDKs

This directory contains official client SDKs for the **Kizashi** REST API.

## Available SDKs

| Language | Directory | Package name |
|----------|-----------|--------------|
| TypeScript / Node.js | [`typescript/`](typescript/) | `@kizashi-edr/client` |
| Python | [`python/`](python/) | `kizashi-edr-client` |

## API overview

- **Base URL (production):** `https://api.kizashi-edr.example.com`
- **Base URL (development):** `http://localhost:8080`
- **API version prefix:** `/api/v1/`
- **Rate limits:** 1 000 req/min (authenticated), 10 req/min (auth endpoints)

## Authentication

All protected endpoints require a JWT bearer token.

**Step 1 — obtain a token:**

```http
POST /api/v1/auth/login
Content-Type: application/json

{"email": "admin@example.com", "password": "Password123!"}
```

Response:
```json
{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "user": {...}}
```

**Step 2 — pass it to the SDK constructor** as `apiKey` (TypeScript) or
`api_key` (Python). The SDK automatically sends it as:

```
Authorization: Bearer <token>
```

## Quick start

### TypeScript

```typescript
import { KizashiEDRClient } from '@kizashi-edr/client';

const client = new KizashiEDRClient({
  baseUrl: 'https://api.kizashi-edr.example.com',
  apiKey: 'edr_your_token_here',
});

const { data: alerts } = await client.alerts.list({ status: 'open', severity: 'high' });
```

See [typescript/README.md](typescript/README.md) for full documentation.

### Python

```python
from kizashi_edr import KizashiEDRClient

client = KizashiEDRClient(
    base_url='https://api.kizashi-edr.example.com',
    api_key='edr_your_token_here',
)

alerts = client.alerts.list(status='open', severity='high')
```

See [python/README.md](python/README.md) for full documentation.

## Resource groups

Both SDKs expose the same set of resource namespaces:

| Namespace (TS) | Namespace (Python) | Key operations |
|----------------|--------------------|----------------|
| `alerts` | `alerts` | `list`, `get`, `classify`, `bulk_classify` |
| `agents` | `agents` | `list`, `get`, `isolate`, `unisolate` |
| `incidents` | `incidents` | `list`, `get`, `create`, `update` |
| `rules` | `rules` | `list`, `create`, `get`, `update`, `delete` |
| `vulnerabilities` | `vulnerabilities` | `list`, `get`, `stats` |
| `apiKeys` | `api_keys` | `list`, `create`, `revoke` |
| `liveResponse` | `live_response` | `list`, `open`, `exec` |
| `ioc` | `ioc` | `list`, bulk import |

### incidents.update

Patch an incident's status, assignee, or description:

```typescript
// TypeScript
await client.incidents.update("INC-001", {
  status: "in_progress",
  assigned_to: "analyst@example.com",
});
```

```python
# Python
client.incidents.update("INC-001", status="in_progress", assigned_to="analyst@example.com")
```

### rules CRUD

```typescript
// TypeScript — get / update / delete a rule
const rule = await client.rules.get("rule-uuid");
await client.rules.update("rule-uuid", { enabled: false });
await client.rules.delete("rule-uuid");
```

```python
# Python
rule = client.rules.get("rule-uuid")
client.rules.update("rule-uuid", enabled=False)
client.rules.delete("rule-uuid")
```

## Error handling

Both SDKs raise an `EDRError` / `EDRAPIError` exception containing the HTTP status code and error message from the API.

```typescript
// TypeScript
import { EDRError } from '@kizashi-edr/client';
try { ... } catch (err) {
  if (err instanceof EDRError) console.error(err.status, err.message);
}
```

```python
# Python
from kizashi_edr import EDRError
try: ...
except EDRError as exc:
    print(exc.status_code, str(exc))
```

## Directory structure

```
sdk/
├── README.md                   ← this file
├── typescript/
│   ├── package.json
│   ├── README.md
│   └── src/
│       └── client.ts           ← main SDK source
└── python/
    ├── setup.py
    ├── README.md
    └── kizashi_edr/
        └── __init__.py         ← main SDK source
```
