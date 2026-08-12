# kizashi-edr-client — Python SDK

Official Python client for the **Kizashi** REST API.

## Requirements

- Python >= 3.9
- No external dependencies (uses only the standard library)

## Installation

```bash
pip install kizashi-edr-client
```

Or install directly from source:

```bash
pip install ./sdk/python
```

## Authentication

The SDK uses **Bearer token** authentication. Obtain a token by calling
`POST /api/v1/auth/login`, then pass it as `api_key` to the constructor.
The token is sent as `Authorization: Bearer <api_key>` on every request.

```python
from kizashi_edr import KizashiEDRClient

client = KizashiEDRClient(
    base_url='https://api.kizashi-edr.example.com',
    api_key='edr_your_jwt_token_here',
    timeout=15,  # optional, default 30 seconds
)
```

## Usage examples

### Alerts

```python
# List open alerts with high severity
result = client.alerts.list(status='open', severity='high', limit=20)
print(f"Found {result['total']} alerts")

for alert in result['data']:
    print(f"[{alert['severity'].upper()}] {alert['title']} — {alert['status']}")

# Fetch a single alert
alert = client.alerts.get('3fa85f64-5717-4562-b3fc-2c963f66afa6')

# Update alert status
updated = client.alerts.update(
    alert['id'],
    status='investigating',
    assigned_to='analyst@example.com',
)
```

### Agents

```python
# List all online agents
result = client.agents.list(status='online')
for agent in result['data']:
    print(f"{agent['hostname']} ({agent['ip_address']}) — {agent['status']}")

# Fetch a single agent
agent = client.agents.get('3fa85f64-5717-4562-b3fc-2c963f66afa6')

# Isolate a compromised endpoint
client.agents.isolate(agent['id'])

# Lift isolation after remediation
client.agents.release(agent['id'])
```

### Incidents

```python
# List all incidents
result = client.incidents.list()

# Create a new incident
incident = client.incidents.create(
    title='Ransomware suspected on DESKTOP-ABC',
    severity='critical',
    description='Multiple encrypted files detected alongside lateral movement.',
)
print(f"Created incident: {incident['id']}")

# Fetch a single incident
detail = client.incidents.get(incident['id'])
```

### Detection Rules

```python
# List Sigma rules
sigma_rules = client.rules.list_sigma()
for rule in sigma_rules:
    print(f"{rule['name']} — enabled: {rule['enabled']}")

# List YARA rules
yara_rules = client.rules.list_yara()

# Create a new detection rule
rule = client.rules.create(
    name='Suspicious PowerShell Encoded Command',
    rule_type='sigma',
    condition='| encodedCommand',
    severity='high',
    enabled=True,
)
```

### Indicators of Compromise (IOC)

```python
# List existing IOC entries
iocs = client.ioc.list()
for ioc in iocs:
    print(f"[{ioc['type']}] {ioc['value']} — {ioc.get('severity', 'unknown')}")

# Import IOCs in bulk
client.ioc.import_iocs([
    {'type': 'ip',     'value': '198.51.100.42',            'severity': 'high',     'description': 'C2 server'},
    {'type': 'domain', 'value': 'malicious.example.net',    'severity': 'critical'},
    {'type': 'sha256', 'value': 'e3b0c44298fc1c149afb...', 'severity': 'medium'},
])
```

## Error handling

```python
from kizashi_edr import KizashiEDRClient, EDRAPIError

try:
    alert = client.alerts.get('nonexistent-id')
except EDRAPIError as exc:
    print(f"API error {exc.status}: {exc.message}")
    # exc.status  — HTTP status code (e.g. 404, 401, 403)
    # exc.message — error description from the API
    # exc.body    — full parsed response body
```

## Dataclasses (optional)

The SDK provides convenience dataclasses for the main resources:

```python
from kizashi_edr import Alert, Agent, Incident

raw_alert = client.alerts.get('3fa85f64-...')
alert = Alert.from_dict(raw_alert)
print(alert.hostname, alert.severity)
```

## API reference

| Namespace | Methods |
|-----------|---------|
| `client.alerts` | `list(severity?, status?, limit?, offset?)`, `get(id)`, `update(id, *, status?, assigned_to?)` |
| `client.agents` | `list(status?, limit?, offset?)`, `get(id)`, `isolate(id)`, `release(id)` |
| `client.incidents` | `list()`, `get(id)`, `create(title, severity, *, description?)` |
| `client.rules` | `list_sigma()`, `list_yara()`, `create(name, rule_type, condition, ...)` |
| `client.ioc` | `list()`, `import_iocs(entries)` |
