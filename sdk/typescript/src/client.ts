/**
 * Kizashi — TypeScript Client SDK
 *
 * Authentication: every request sends `Authorization: Bearer <apiKey>`.
 * Base URL example: https://api.kizashi-edr.example.com
 */

// ─── Error ────────────────────────────────────────────────────────────────────

/**
 * Thrown when the API returns a non-2xx response.
 */
export class EDRAPIError extends Error {
  /** HTTP status code returned by the server. */
  readonly status: number;
  /** Raw error message from the response body, if available. */
  readonly body: unknown;

  constructor(status: number, message: string, body?: unknown) {
    super(message);
    this.name = "EDRAPIError";
    this.status = status;
    this.body = body;
  }
}

// ─── Interfaces ───────────────────────────────────────────────────────────────

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";
export type AlertStatus = "open" | "investigating" | "resolved" | "false_positive";

/** A security alert raised by a detection rule. */
export interface Alert {
  id: string;
  title: string;
  description?: string;
  severity: AlertSeverity;
  status: AlertStatus;
  rule_name?: string;
  agent_id?: string;
  hostname?: string;
  mitre_technique?: string;
  created_at: string;
  resolved_at?: string;
}

export type AgentStatus = "online" | "offline" | "isolated";

/** An endpoint agent registered with the platform. */
export interface Agent {
  id: string;
  hostname: string;
  os?: string;
  os_version?: string;
  ip_address?: string;
  status: AgentStatus;
  version?: string;
  last_seen_at?: string;
  tags?: string[];
}

export type IncidentSeverity = "critical" | "high" | "medium" | "low";
export type IncidentStatus =
  | "open"
  | "investigating"
  | "contained"
  | "resolved"
  | "closed";

/** A security incident grouping one or more alerts. */
export interface Incident {
  id: string;
  title: string;
  description?: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  assigned_to?: string;
  created_at: string;
}

export type RuleType = "sigma" | "yara" | "custom";

/** A detection rule (Sigma, YARA, or custom). */
export interface SigmaRule {
  id: string;
  name: string;
  description?: string;
  type: RuleType;
  severity?: AlertSeverity;
  /** Sigma/YARA rule content or JSON condition string. */
  condition: string;
  enabled: boolean;
}

/** Input payload for creating or updating a rule. */
export interface RuleInput {
  name: string;
  description?: string;
  type: RuleType;
  severity?: AlertSeverity;
  condition: string;
  enabled?: boolean;
}

/** An Indicator of Compromise entry. */
export interface IOCEntry {
  type: string;
  value: string;
  description?: string;
  severity?: AlertSeverity;
  source?: string;
  tags?: string[];
}

/** Generic paginated list response. */
export interface ListResponse<T> {
  data: T[];
  total: number;
}

// ─── Client configuration ─────────────────────────────────────────────────────

export interface KizashiEDRClientConfig {
  /** Base URL of the API server, e.g. https://api.kizashi-edr.example.com */
  baseUrl: string;
  /** API key (JWT bearer token) obtained from /api/v1/auth/login. */
  apiKey: string;
  /** Request timeout in milliseconds. Defaults to 30 000. */
  timeout?: number;
}

// ─── Additional types ─────────────────────────────────────────────────────────

/** A vulnerability found on an endpoint. */
export interface Vulnerability {
  id: string;
  cve_id: string;
  title: string;
  description?: string;
  severity: AlertSeverity;
  cvss_score?: number;
  agent_id?: string;
  hostname?: string;
  package_name?: string;
  package_version?: string;
  fixed_version?: string;
  status: "open" | "acknowledged" | "resolved" | "risk_accepted";
  published_at?: string;
  detected_at: string;
}

/** An API key for programmatic access. */
export interface APIKey {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  last_used_at?: string;
  expires_at?: string;
  created_at: string;
}

/** A live-response session connecting to an agent. */
export interface LiveResponseSession {
  id: string;
  agent_id: string;
  hostname?: string;
  status: "pending" | "active" | "closed";
  created_at: string;
  expires_at: string;
}

/** Result of a live-response command execution. */
export interface CommandResult {
  command_id: string;
  stdout: string;
  stderr: string;
  exit_code: number;
  executed_at: string;
}

// ─── Resource namespaces ──────────────────────────────────────────────────────

export interface AlertFilter {
  severity?: AlertSeverity;
  status?: AlertStatus;
  limit?: number;
  offset?: number;
}

export interface AgentFilter {
  status?: AgentStatus;
  limit?: number;
  offset?: number;
}

export interface AlertUpdatePayload {
  status?: AlertStatus;
  assigned_to?: string;
}

export interface IncidentCreatePayload {
  title: string;
  severity: IncidentSeverity;
  description?: string;
}

export interface IncidentUpdatePayload {
  status?: IncidentStatus;
  assigned_to?: string;
  description?: string;
}

// ─── Main client ──────────────────────────────────────────────────────────────

/**
 * Kizashi API client.
 *
 * @example
 * ```typescript
 * const client = new KizashiEDRClient({
 *   baseUrl: 'https://api.kizashi-edr.example.com',
 *   apiKey: 'edr_...',
 * });
 *
 * const { data: alerts } = await client.alerts.list({ status: 'open', severity: 'high' });
 * ```
 */
export class KizashiEDRClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;

  /** Alert management methods. */
  readonly alerts: {
    /**
     * Returns a paginated list of alerts, optionally filtered.
     * @param filter - Optional query parameters (severity, status, limit, offset).
     */
    list(filter?: AlertFilter): Promise<ListResponse<Alert>>;
    /**
     * Fetches a single alert by its UUID.
     * @param id - Alert UUID.
     */
    get(id: string): Promise<Alert>;
    /**
     * Updates an alert's status or assignee.
     * @param id   - Alert UUID.
     * @param data - Fields to update.
     */
    update(id: string, data: AlertUpdatePayload): Promise<Alert>;
  };

  /** Endpoint agent management methods. */
  readonly agents: {
    /**
     * Returns a paginated list of registered agents.
     * @param filter - Optional query parameters (status, limit, offset).
     */
    list(filter?: AgentFilter): Promise<ListResponse<Agent>>;
    /**
     * Fetches a single agent by its UUID.
     * @param id - Agent UUID.
     */
    get(id: string): Promise<Agent>;
    /**
     * Sends a network-isolation command to the specified agent.
     * @param id - Agent UUID.
     */
    isolate(id: string): Promise<void>;
    /**
     * Lifts network isolation from the specified agent.
     * @param id - Agent UUID.
     */
    release(id: string): Promise<void>;
  };

  /** Incident management methods. */
  readonly incidents: {
    /** Returns all incidents. */
    list(): Promise<ListResponse<Incident>>;
    /**
     * Fetches a single incident by its UUID.
     * @param id - Incident UUID.
     */
    get(id: string): Promise<Incident>;
    /**
     * Creates a new incident.
     * @param data - Title, severity, and optional description.
     */
    create(data: IncidentCreatePayload): Promise<Incident>;
    /**
     * Updates an incident's status, assignee, or description.
     * @param id   - Incident UUID.
     * @param data - Fields to update.
     */
    update(id: string, data: IncidentUpdatePayload): Promise<Incident>;
  };

  /** Detection rule management methods. */
  readonly rules: {
    /**
     * Returns rules of type `sigma`.
     * The underlying endpoint returns all rules; this method filters client-side.
     */
    listSigma(): Promise<SigmaRule[]>;
    /**
     * Returns rules of type `yara`.
     * The underlying endpoint returns all rules; this method filters client-side.
     */
    listYara(): Promise<SigmaRule[]>;
    /**
     * Fetches a single rule by its UUID.
     * @param id - Rule UUID.
     */
    get(id: string): Promise<SigmaRule>;
    /**
     * Creates a new detection rule.
     * @param data - Rule payload.
     */
    create(data: RuleInput): Promise<SigmaRule>;
    /**
     * Updates an existing detection rule.
     * @param id   - Rule UUID.
     * @param data - Fields to update.
     */
    update(id: string, data: Partial<RuleInput>): Promise<SigmaRule>;
    /**
     * Deletes a detection rule by its UUID.
     * @param id - Rule UUID.
     */
    delete(id: string): Promise<void>;
  };

  /** Vulnerability management methods. */
  readonly vulnerabilities: {
    /**
     * Returns a paginated list of vulnerabilities.
     * @param filter - Optional query parameters.
     */
    list(filter?: { severity?: AlertSeverity; status?: string; agent_id?: string; limit?: number; offset?: number }): Promise<ListResponse<Vulnerability>>;
    /** Returns aggregate vulnerability statistics. */
    stats(): Promise<Record<string, unknown>>;
  };

  /** API key management methods. */
  readonly apiKeys: {
    /** Returns all API keys for the current user. */
    list(): Promise<APIKey[]>;
    /**
     * Creates a new API key.
     * @param data - Name and optional scopes.
     */
    create(data: { name: string; scopes?: string[]; expires_at?: string }): Promise<APIKey & { key: string }>;
    /**
     * Revokes (deletes) an API key.
     * @param id - API key UUID.
     */
    revoke(id: string): Promise<void>;
  };

  /** Live response session management methods. */
  readonly liveResponse: {
    /**
     * Returns the active live-response sessions on an agent.
     *
     * **セッションは端末ごとです。** 以前このメソッドは端末を受け取らず
     * `/api/v1/live-response/sessions` を叩いていました —— サーバに
     * その経路はなく、**呼ぶと必ず 404 でした**。
     * @param agentId - Target agent UUID.
     */
    list(agentId: string): Promise<ListResponse<LiveResponseSession>>;
    /**
     * Opens a new live-response session on an agent.
     * @param agentId - Target agent UUID.
     */
    open(agentId: string): Promise<LiveResponseSession>;
    /**
     * Executes a command in an active session.
     * @param agentId   - Target agent UUID.
     * @param sessionId - Session UUID.
     * @param command   - Shell command to run.
     */
    exec(agentId: string, sessionId: string, command: string): Promise<CommandResult>;
  };

  /** Indicator of Compromise (IOC / threat-intel) methods. */
  readonly ioc: {
    /** Returns all IOC entries from the threat-intel feed. */
    list(): Promise<IOCEntry[]>;
    /**
     * Bulk-imports IOC entries.
     * @param entries - Array of IOC objects to import.
     */
    import(entries: IOCEntry[]): Promise<void>;
  };

  constructor(config: KizashiEDRClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.apiKey = config.apiKey;
    this.timeout = config.timeout ?? 30_000;

    // Bind resource namespaces so `this` is always correct.
    this.alerts = {
      list: (filter?) => this.request<ListResponse<Alert>>("GET", "/api/v1/alerts", { query: filter }),
      get: (id) => this.request<Alert>("GET", `/api/v1/alerts/${id}`),
      update: (id, data) => this.request<Alert>("PUT", `/api/v1/alerts/${id}`, { body: data }),
    };

    this.agents = {
      list: (filter?) => this.request<ListResponse<Agent>>("GET", "/api/v1/agents", { query: filter }),
      get: (id) => this.request<Agent>("GET", `/api/v1/agents/${id}`),
      isolate: (id) => this.request<void>("POST", `/api/v1/agents/${id}/isolate`),
      release: (id) => this.request<void>("POST", `/api/v1/agents/${id}/unisolate`),
    };

    this.incidents = {
      list: () => this.request<ListResponse<Incident>>("GET", "/api/v1/incidents"),
      get: (id) => this.request<Incident>("GET", `/api/v1/incidents/${id}`),
      create: (data) => this.request<Incident>("POST", "/api/v1/incidents", { body: data }),
      update: (id, data) => this.request<Incident>("PUT", `/api/v1/incidents/${id}`, { body: data }),
    };

    this.rules = {
      listSigma: async () => {
        const res = await this.request<{ data?: SigmaRule[] }>("GET", "/api/v1/rules");
        return (res.data ?? []).filter((r) => r.type === "sigma");
      },
      listYara: async () => {
        const res = await this.request<{ data?: SigmaRule[] }>("GET", "/api/v1/rules");
        return (res.data ?? []).filter((r) => r.type === "yara");
      },
      get: (id) => this.request<SigmaRule>("GET", `/api/v1/rules/${id}`),
      create: (data) => this.request<SigmaRule>("POST", "/api/v1/rules", { body: data }),
      update: (id, data) => this.request<SigmaRule>("PUT", `/api/v1/rules/${id}`, { body: data }),
      delete: (id) => this.request<void>("DELETE", `/api/v1/rules/${id}`),
    };

    this.ioc = {
      list: () => this.request<IOCEntry[]>("GET", "/api/v1/ioc"),
      import: (entries) =>
        this.request<void>("POST", "/api/v1/ioc/import", { body: { entries } }),
    };

    this.vulnerabilities = {
      list: (filter?) =>
        this.request<ListResponse<Vulnerability>>("GET", "/api/v1/vulnerabilities", { query: filter }),
      stats: () => this.request<Record<string, unknown>>("GET", "/api/v1/vulnerabilities/stats"),
    };

    this.apiKeys = {
      list: () => this.request<APIKey[]>("GET", "/api/v1/api-keys"),
      create: (data) =>
        this.request<APIKey & { key: string }>("POST", "/api/v1/api-keys", { body: data }),
      revoke: (id) => this.request<void>("DELETE", `/api/v1/api-keys/${id}`),
    };

    this.liveResponse = {
      list: (agentId) =>
        this.request<ListResponse<LiveResponseSession>>(
          "GET",
          `/api/v1/agents/${agentId}/live-response/sessions`,
        ),
      open: (agentId) =>
        this.request<LiveResponseSession>(
          "POST",
          `/api/v1/agents/${agentId}/live-response/sessions`,
        ),
      exec: (agentId, sessionId, command) =>
        this.request<CommandResult>(
          "POST",
          `/api/v1/agents/${agentId}/live-response/sessions/${sessionId}/exec`,
          { body: { command } },
        ),
    };
  }

  /**
   * Internal HTTP request helper.
   *
   * Adds `Authorization: Bearer <apiKey>` to every request.
   * Throws `EDRAPIError` for non-2xx responses.
   *
   * @param method  - HTTP method.
   * @param path    - API path, e.g. `/api/v1/alerts`.
   * @param options - Optional request body and/or query parameters.
   */
  private async request<T>(
    method: string,
    path: string,
    options: { body?: unknown; query?: Record<string, unknown> | object } = {}
  ): Promise<T> {
    const url = new URL(this.baseUrl + path);

    if (options.query) {
      for (const [key, value] of Object.entries(options.query)) {
        if (value !== undefined && value !== null) {
          url.searchParams.set(key, String(value));
        }
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    let response: Response;
    try {
      response = await fetch(url.toString(), {
        method,
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${this.apiKey}`,
        },
        body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      });
    } finally {
      clearTimeout(timer);
    }

    // Parse body (may be empty for 204 / some 200 responses).
    let responseBody: unknown;
    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      responseBody = await response.json();
    } else {
      const text = await response.text();
      responseBody = text || undefined;
    }

    if (!response.ok) {
      const message =
        (responseBody as { error?: string })?.error ??
        `HTTP ${response.status} ${response.statusText}`;
      throw new EDRAPIError(response.status, message, responseBody);
    }

    return responseBody as T;
  }
}
