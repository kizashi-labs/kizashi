/**
 * Unit tests for KizashiEDRClient
 *
 * Run with:  npx vitest run
 * (Add vitest and @vitest/coverage-v8 as devDependencies if not present)
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EDRAPIError, KizashiEDRClient } from "./client.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const BASE_URL = "https://api.kizashi-edr.example.com";
const API_KEY = "edr_test_key_abc123";

/** Build a mock Response object with JSON body. */
function mockJsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Build a mock Response with a plain-text body. */
function mockTextResponse(text: string, status: number): Response {
  return new Response(text, { status });
}

// ─── Test setup ───────────────────────────────────────────────────────────────

let client: KizashiEDRClient;

beforeEach(() => {
  // Replace the global fetch with a vitest spy before each test.
  vi.stubGlobal("fetch", vi.fn());

  client = new KizashiEDRClient({ baseUrl: BASE_URL, apiKey: API_KEY });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ─── Constructor ──────────────────────────────────────────────────────────────

describe("KizashiEDRClient constructor", () => {
  it("stores baseUrl, stripping trailing slash", () => {
    const c = new KizashiEDRClient({
      baseUrl: "https://api.example.com/",
      apiKey: "key",
    });
    // Trigger a request to observe the URL used
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    void c.alerts.list();
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/^https:\/\/api\.example\.com\/api\/v1\/alerts/);
  });

  it("sends Authorization: Bearer header on every request", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.alerts.list();
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["Authorization"]).toBe(
      `Bearer ${API_KEY}`
    );
  });

  it("sends Content-Type: application/json on every request", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.alerts.list();
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe(
      "application/json"
    );
  });

  it("defaults timeout to 30 000 ms when not specified", () => {
    // The timeout is internal, but we can verify it is accepted without error.
    expect(
      () => new KizashiEDRClient({ baseUrl: BASE_URL, apiKey: "k" })
    ).not.toThrow();
  });

  it("accepts a custom timeout value", () => {
    expect(
      () =>
        new KizashiEDRClient({ baseUrl: BASE_URL, apiKey: "k", timeout: 5000 })
    ).not.toThrow();
  });
});

// ─── alerts.list ──────────────────────────────────────────────────────────────

describe("alerts.list()", () => {
  it("makes a GET request to /api/v1/alerts", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.alerts.list();
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/v1/alerts");
    expect(init.method).toBe("GET");
  });

  it("returns the parsed ListResponse", async () => {
    const payload = {
      data: [
        {
          id: "a1",
          title: "Suspicious process",
          severity: "high",
          status: "open",
          created_at: "2026-01-01T00:00:00Z",
        },
      ],
      total: 1,
    };
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse(payload));
    const result = await client.alerts.list();
    expect(result.total).toBe(1);
    expect(result.data[0].id).toBe("a1");
  });

  it("does not append query params when filter is undefined", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.alerts.list();
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).not.toContain("?");
  });

  it("appends severity and status query params when provided", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.alerts.list({ severity: "critical", status: "open" });
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain("severity=critical");
    expect(url).toContain("status=open");
  });

  it("appends limit and offset when provided", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.alerts.list({ limit: 20, offset: 40 });
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain("limit=20");
    expect(url).toContain("offset=40");
  });
});

// ─── alerts.get ───────────────────────────────────────────────────────────────

describe("alerts.get(id)", () => {
  it("makes a GET request to /api/v1/alerts/:id", async () => {
    const alert = {
      id: "uuid-1",
      title: "Test alert",
      severity: "medium",
      status: "open",
      created_at: "2026-01-01T00:00:00Z",
    };
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse(alert));
    await client.alerts.get("uuid-1");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/alerts\/uuid-1$/);
    expect(init.method).toBe("GET");
  });

  it("returns the alert object", async () => {
    const alert = {
      id: "uuid-2",
      title: "Malware detected",
      severity: "critical",
      status: "investigating",
      created_at: "2026-01-01T00:00:00Z",
    };
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse(alert));
    const result = await client.alerts.get("uuid-2");
    expect(result.id).toBe("uuid-2");
    expect(result.severity).toBe("critical");
  });
});

// ─── agents.isolate ───────────────────────────────────────────────────────────

describe("agents.isolate(id)", () => {
  it("makes a POST request to /api/v1/agents/:id/isolate", async () => {
    // 200 with empty body is fine for void return
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(null, { status: 200 })
    );
    await client.agents.isolate("agent-abc");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/agents\/agent-abc\/isolate$/);
    expect(init.method).toBe("POST");
  });

  it("does not include a request body", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response(null, { status: 200 }));
    await client.agents.isolate("agent-abc");
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(init.body).toBeUndefined();
  });
});

// ─── EDRAPIError on 4xx responses ─────────────────────────────────────────────

describe("EDRAPIError on 4xx responses", () => {
  it("throws EDRAPIError with status 401 on Unauthorized", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockJsonResponse({ error: "Unauthorized" }, 401)
    );
    await expect(client.alerts.list()).rejects.toMatchObject({
      name: "EDRAPIError",
      status: 401,
      message: "Unauthorized",
    });
  });

  it("throws EDRAPIError with status 403 on Forbidden", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockJsonResponse({ error: "Forbidden" }, 403)
    );
    await expect(client.alerts.get("some-id")).rejects.toMatchObject({
      name: "EDRAPIError",
      status: 403,
    });
  });

  it("throws EDRAPIError with status 404 on Not Found", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockJsonResponse({ error: "Alert not found" }, 404)
    );
    await expect(client.alerts.get("nonexistent")).rejects.toMatchObject({
      name: "EDRAPIError",
      status: 404,
      message: "Alert not found",
    });
  });

  it("attaches response body to EDRAPIError.body", async () => {
    const body = { error: "Bad Request", detail: "Invalid UUID" };
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse(body, 400));
    try {
      await client.alerts.get("bad-uuid");
      expect.fail("Expected EDRAPIError to be thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(EDRAPIError);
      expect((err as EDRAPIError).body).toEqual(body);
    }
  });

  it("falls back to HTTP status text when response has no error field", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({}), {
        status: 422,
        statusText: "Unprocessable Entity",
        headers: { "Content-Type": "application/json" },
      })
    );
    await expect(client.alerts.list()).rejects.toMatchObject({
      status: 422,
    });
  });
});

// ─── EDRAPIError on 5xx responses ─────────────────────────────────────────────

describe("EDRAPIError on 5xx responses", () => {
  it("throws EDRAPIError with status 500 on Internal Server Error", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockJsonResponse({ error: "Internal server error" }, 500)
    );
    await expect(client.agents.isolate("agent-1")).rejects.toMatchObject({
      name: "EDRAPIError",
      status: 500,
    });
  });

  it("throws EDRAPIError with status 503 on Service Unavailable", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockTextResponse("Service Unavailable", 503)
    );
    await expect(client.incidents.list()).rejects.toMatchObject({
      name: "EDRAPIError",
      status: 503,
    });
  });
});

// ─── Timeout ──────────────────────────────────────────────────────────────────

describe("Request timeout", () => {
  it("aborts the request after the configured timeout", async () => {
    const shortClient = new KizashiEDRClient({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      timeout: 50, // 50 ms
    });

    // Simulate fetch never resolving until AbortSignal fires
    vi.mocked(fetch).mockImplementationOnce(
      (_url: string, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("The operation was aborted.", "AbortError"));
          });
        })
    );

    vi.useFakeTimers();
    const promise = shortClient.alerts.list();
    // Advance past the 50 ms timeout
    vi.advanceTimersByTime(100);
    await expect(promise).rejects.toThrow();
    vi.useRealTimers();
  });

  it("passes an AbortSignal to fetch", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.alerts.list();
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBeDefined();
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });
});

// ─── Query parameter encoding ─────────────────────────────────────────────────

describe("Query parameter encoding", () => {
  it("correctly appends a single query param", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.agents.list({ status: "isolated" });
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/[?&]status=isolated/);
  });

  it("correctly appends multiple query params", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.alerts.list({ severity: "high", status: "open", limit: 10 });
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain("severity=high");
    expect(url).toContain("status=open");
    expect(url).toContain("limit=10");
  });

  it("omits undefined and null filter values", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    // limit is undefined — should not appear in URL
    await client.alerts.list({ severity: "low" });
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).not.toContain("limit=");
    expect(url).not.toContain("offset=");
  });

  it("builds the URL correctly for alerts.get without query params", async () => {
    const alert = { id: "x", title: "t", severity: "low", status: "open", created_at: "" };
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse(alert));
    await client.alerts.get("x");
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE_URL}/api/v1/alerts/x`);
  });
});

// ─── vulnerabilities ──────────────────────────────────────────────────────────

describe("vulnerabilities.list()", () => {
  it("calls GET /api/v1/vulnerabilities", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.vulnerabilities.list();
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/v1/vulnerabilities");
    expect(init.method).toBe("GET");
  });

  it("does not append /stats to the list URL", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.vulnerabilities.list();
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).not.toContain("/stats");
  });
});

describe("vulnerabilities.stats()", () => {
  it("calls GET /api/v1/vulnerabilities/stats", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ critical: 1, high: 3 }));
    await client.vulnerabilities.stats();
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/vulnerabilities\/stats$/);
    expect(init.method).toBe("GET");
  });
});

// ─── apiKeys ──────────────────────────────────────────────────────────────────

describe("apiKeys.list()", () => {
  it("calls GET /api/v1/api-keys", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.apiKeys.list();
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/api-keys$/);
    expect(init.method).toBe("GET");
  });
});

describe("apiKeys.create(name, scopes)", () => {
  it("calls POST /api/v1/api-keys with name and scopes in body", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockJsonResponse({ id: "key-1", name: "ci-key" })
    );
    await client.apiKeys.create({ name: "ci-key", scopes: ["alerts:read", "agents:read"] });
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/api-keys$/);
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.name).toBe("ci-key");
    expect(body.scopes).toEqual(["alerts:read", "agents:read"]);
  });
});

describe("apiKeys.revoke(id)", () => {
  it("calls DELETE /api/v1/api-keys/:id", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response(null, { status: 200 }));
    await client.apiKeys.revoke("key-1");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/api-keys\/key-1$/);
    expect(init.method).toBe("DELETE");
  });
});

// ─── liveResponse ─────────────────────────────────────────────────────────────

// **この3つは、サーバに無い宛先を留めていました。**
//
// 検査はクライアントの実装から書かれていて、サーバの経路と突き合わせた
// ものは1つもありませんでした —— **緑のまま、呼べば必ず 404** です。
// セッションは端末ごと（`/agents/:id/live-response/sessions`）です。

describe("liveResponse.list(agentId)", () => {
  it("calls GET /api/v1/agents/:id/live-response/sessions", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ data: [], total: 0 }));
    await client.liveResponse.list("agent-007");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/agents\/agent-007\/live-response\/sessions$/);
    expect(init.method).toBe("GET");
  });
});

describe("liveResponse.open(agentId)", () => {
  it("calls POST /api/v1/agents/:id/live-response/sessions", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockJsonResponse({ id: "sess-1", agent_id: "agent-007" })
    );
    await client.liveResponse.open("agent-007");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/agents\/agent-007\/live-response\/sessions$/);
    expect(init.method).toBe("POST");
  });
});

describe("liveResponse.exec(agentId, sessionId, command)", () => {
  it("calls POST /api/v1/agents/:id/live-response/sessions/:sid/exec with command in body", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({ output: "uid=0(root)" }));
    await client.liveResponse.exec("agent-007", "sess-1", "id");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(
      /\/api\/v1\/agents\/agent-007\/live-response\/sessions\/sess-1\/exec$/
    );
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.command).toBe("id");
  });
});

// ─── incidents.update ─────────────────────────────────────────────────────────

describe("incidents.update(id, data)", () => {
  it("calls PUT /api/v1/incidents/:id", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockJsonResponse({ id: "inc-1", status: "investigating" })
    );
    await client.incidents.update("inc-1", { status: "investigating" });
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/incidents\/inc-1$/);
    expect(init.method).toBe("PUT");
  });

  it("sends status and assigned_to in body", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockJsonResponse({ id: "inc-2", status: "resolved", assigned_to: "alice" })
    );
    await client.incidents.update("inc-2", { status: "resolved", assigned_to: "alice" });
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.status).toBe("resolved");
    expect(body.assigned_to).toBe("alice");
  });

  it("returns the updated incident", async () => {
    const incident = { id: "inc-3", title: "Breach", severity: "critical", status: "contained", created_at: "2026-01-01T00:00:00Z" };
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse(incident));
    const result = await client.incidents.update("inc-3", { status: "contained" });
    expect(result).toEqual(incident);
  });
});

// ─── rules.get ────────────────────────────────────────────────────────────────

describe("rules.get(id)", () => {
  it("calls GET /api/v1/rules/:id", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockJsonResponse({ id: "rule-1", name: "mimikatz", type: "sigma", condition: "...", enabled: true })
    );
    await client.rules.get("rule-1");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/rules\/rule-1$/);
    expect(init.method).toBe("GET");
  });

  it("returns the rule object", async () => {
    const rule = { id: "rule-2", name: "lsass", type: "sigma", condition: "x", enabled: false };
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse(rule));
    const result = await client.rules.get("rule-2");
    expect(result.id).toBe("rule-2");
    expect(result.name).toBe("lsass");
  });
});

// ─── rules.update ─────────────────────────────────────────────────────────────

describe("rules.update(id, data)", () => {
  it("calls PUT /api/v1/rules/:id", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockJsonResponse({ id: "rule-1", name: "updated", type: "sigma", condition: "...", enabled: false })
    );
    await client.rules.update("rule-1", { enabled: false });
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/rules\/rule-1$/);
    expect(init.method).toBe("PUT");
  });

  it("sends only provided fields in body", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockJsonResponse({}));
    await client.rules.update("rule-1", { enabled: true, severity: "high" });
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.enabled).toBe(true);
    expect(body.severity).toBe("high");
  });
});

// ─── rules.delete ─────────────────────────────────────────────────────────────

describe("rules.delete(id)", () => {
  it("calls DELETE /api/v1/rules/:id", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response(null, { status: 204 }));
    await client.rules.delete("rule-99");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/rules\/rule-99$/);
    expect(init.method).toBe("DELETE");
  });

  it("resolves without a return value on 204 No Content", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response(null, { status: 204 }));
    const result = await client.rules.delete("rule-88");
    expect(result).toBeUndefined();
  });
});
