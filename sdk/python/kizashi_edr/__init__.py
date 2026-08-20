"""
Kizashi — Python Client SDK
==========================================

Authentication: every request sends ``Authorization: Bearer <api_key>``.
No external dependencies — only the standard library is used.

Example::

    from kizashi_edr import KizashiEDRClient

    client = KizashiEDRClient(
        base_url="https://api.kizashi-edr.example.com",
        api_key="edr_your_jwt_token_here",
    )

    alerts = client.alerts.list(status="open", severity="high")
    print(f"Found {alerts['total']} alerts")
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__all__ = [
    "KizashiEDRClient",
    "EDRAPIError",
    "Alert",
    "Agent",
    "Incident",
]

# ─── Exceptions ───────────────────────────────────────────────────────────────


class EDRAPIError(Exception):
    """Raised when the Kizashi API returns a non-2xx response.

    Attributes:
        status:  HTTP status code (e.g. 401, 404).
        message: Error description from the response body.
        body:    Full parsed response body, or ``None`` if unavailable.
    """

    def __init__(self, status: int, message: str, body: Any = None) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status: int = status
        self.message: str = message
        self.body: Any = body


# ─── Dataclasses ──────────────────────────────────────────────────────────────


@dataclass
class Alert:
    """A security alert raised by a detection rule."""

    id: str
    title: str
    severity: str  # critical | high | medium | low | info
    status: str    # open | investigating | resolved | false_positive
    description: Optional[str] = None
    rule_name: Optional[str] = None
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    mitre_technique: Optional[str] = None
    created_at: Optional[str] = None
    resolved_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        """Construct an Alert from a raw API response dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            severity=data["severity"],
            status=data["status"],
            description=data.get("description"),
            rule_name=data.get("rule_name"),
            agent_id=data.get("agent_id"),
            hostname=data.get("hostname"),
            mitre_technique=data.get("mitre_technique"),
            created_at=data.get("created_at"),
            resolved_at=data.get("resolved_at"),
        )


@dataclass
class Agent:
    """An endpoint agent registered with the platform."""

    id: str
    hostname: str
    status: str  # online | offline | isolated
    os: Optional[str] = None
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    version: Optional[str] = None
    last_seen_at: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Agent":
        """Construct an Agent from a raw API response dictionary."""
        return cls(
            id=data["id"],
            hostname=data["hostname"],
            status=data["status"],
            os=data.get("os"),
            os_version=data.get("os_version"),
            ip_address=data.get("ip_address"),
            version=data.get("version"),
            last_seen_at=data.get("last_seen_at"),
            tags=data.get("tags") or [],
        )


@dataclass
class Incident:
    """A security incident grouping one or more alerts."""

    id: str
    title: str
    severity: str  # critical | high | medium | low
    status: str    # open | investigating | contained | resolved | closed
    description: Optional[str] = None
    assigned_to: Optional[str] = None
    created_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Incident":
        """Construct an Incident from a raw API response dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            severity=data["severity"],
            status=data["status"],
            description=data.get("description"),
            assigned_to=data.get("assigned_to"),
            created_at=data.get("created_at"),
        )


# ─── Resource namespaces ──────────────────────────────────────────────────────


class _AlertsResource:
    """Alert management methods."""

    def __init__(self, client: "KizashiEDRClient") -> None:
        self._client = client

    def list(
        self,
        *,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Return a paginated list of alerts.

        Args:
            severity: Filter by severity (``critical``, ``high``, ``medium``,
                      ``low``, ``info``).
            status:   Filter by status (``open``, ``investigating``,
                      ``resolved``, ``false_positive``).
            limit:    Maximum number of results (default 50).
            offset:   Pagination offset (default 0).

        Returns:
            A dict with ``data`` (list of alert dicts) and ``total`` (int).
        """
        params: Dict[str, Any] = {}
        if severity is not None:
            params["severity"] = severity
        if status is not None:
            params["status"] = status
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        return self._client._request("GET", "/api/v1/alerts", params=params)

    def get(self, alert_id: str) -> Dict[str, Any]:
        """Fetch a single alert by its UUID.

        Args:
            alert_id: Alert UUID string.

        Returns:
            Alert dict.
        """
        return self._client._request("GET", f"/api/v1/alerts/{alert_id}")

    def update(
        self,
        alert_id: str,
        *,
        status: Optional[str] = None,
        assigned_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update an alert's status or assignee.

        Args:
            alert_id:    Alert UUID string.
            status:      New status value.
            assigned_to: Assignee identifier (e.g. email).

        Returns:
            Updated alert dict.
        """
        body: Dict[str, Any] = {}
        if status is not None:
            body["status"] = status
        if assigned_to is not None:
            body["assigned_to"] = assigned_to
        return self._client._request("PUT", f"/api/v1/alerts/{alert_id}", body=body)


class _AgentsResource:
    """Endpoint agent management methods."""

    def __init__(self, client: "KizashiEDRClient") -> None:
        self._client = client

    def list(
        self,
        *,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Return a paginated list of registered agents.

        Args:
            status: Filter by agent status (``online``, ``offline``,
                    ``isolated``).
            limit:  Maximum number of results (default 50).
            offset: Pagination offset (default 0).

        Returns:
            A dict with ``data`` (list of agent dicts) and ``total`` (int).
        """
        params: Dict[str, Any] = {}
        if status is not None:
            params["status"] = status
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        return self._client._request("GET", "/api/v1/agents", params=params)

    def get(self, agent_id: str) -> Dict[str, Any]:
        """Fetch a single agent by its UUID.

        Args:
            agent_id: Agent UUID string.

        Returns:
            Agent dict.
        """
        return self._client._request("GET", f"/api/v1/agents/{agent_id}")

    def isolate(self, agent_id: str) -> Dict[str, Any]:
        """Send a network-isolation command to the specified agent.

        Args:
            agent_id: Agent UUID string.

        Returns:
            API response dict.
        """
        return self._client._request("POST", f"/api/v1/agents/{agent_id}/isolate")

    def release(self, agent_id: str) -> Dict[str, Any]:
        """Lift network isolation from the specified agent.

        Args:
            agent_id: Agent UUID string.

        Returns:
            API response dict.
        """
        return self._client._request("POST", f"/api/v1/agents/{agent_id}/unisolate")


class _IncidentsResource:
    """Incident management methods."""

    def __init__(self, client: "KizashiEDRClient") -> None:
        self._client = client

    def list(self) -> Dict[str, Any]:
        """Return all incidents.

        Returns:
            A dict with ``data`` (list of incident dicts).
        """
        return self._client._request("GET", "/api/v1/incidents")

    def get(self, incident_id: str) -> Dict[str, Any]:
        """Fetch a single incident by its UUID.

        Args:
            incident_id: Incident UUID string.

        Returns:
            Incident dict.
        """
        return self._client._request("GET", f"/api/v1/incidents/{incident_id}")

    def create(
        self,
        title: str,
        severity: str,
        *,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new incident.

        Args:
            title:       Short incident title (required).
            severity:    One of ``critical``, ``high``, ``medium``, ``low``
                         (required).
            description: Optional longer description.

        Returns:
            Created incident dict.
        """
        body: Dict[str, Any] = {"title": title, "severity": severity}
        if description is not None:
            body["description"] = description
        return self._client._request("POST", "/api/v1/incidents", body=body)

    def update(
        self,
        incident_id: str,
        *,
        status: Optional[str] = None,
        assigned_to: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update an incident's status, assignee, or description.

        Args:
            incident_id: Incident UUID string.
            status:      New status value (e.g. ``investigating``, ``resolved``).
            assigned_to: Username or user ID to assign the incident to.
            description: Updated description text.

        Returns:
            Updated incident dict.
        """
        body: Dict[str, Any] = {}
        if status is not None:
            body["status"] = status
        if assigned_to is not None:
            body["assigned_to"] = assigned_to
        if description is not None:
            body["description"] = description
        return self._client._request("PUT", f"/api/v1/incidents/{incident_id}", body=body)


class _RulesResource:
    """Detection rule management methods."""

    def __init__(self, client: "KizashiEDRClient") -> None:
        self._client = client

    def list_sigma(self) -> List[Dict[str, Any]]:
        """Return all detection rules of type ``sigma``.

        Returns:
            List of rule dicts.
        """
        resp = self._client._request("GET", "/api/v1/rules")
        all_rules: List[Dict[str, Any]] = resp.get("data", resp) if isinstance(resp, dict) else resp
        return [r for r in all_rules if r.get("type") == "sigma"]

    def list_yara(self) -> List[Dict[str, Any]]:
        """Return all detection rules of type ``yara``.

        Returns:
            List of rule dicts.
        """
        resp = self._client._request("GET", "/api/v1/rules")
        all_rules: List[Dict[str, Any]] = resp.get("data", resp) if isinstance(resp, dict) else resp
        return [r for r in all_rules if r.get("type") == "yara"]

    def create(
        self,
        name: str,
        rule_type: str,
        condition: str,
        *,
        description: Optional[str] = None,
        severity: Optional[str] = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """Create a new detection rule.

        Args:
            name:        Rule name (required).
            rule_type:   One of ``sigma``, ``yara``, ``custom`` (required).
            condition:   Sigma/YARA rule content or JSON condition string
                         (required).
            description: Optional description.
            severity:    Alert severity level for matches.
            enabled:     Whether the rule is active immediately (default
                         ``True``).

        Returns:
            Created rule dict.
        """
        body: Dict[str, Any] = {
            "name": name,
            "type": rule_type,
            "condition": condition,
            "enabled": enabled,
        }
        if description is not None:
            body["description"] = description
        if severity is not None:
            body["severity"] = severity
        return self._client._request("POST", "/api/v1/rules", body=body)

    def get(self, rule_id: str) -> Dict[str, Any]:
        """Fetch a single detection rule by its UUID.

        Args:
            rule_id: Rule UUID string.

        Returns:
            Rule dict.
        """
        return self._client._request("GET", f"/api/v1/rules/{rule_id}")

    def update(
        self,
        rule_id: str,
        *,
        name: Optional[str] = None,
        condition: Optional[str] = None,
        description: Optional[str] = None,
        severity: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Update an existing detection rule.

        Args:
            rule_id:     Rule UUID string.
            name:        Updated rule name.
            condition:   Updated Sigma/YARA content or JSON condition.
            description: Updated description.
            severity:    Updated severity level.
            enabled:     Enable or disable the rule.

        Returns:
            Updated rule dict.
        """
        body: Dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if condition is not None:
            body["condition"] = condition
        if description is not None:
            body["description"] = description
        if severity is not None:
            body["severity"] = severity
        if enabled is not None:
            body["enabled"] = enabled
        return self._client._request("PUT", f"/api/v1/rules/{rule_id}", body=body)

    def delete(self, rule_id: str) -> None:
        """Delete a detection rule by its UUID.

        Args:
            rule_id: Rule UUID string.
        """
        self._client._request("DELETE", f"/api/v1/rules/{rule_id}")


class _IOCResource:
    """Indicator of Compromise (threat-intel) methods."""

    def __init__(self, client: "KizashiEDRClient") -> None:
        self._client = client

    def list(self) -> List[Dict[str, Any]]:
        """Return all IOC entries from the threat-intel feed.

        Returns:
            List of IOC entry dicts.
        """
        resp = self._client._request("GET", "/api/v1/ioc")
        if isinstance(resp, list):
            return resp
        return resp.get("data", [])

    def import_iocs(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Bulk-import IOC entries.

        Args:
            entries: List of IOC dicts. Each entry should contain at minimum
                     ``type`` (e.g. ``"ip"``, ``"domain"``, ``"sha256"``) and
                     ``value``.

        Returns:
            API response dict.
        """
        return self._client._request(
            "POST",
            "/api/v1/ioc/import",
            body={"entries": entries},
        )


class _VulnerabilitiesResource:
    """Vulnerability management methods."""

    def __init__(self, client: "KizashiEDRClient") -> None:
        self._client = client

    def list(
        self,
        *,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Return a paginated list of vulnerabilities.

        Args:
            severity:  Filter by severity (critical/high/medium/low).
            status:    Filter by status (open/acknowledged/resolved).
            agent_id:  Filter by agent UUID.
            limit:     Maximum results to return (default 50).
            offset:    Pagination offset (default 0).

        Returns:
            Dict with ``data`` list and ``total`` count.
        """
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if severity is not None:
            params["severity"] = severity
        if status is not None:
            params["status"] = status
        if agent_id is not None:
            params["agent_id"] = agent_id
        return self._client._request("GET", "/api/v1/vulnerabilities", params=params)

    def stats(self) -> Dict[str, Any]:
        """Return aggregate vulnerability statistics."""
        return self._client._request("GET", "/api/v1/vulnerabilities/stats")


class _APIKeysResource:
    """API key management methods."""

    def __init__(self, client: "KizashiEDRClient") -> None:
        self._client = client

    def list(self) -> List[Dict[str, Any]]:
        """Return all API keys for the authenticated user."""
        resp = self._client._request("GET", "/api/v1/api-keys")
        if isinstance(resp, list):
            return resp
        return resp.get("data", [])

    def create(
        self,
        name: str,
        *,
        scopes: Optional[List[str]] = None,
        expires_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new API key.

        Args:
            name:       Human-readable name for the key.
            scopes:     Optional list of permission scopes.
            expires_at: Optional ISO 8601 expiry datetime string.

        Returns:
            API key dict including the one-time ``key`` field.
        """
        body: Dict[str, Any] = {"name": name}
        if scopes is not None:
            body["scopes"] = scopes
        if expires_at is not None:
            body["expires_at"] = expires_at
        return self._client._request("POST", "/api/v1/api-keys", body=body)

    def revoke(self, key_id: str) -> None:
        """Revoke (delete) an API key.

        Args:
            key_id: UUID of the API key to revoke.
        """
        self._client._request("DELETE", f"/api/v1/api-keys/{key_id}")


class _LiveResponseResource:
    """Live response session methods."""

    def __init__(self, client: "KizashiEDRClient") -> None:
        self._client = client

    def list(self, agent_id: str) -> Dict[str, Any]:
        """Return the active live-response sessions on the specified agent.

        Args:
            agent_id: UUID of the target agent.

        Note:
            **セッションは端末ごとです。** 以前この関数は端末を受け取らず
            ``/api/v1/live-response/sessions`` を叩いていました —— サーバに
            その経路はなく、**呼ぶと必ず 404 でした**。
        """
        return self._client._request(
            "GET", f"/api/v1/agents/{agent_id}/live-response/sessions"
        )

    def open(self, agent_id: str) -> Dict[str, Any]:
        """Open a new live-response session on the specified agent.

        Args:
            agent_id: UUID of the target agent.

        Returns:
            Session dict including ``id`` and ``expires_at``.
        """
        return self._client._request(
            "POST", f"/api/v1/agents/{agent_id}/live-response/sessions"
        )

    def exec(self, agent_id: str, session_id: str, command: str) -> Dict[str, Any]:
        """Execute a shell command in an active live-response session.

        Args:
            agent_id:   UUID of the target agent.
            session_id: UUID of the session.
            command:    Shell command to run on the remote endpoint.

        Returns:
            Result dict with ``stdout``, ``stderr``, and ``exit_code``.
        """
        return self._client._request(
            "POST",
            f"/api/v1/agents/{agent_id}/live-response/sessions/{session_id}/exec",
            body={"command": command},
        )


# ─── Main client ──────────────────────────────────────────────────────────────


class KizashiEDRClient:
    """Kizashi API client.

    Uses only Python standard library (``urllib.request``) — no third-party
    packages required.

    Args:
        base_url: Base URL of the API server, e.g.
                  ``https://api.kizashi-edr.example.com``.
        api_key:  JWT bearer token obtained from ``POST /api/v1/auth/login``.
        timeout:  Request timeout in seconds (default ``30``).

    Example::

        client = KizashiEDRClient(
            base_url="https://api.kizashi-edr.example.com",
            api_key="edr_your_token_here",
        )
        result = client.alerts.list(status="open", severity="high")
        for alert in result["data"]:
            print(alert["title"])
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 30,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

        # Resource namespaces
        self.alerts = _AlertsResource(self)
        self.agents = _AgentsResource(self)
        self.incidents = _IncidentsResource(self)
        self.rules = _RulesResource(self)
        self.ioc = _IOCResource(self)
        self.vulnerabilities = _VulnerabilitiesResource(self)
        self.api_keys = _APIKeysResource(self)
        self.live_response = _LiveResponseResource(self)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Execute an authenticated HTTP request.

        Args:
            method: HTTP method (``GET``, ``POST``, ``PATCH``, etc.).
            path:   API path starting with ``/``.
            params: Optional query-string parameters.
            body:   Optional JSON request body.

        Returns:
            Parsed JSON response body (dict or list).

        Raises:
            EDRAPIError: When the server returns a non-2xx status code.
            urllib.error.URLError: On network / connectivity errors.
        """
        url = self._base_url + path
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                url += "?" + urllib.parse.urlencode(filtered)

        data: Optional[bytes] = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._api_key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
                if not raw:
                    return {}
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            response_body: Any = None
            try:
                response_body = json.loads(raw.decode("utf-8"))
            except Exception:
                response_body = raw.decode("utf-8", errors="replace")

            message: str
            if isinstance(response_body, dict) and "error" in response_body:
                message = str(response_body["error"])
            else:
                message = exc.reason or f"HTTP {exc.code}"

            raise EDRAPIError(exc.code, message, response_body) from exc
