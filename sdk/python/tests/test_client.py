"""
Unit tests for KizashiEDRClient (Python SDK).

Run with:  pytest sdk/python/tests/
or from the sdk/python directory:  pytest
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from io import BytesIO
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Ensure the package is importable regardless of working directory.
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[1]))

from kizashi_edr import (
    Alert,
    Agent,
    EDRAPIError,
    Incident,
    KizashiEDRClient,
)

# ─── Constants ────────────────────────────────────────────────────────────────

BASE_URL = "https://api.kizashi-edr.example.com"
API_KEY = "edr_test_python_key"


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_response(body: Any, status: int = 200) -> MagicMock:
    """Return a mock context-manager response that reads JSON."""
    raw = json.dumps(body).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = raw
    mock_resp.status = status
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _make_http_error(status: int, body: Any) -> urllib.error.HTTPError:
    """Return a urllib HTTPError whose .read() returns a JSON body."""
    raw = json.dumps(body).encode("utf-8")
    err = urllib.error.HTTPError(
        url="https://example.com",
        code=status,
        msg=f"HTTP {status}",
        hdrs=None,  # type: ignore[arg-type]
        fp=BytesIO(raw),
    )
    return err


# ─── Constructor ──────────────────────────────────────────────────────────────


class TestConstructor:
    def test_stores_base_url_without_trailing_slash(self):
        c = KizashiEDRClient(base_url="https://api.example.com/", api_key="k")
        assert c._base_url == "https://api.example.com"

    def test_stores_base_url_without_slash(self):
        c = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)
        assert c._base_url == BASE_URL

    def test_stores_api_key(self):
        c = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)
        assert c._api_key == API_KEY

    def test_default_timeout_is_30(self):
        c = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)
        assert c._timeout == 30

    def test_custom_timeout_stored(self):
        c = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY, timeout=60)
        assert c._timeout == 60

    def test_resource_namespaces_created(self):
        c = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)
        assert hasattr(c, "alerts")
        assert hasattr(c, "agents")
        assert hasattr(c, "incidents")
        assert hasattr(c, "rules")
        assert hasattr(c, "ioc")


# ─── alerts.list ──────────────────────────────────────────────────────────────


class TestAlertsList:
    def setup_method(self):
        self.client = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)

    @patch("urllib.request.urlopen")
    def test_calls_get_on_alerts_endpoint(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.alerts.list()

        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/alerts"
        assert req.get_method() == "GET"

    @patch("urllib.request.urlopen")
    def test_returns_dict_with_data_and_total(self, mock_urlopen):
        payload = {
            "data": [{"id": "a1", "title": "T", "severity": "high", "status": "open"}],
            "total": 1,
        }
        mock_urlopen.return_value = _make_response(payload)
        result = self.client.alerts.list()
        assert result["total"] == 1
        assert result["data"][0]["id"] == "a1"

    @patch("urllib.request.urlopen")
    def test_sends_authorization_header(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.alerts.list()
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == f"Bearer {API_KEY}"

    @patch("urllib.request.urlopen")
    def test_appends_severity_filter(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.alerts.list(severity="critical")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert "severity=critical" in req.full_url

    @patch("urllib.request.urlopen")
    def test_appends_status_filter(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.alerts.list(status="open")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert "status=open" in req.full_url

    @patch("urllib.request.urlopen")
    def test_omits_none_params_from_url(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.alerts.list(severity=None, status=None)
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert "?" not in req.full_url

    @patch("urllib.request.urlopen")
    def test_appends_limit_and_offset(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.alerts.list(limit=10, offset=20)
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert "limit=10" in req.full_url
        assert "offset=20" in req.full_url


# ─── agents.isolate ───────────────────────────────────────────────────────────


class TestAgentsIsolate:
    def setup_method(self):
        self.client = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)

    @patch("urllib.request.urlopen")
    def test_calls_post_on_isolate_endpoint(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({})
        self.client.agents.isolate("agent-xyz")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/agents/agent-xyz/isolate"
        assert req.get_method() == "POST"

    @patch("urllib.request.urlopen")
    def test_sends_authorization_header(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({})
        self.client.agents.isolate("agent-xyz")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == f"Bearer {API_KEY}"

    @patch("urllib.request.urlopen")
    def test_returns_response_dict(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"status": "isolated"})
        result = self.client.agents.isolate("agent-xyz")
        assert isinstance(result, dict)


# ─── EDRAPIError on HTTP errors ───────────────────────────────────────────────


class TestEDRAPIError:
    def setup_method(self):
        self.client = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)

    @patch("urllib.request.urlopen")
    def test_raises_on_401(self, mock_urlopen):
        mock_urlopen.side_effect = _make_http_error(401, {"error": "Unauthorized"})
        with pytest.raises(EDRAPIError) as exc_info:
            self.client.alerts.list()
        assert exc_info.value.status == 401
        assert "Unauthorized" in exc_info.value.message

    @patch("urllib.request.urlopen")
    def test_raises_on_403(self, mock_urlopen):
        mock_urlopen.side_effect = _make_http_error(403, {"error": "Forbidden"})
        with pytest.raises(EDRAPIError) as exc_info:
            self.client.agents.list()
        assert exc_info.value.status == 403

    @patch("urllib.request.urlopen")
    def test_raises_on_404(self, mock_urlopen):
        mock_urlopen.side_effect = _make_http_error(404, {"error": "Alert not found"})
        with pytest.raises(EDRAPIError) as exc_info:
            self.client.alerts.get("nonexistent-id")
        assert exc_info.value.status == 404
        assert "Alert not found" in exc_info.value.message

    @patch("urllib.request.urlopen")
    def test_raises_on_500(self, mock_urlopen):
        mock_urlopen.side_effect = _make_http_error(500, {"error": "Internal error"})
        with pytest.raises(EDRAPIError) as exc_info:
            self.client.incidents.list()
        assert exc_info.value.status == 500

    @patch("urllib.request.urlopen")
    def test_attaches_body_to_error(self, mock_urlopen):
        body = {"error": "Validation failed", "field": "severity"}
        mock_urlopen.side_effect = _make_http_error(422, body)
        with pytest.raises(EDRAPIError) as exc_info:
            self.client.alerts.list()
        assert exc_info.value.body == body

    @patch("urllib.request.urlopen")
    def test_error_message_from_json_error_field(self, mock_urlopen):
        mock_urlopen.side_effect = _make_http_error(400, {"error": "Bad input"})
        with pytest.raises(EDRAPIError) as exc_info:
            self.client.alerts.list()
        assert exc_info.value.message == "Bad input"

    @patch("urllib.request.urlopen")
    def test_error_falls_back_to_reason_when_no_error_field(self, mock_urlopen):
        mock_urlopen.side_effect = _make_http_error(502, {"message": "Bad Gateway"})
        with pytest.raises(EDRAPIError) as exc_info:
            self.client.agents.list()
        # message should be the HTTP reason string when no 'error' key present
        assert exc_info.value.status == 502


# ─── Query parameter encoding ─────────────────────────────────────────────────


class TestQueryParams:
    def setup_method(self):
        self.client = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)

    @patch("urllib.request.urlopen")
    def test_no_query_string_when_no_params(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.alerts.list()
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert "?" not in req.full_url

    @patch("urllib.request.urlopen")
    def test_single_param_appended(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.agents.list(status="offline")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert "status=offline" in req.full_url

    @patch("urllib.request.urlopen")
    def test_multiple_params_appended(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.alerts.list(severity="high", status="open", limit=5, offset=10)
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert "severity=high" in req.full_url
        assert "status=open" in req.full_url
        assert "limit=5" in req.full_url
        assert "offset=10" in req.full_url

    @patch("urllib.request.urlopen")
    def test_integer_params_are_url_encoded(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.alerts.list(limit=100)
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert "limit=100" in req.full_url


# ─── Alert dataclass ──────────────────────────────────────────────────────────


class TestAlertDataclass:
    def _full_data(self) -> Dict[str, Any]:
        return {
            "id": "alert-001",
            "title": "Ransomware detected",
            "severity": "critical",
            "status": "open",
            "description": "File encryption activity observed",
            "rule_name": "Ransomware_FileEnc",
            "agent_id": "agent-001",
            "hostname": "WIN-SERVER01",
            "mitre_technique": "T1486",
            "created_at": "2026-03-01T10:00:00Z",
            "resolved_at": None,
        }

    def test_from_dict_required_fields(self):
        data = {"id": "a", "title": "T", "severity": "high", "status": "open"}
        alert = Alert.from_dict(data)
        assert alert.id == "a"
        assert alert.title == "T"
        assert alert.severity == "high"
        assert alert.status == "open"

    def test_from_dict_optional_fields_populated(self):
        alert = Alert.from_dict(self._full_data())
        assert alert.description == "File encryption activity observed"
        assert alert.rule_name == "Ransomware_FileEnc"
        assert alert.agent_id == "agent-001"
        assert alert.hostname == "WIN-SERVER01"
        assert alert.mitre_technique == "T1486"
        assert alert.created_at == "2026-03-01T10:00:00Z"

    def test_from_dict_optional_fields_default_to_none(self):
        data = {"id": "a", "title": "T", "severity": "low", "status": "resolved"}
        alert = Alert.from_dict(data)
        assert alert.description is None
        assert alert.rule_name is None
        assert alert.agent_id is None
        assert alert.hostname is None
        assert alert.mitre_technique is None
        assert alert.resolved_at is None

    def test_from_dict_is_alert_instance(self):
        data = {"id": "a", "title": "T", "severity": "info", "status": "open"}
        assert isinstance(Alert.from_dict(data), Alert)


# ─── Agent dataclass ──────────────────────────────────────────────────────────


class TestAgentDataclass:
    def _full_data(self) -> Dict[str, Any]:
        return {
            "id": "agent-999",
            "hostname": "LINUX-WEB01",
            "status": "online",
            "os": "linux",
            "os_version": "Ubuntu 22.04",
            "ip_address": "10.0.0.5",
            "version": "2.1.0",
            "last_seen_at": "2026-03-23T09:00:00Z",
            "tags": ["web", "prod"],
        }

    def test_from_dict_required_fields(self):
        data = {"id": "x", "hostname": "HOST", "status": "offline"}
        agent = Agent.from_dict(data)
        assert agent.id == "x"
        assert agent.hostname == "HOST"
        assert agent.status == "offline"

    def test_from_dict_optional_fields_populated(self):
        agent = Agent.from_dict(self._full_data())
        assert agent.os == "linux"
        assert agent.os_version == "Ubuntu 22.04"
        assert agent.ip_address == "10.0.0.5"
        assert agent.version == "2.1.0"
        assert agent.last_seen_at == "2026-03-23T09:00:00Z"
        assert agent.tags == ["web", "prod"]

    def test_from_dict_tags_default_to_empty_list(self):
        data = {"id": "x", "hostname": "HOST", "status": "online"}
        agent = Agent.from_dict(data)
        assert agent.tags == []

    def test_from_dict_null_tags_normalized_to_empty_list(self):
        data = {"id": "x", "hostname": "HOST", "status": "online", "tags": None}
        agent = Agent.from_dict(data)
        assert agent.tags == []

    def test_from_dict_is_agent_instance(self):
        data = {"id": "x", "hostname": "H", "status": "isolated"}
        assert isinstance(Agent.from_dict(data), Agent)


# ─── Incident dataclass ───────────────────────────────────────────────────────


class TestIncidentDataclass:
    def test_from_dict_required_fields(self):
        data = {
            "id": "inc-001",
            "title": "Breach investigation",
            "severity": "critical",
            "status": "investigating",
        }
        inc = Incident.from_dict(data)
        assert inc.id == "inc-001"
        assert inc.title == "Breach investigation"
        assert inc.severity == "critical"
        assert inc.status == "investigating"

    def test_from_dict_optional_fields_default_to_none(self):
        data = {"id": "i", "title": "T", "severity": "high", "status": "open"}
        inc = Incident.from_dict(data)
        assert inc.description is None
        assert inc.assigned_to is None
        assert inc.created_at is None

    def test_from_dict_optional_fields_populated(self):
        data = {
            "id": "i",
            "title": "T",
            "severity": "low",
            "status": "closed",
            "description": "False alarm",
            "assigned_to": "analyst@example.com",
            "created_at": "2026-01-15T08:00:00Z",
        }
        inc = Incident.from_dict(data)
        assert inc.description == "False alarm"
        assert inc.assigned_to == "analyst@example.com"
        assert inc.created_at == "2026-01-15T08:00:00Z"

    def test_from_dict_is_incident_instance(self):
        data = {"id": "i", "title": "T", "severity": "medium", "status": "open"}
        assert isinstance(Incident.from_dict(data), Incident)


# ─── vulnerabilities.list / stats ─────────────────────────────────────────────


class TestVulnerabilitiesList:
    def setup_method(self):
        self.client = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)

    @patch("urllib.request.urlopen")
    def test_vulnerabilities_list_sends_get(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.vulnerabilities.list()
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        # list() includes default limit/offset query params
        assert req.full_url.startswith(f"{BASE_URL}/api/v1/vulnerabilities")
        assert req.get_method() == "GET"

    @patch("urllib.request.urlopen")
    def test_vulnerabilities_list_with_filters(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.vulnerabilities.list(severity="critical", status="open", agent_id="agent-001")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert "severity=critical" in req.full_url
        assert "status=open" in req.full_url
        assert "agent_id=agent-001" in req.full_url

    @patch("urllib.request.urlopen")
    def test_vulnerabilities_stats(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"critical": 2, "high": 5})
        self.client.vulnerabilities.stats()
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/vulnerabilities/stats"
        assert req.get_method() == "GET"


# ─── api_keys ─────────────────────────────────────────────────────────────────


class TestAPIKeys:
    def setup_method(self):
        self.client = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)

    @patch("urllib.request.urlopen")
    def test_api_keys_list(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.api_keys.list()
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/api-keys"
        assert req.get_method() == "GET"

    @patch("urllib.request.urlopen")
    def test_api_keys_create(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"id": "key-1", "name": "ci-key"})
        self.client.api_keys.create(name="ci-key", scopes=["alerts:read", "agents:read"])
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/api-keys"
        assert req.get_method() == "POST"
        body = json.loads(req.data.decode("utf-8"))
        assert body["name"] == "ci-key"
        assert body["scopes"] == ["alerts:read", "agents:read"]

    @patch("urllib.request.urlopen")
    def test_api_keys_revoke(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({})
        self.client.api_keys.revoke("key-1")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/api-keys/key-1"
        assert req.get_method() == "DELETE"


# ─── live_response ────────────────────────────────────────────────────────────


class TestLiveResponse:
    def setup_method(self):
        self.client = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)

    # **この3つは、サーバに無い宛先を留めていました。**
    #
    # 検査はクライアントの実装から書かれていて、サーバの経路と突き合わせた
    # ものは1つもありませんでした —— **緑のまま、呼べば必ず 404** です。
    # セッションは端末ごと（`/agents/:id/live-response/sessions`）です。

    @patch("urllib.request.urlopen")
    def test_live_response_list(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"data": [], "total": 0})
        self.client.live_response.list(agent_id="agent-007")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/agents/agent-007/live-response/sessions"
        assert req.get_method() == "GET"

    @patch("urllib.request.urlopen")
    def test_live_response_open(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"id": "sess-1", "agent_id": "agent-007"})
        self.client.live_response.open(agent_id="agent-007")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/agents/agent-007/live-response/sessions"
        assert req.get_method() == "POST"

    @patch("urllib.request.urlopen")
    def test_live_response_exec(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"output": "uid=0(root)"})
        self.client.live_response.exec(agent_id="agent-007", session_id="sess-1", command="id")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            f"{BASE_URL}/api/v1/agents/agent-007/live-response/sessions/sess-1/exec"
        )
        assert req.get_method() == "POST"
        body = json.loads(req.data.decode("utf-8"))
        assert body["command"] == "id"


class TestAlertsUpdate:
    """alerts.update は検査が 1 つも無く、PATCH を送っていました。

    サーバに在るのは `PUT /alerts/:id` だけなので、呼べば必ず失敗します。
    incidents / rules は同じ誤りが検査で見つかりましたが、ここは検査そのものが
    無かったため残っていました。**検査の無いメソッドは、壊れていても緑です。**
    """

    def setup_method(self):
        self.client = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)

    @patch("urllib.request.urlopen")
    def test_update_calls_put(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"id": "alert-1", "status": "investigating"})
        self.client.alerts.update("alert-1", status="investigating")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/alerts/alert-1"
        assert req.get_method() == "PUT"

    @patch("urllib.request.urlopen")
    def test_update_sends_status_and_assigned_to_in_body(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"id": "alert-1", "status": "resolved"})
        self.client.alerts.update("alert-1", status="resolved", assigned_to="alice")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert body["status"] == "resolved"
        assert body["assigned_to"] == "alice"


class TestIncidentsUpdate:
    def setup_method(self):
        self.client = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)

    @patch("urllib.request.urlopen")
    def test_update_calls_put(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"id": "inc-1", "status": "investigating"})
        self.client.incidents.update("inc-1", status="investigating")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/incidents/inc-1"
        assert req.get_method() == "PUT"

    @patch("urllib.request.urlopen")
    def test_update_sends_status_and_assigned_to_in_body(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"id": "inc-1", "status": "resolved"})
        self.client.incidents.update("inc-1", status="resolved", assigned_to="alice")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert body["status"] == "resolved"
        assert body["assigned_to"] == "alice"

    @patch("urllib.request.urlopen")
    def test_update_omits_none_fields(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({"id": "inc-1"})
        self.client.incidents.update("inc-1", status="closed")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert "assigned_to" not in body
        assert "description" not in body


class TestRulesCRUD:
    def setup_method(self):
        self.client = KizashiEDRClient(base_url=BASE_URL, api_key=API_KEY)

    @patch("urllib.request.urlopen")
    def test_get_calls_get_endpoint(self, mock_urlopen):
        mock_urlopen.return_value = _make_response(
            {"id": "rule-1", "name": "mimikatz", "type": "sigma", "condition": "x", "enabled": True}
        )
        self.client.rules.get("rule-1")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/rules/rule-1"
        assert req.get_method() == "GET"

    @patch("urllib.request.urlopen")
    def test_update_calls_put(self, mock_urlopen):
        mock_urlopen.return_value = _make_response(
            {"id": "rule-1", "name": "mimikatz", "type": "sigma", "condition": "x", "enabled": False}
        )
        self.client.rules.update("rule-1", enabled=False)
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/rules/rule-1"
        assert req.get_method() == "PUT"

    @patch("urllib.request.urlopen")
    def test_update_sends_only_provided_fields(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({})
        self.client.rules.update("rule-1", enabled=True, severity="high")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert body["enabled"] is True
        assert body["severity"] == "high"
        assert "name" not in body

    @patch("urllib.request.urlopen")
    def test_delete_calls_delete(self, mock_urlopen):
        mock_urlopen.return_value = _make_response({})
        self.client.rules.delete("rule-99")
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        assert req.full_url == f"{BASE_URL}/api/v1/rules/rule-99"
        assert req.get_method() == "DELETE"
