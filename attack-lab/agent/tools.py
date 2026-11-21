"""Tool Registry and DAST Wrappers for the Offensive AI Red Team Agent.

Task 10.3: Provides HTTP Dispatching, telemetry collection, and DAST
(e.g., SQLMap REST API) integration for automated testing against WAF Gateway.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

import httpx

logger = logging.getLogger("attack_lab.agent.tools")


@dataclass
class DispatchResult:
    """Unified telemetry result of an HTTP dispatch attempt through the WAF."""

    status_code: int
    response_body: str
    latency_ms: float
    is_blocked: bool
    waf_action: str | None = None
    waf_decision: str | None = None
    waf_threat_score: float | None = None
    waf_ml_type: str | None = None
    blocked_reason: str | None = None
    request_id: str | None = None
    confirmed_bypass: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize dispatch result to dictionary format."""
        return asdict(self)


class HttpDispatcher:
    """Dispatches HTTP requests through the WAF Gateway and bakes telemetry."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        proxy_prefix: str = "/api/proxy",
        timeout: float = 5.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.proxy_prefix = proxy_prefix
        self.timeout = timeout
        self._client = client or httpx.Client(timeout=timeout)

    def dispatch(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        bypass_detection_keywords: list[str] | None = None,
    ) -> DispatchResult:
        """Send an HTTP request via the WAF proxy endpoint and parse security telemetry."""
        normalized_path = path.lstrip("/")
        if self.proxy_prefix:
            target_url = f"{self.base_url}{self.proxy_prefix}/{normalized_path}"
        else:
            target_url = f"{self.base_url}/{normalized_path}"

        req_headers = {"User-Agent": "PBL6-AttackLab-RedTeamAgent/1.0"}
        if headers:
            req_headers.update(headers)

        start_time = time.perf_counter()
        try:
            resp = self._client.request(
                method=method.upper(),
                url=target_url,
                params=params,
                json=json_data,
                data=data,
                headers=req_headers,
            )
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return self._parse_response(
                resp=resp,
                latency_ms=latency_ms,
                bypass_keywords=bypass_detection_keywords,
            )
        except Exception as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            logger.warning("HTTP dispatch connection error to %s: %s", target_url, exc)
            return DispatchResult(
                status_code=0,
                response_body="",
                latency_ms=latency_ms,
                is_blocked=False,
                error_message=str(exc),
            )

    def _parse_response(
        self,
        resp: httpx.Response,
        latency_ms: float,
        bypass_keywords: list[str] | None = None,
    ) -> DispatchResult:
        """Parse WAF Gateway telemetry headers and payload body."""
        resp_headers = dict(resp.headers)
        body_text = resp.text
        status = resp.status_code

        # Extract WAF headers
        waf_action = resp_headers.get("x-waf-action")
        waf_decision = resp_headers.get("x-waf-decision")
        waf_ml_type = resp_headers.get("x-waf-ml-type")
        request_id = resp_headers.get("x-request-id")

        threat_score: float | None = None
        raw_score = resp_headers.get("x-waf-risk-score") or resp_headers.get("x-threat-score")
        if raw_score:
            try:
                threat_score = float(raw_score)
            except ValueError:
                threat_score = None

        blocked_reason: str | None = None
        is_blocked = (status == 403) or (waf_action == "BLOCKED")

        # Try parsing JSON body for reason/attack_type
        if is_blocked:
            try:
                data = resp.json()
                blocked_reason = data.get("reason") or data.get("detail")
                if not threat_score and "threat_score" in data:
                    threat_score = float(data["threat_score"])
                if not waf_ml_type and "attack_type" in data:
                    waf_ml_type = str(data["attack_type"])
            except Exception:
                blocked_reason = body_text[:200] if body_text else "Forbidden by WAF"

        # Evaluate confirmed bypass heuristics:
        # Status must be 200/201 and not blocked by WAF.
        confirmed_bypass = False
        if 200 <= status < 300 and not is_blocked:
            if bypass_keywords:
                confirmed_bypass = any(k.lower() in body_text.lower() for k in bypass_keywords)
            else:
                confirmed_bypass = True

        return DispatchResult(
            status_code=status,
            response_body=body_text,
            latency_ms=round(latency_ms, 2),
            is_blocked=is_blocked,
            waf_action=waf_action,
            waf_decision=waf_decision,
            waf_threat_score=threat_score,
            waf_ml_type=waf_ml_type,
            blocked_reason=blocked_reason,
            request_id=request_id,
            confirmed_bypass=confirmed_bypass,
            headers=resp_headers,
        )

    def close(self) -> None:
        """Close client resources."""
        self._client.close()


class SqlmapApiWrapper:
    """REST Client for sqlmapapi daemon (e.g. running at localhost:8775)."""

    def __init__(self, api_url: str = "http://localhost:8775", timeout: float = 5.0) -> None:
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def create_task(self) -> str | None:
        """Create a new SQLMap scanning task."""
        try:
            resp = self._client.get(f"{self.api_url}/task/new")
            if resp.status_code == 200 and resp.json().get("success"):
                return str(resp.json().get("taskid"))
        except Exception as exc:
            logger.debug("SQLMap API server unreachable: %s", exc)
        return None

    def start_scan(
        self,
        task_id: str,
        target_url: str,
        options: dict[str, Any] | None = None,
        tamper: str | None = None,
    ) -> bool:
        """Start a scanning job with optional tamper script configuration."""
        data: dict[str, Any] = {"url": target_url}
        if options:
            data.update(options)
        if tamper:
            data["tamper"] = tamper

        try:
            resp = self._client.post(f"{self.api_url}/scan/{task_id}/start", json=data)
            return bool(resp.status_code == 200 and resp.json().get("success"))
        except Exception as exc:
            logger.debug("Failed to start SQLMap scan on task %s: %s", task_id, exc)
            return False

    def get_scan_status(self, task_id: str) -> dict[str, Any]:
        """Poll the scan status of a given task."""
        try:
            resp = self._client.get(f"{self.api_url}/scan/{task_id}/status")
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            logger.debug("Failed to poll SQLMap task %s: %s", task_id, exc)
        return {"status": "error", "success": False}

    def get_scan_data(self, task_id: str) -> dict[str, Any]:
        """Fetch vulnerability findings for a completed task."""
        try:
            resp = self._client.get(f"{self.api_url}/scan/{task_id}/data")
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            logger.debug("Failed to fetch SQLMap data on task %s: %s", task_id, exc)
        return {"data": [], "success": False}

    def delete_task(self, task_id: str) -> bool:
        """Release and delete a task."""
        try:
            resp = self._client.get(f"{self.api_url}/task/{task_id}/delete")
            return bool(resp.status_code == 200 and resp.json().get("success"))
        except Exception:
            return False

    def close(self) -> None:
        """Close client resources."""
        self._client.close()


class ToolRegistry:
    """Central registry of offensive tools available to the Red Team Agent."""

    def __init__(self) -> None:
        self._tools: dict[str, Any] = {}

    def register(self, name: str, tool_instance: Any) -> None:
        """Register a tool instance under a given name."""
        self._tools[name] = tool_instance

    def get(self, name: str) -> Any:
        """Fetch a registered tool instance by name."""
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' is not registered in ToolRegistry.")
        return self._tools[name]

    def has(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._tools

