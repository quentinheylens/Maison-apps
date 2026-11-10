"""Policy enforcement and read-only gateway operations."""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote

from gateway.audit import AuditLogger
from gateway.data_source import ReadOnlyDataSource
from gateway.policy import GatewayPolicy
from gateway.redaction import sanitize
from gateway.real_source import CapabilityUnavailable, SourceUnavailable


MAX_RESPONSE_BYTES = 1024 * 1024
TRACE_FIELDS = {"automation_id", "error", "finished_at", "started_at", "state", "step", "trace_id"}
LOG_FIELDS = {"component", "level", "message", "timestamp"}
STATIC_AUDIT_ROUTES = {
    "/healthz",
    "/v1/automation-traces",
    "/v1/code-links",
    "/v1/diagnostics",
    "/v1/entities",
    "/v1/history",
    "/v1/logs",
}
INTEGRATION_DOMAIN_RE = re.compile(r"[a-z][a-z0-9_]{1,63}")
INTEGRATION_STATES = {"disabled", "error", "loaded", "not_loaded", "setup_retry"}


class GatewayError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def parse_timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GatewayError(400, f"invalid_{label}") from exc
    if parsed.tzinfo is None:
        raise GatewayError(400, f"invalid_{label}")
    return parsed.astimezone(timezone.utc)


def one(query: dict[str, list[str]], name: str, *, required: bool = True) -> str | None:
    values = query.get(name, [])
    if not values:
        if required:
            raise GatewayError(400, f"missing_{name}")
        return None
    if len(values) != 1 or not values[0] or len(values[0]) > 256:
        raise GatewayError(400, f"invalid_{name}")
    return values[0]


def bounded_limit(query: dict[str, list[str]], maximum: int, default: int = 50) -> int:
    raw = one(query, "limit", required=False)
    if raw is None:
        return min(default, maximum)
    try:
        value = int(raw)
    except ValueError as exc:
        raise GatewayError(400, "invalid_limit") from exc
    if not 1 <= value <= maximum:
        raise GatewayError(400, "invalid_limit")
    return value


def require_query_keys(query: dict[str, list[str]], allowed: set[str]) -> None:
    if set(query) - allowed:
        raise GatewayError(400, "unknown_query_parameter")


def audit_route(path: str) -> str:
    if path.startswith("/v1/entities/"):
        return "/v1/entities/{entity_id}"
    if path in STATIC_AUDIT_ROUTES:
        return path
    return "/unmatched"


class RateLimiter:
    def __init__(self, maximum: int):
        self.maximum = maximum
        self.events: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, identity: str) -> bool:
        now = time.monotonic()
        with self.lock:
            events = self.events[identity]
            while events and events[0] <= now - 60:
                events.popleft()
            if len(events) >= self.maximum:
                return False
            events.append(now)
            return True


class GatewayService:
    """Expose a small allowlisted read contract; no write method exists."""

    def __init__(
        self,
        policy: GatewayPolicy,
        source: ReadOnlyDataSource,
        audit: AuditLogger,
    ):
        self.policy = policy
        self.source = source
        self.audit = audit
        self.rate_limiter = RateLimiter(policy.rate_limit_per_minute)

    def handle(
        self,
        method: str,
        path: str,
        query: dict[str, list[str]],
        identity: str | None,
    ) -> tuple[int, dict[str, Any]]:
        request_id = str(uuid.uuid4())
        route = audit_route(path)
        status = 500
        outcome = "internal_error"
        try:
            if method != "GET":
                raise GatewayError(405, "method_not_allowed")
            if path == "/healthz":
                require_query_keys(query, set())
                status, outcome = 200, "ok"
                return status, {"request_id": request_id, "status": "ok",
                                "mode": getattr(self.source, "mode", "fixture")}
            if identity not in self.policy.identities:
                raise GatewayError(401, "unauthorized")
            if not self.rate_limiter.allow(identity):
                raise GatewayError(429, "rate_limited")

            payload = self._read(path, query, identity)
            response = {
                "request_id": request_id,
                "data": sanitize(payload, redact_terms=self.policy.redact_terms),
            }
            if len(json.dumps(response, ensure_ascii=False).encode("utf-8")) > MAX_RESPONSE_BYTES:
                raise GatewayError(413, "response_too_large")
            status, outcome = 200, "allowed"
            return status, response
        except (SourceUnavailable, CapabilityUnavailable) as exc:
            status = 503 if isinstance(exc, SourceUnavailable) else 501
            outcome = "source_unavailable" if status == 503 else "capability_unavailable"
            return status, {"request_id": request_id, "error": {"code": outcome}}
        except GatewayError as exc:
            status, outcome = exc.status, exc.code
            return status, {"request_id": request_id, "error": {"code": exc.code}}
        except Exception:
            status, outcome = 500, "internal_error"
            return status, {"request_id": request_id, "error": {"code": "internal_error"}}
        finally:
            self.audit.write(
                request_id=request_id,
                identity=identity,
                method=method if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} else "OTHER",
                route=route,
                status=status,
                outcome=outcome,
            )

    def _require_scope(self, identity: str, scope: str) -> None:
        if not self.policy.authorize(identity, scope):
            raise GatewayError(403, "forbidden")

    def _read(
        self,
        path: str,
        query: dict[str, list[str]],
        identity: str,
    ) -> Any:
        if path == "/v1/entities":
            self._require_scope(identity, "entities:read")
            require_query_keys(query, set())
            return self._entities()
        if path.startswith("/v1/entities/"):
            self._require_scope(identity, "entities:read")
            require_query_keys(query, set())
            entity_id = unquote(path.removeprefix("/v1/entities/"))
            return self._entity(entity_id)
        if path == "/v1/history":
            self._require_scope(identity, "history:read")
            return self._history(query)
        if path == "/v1/automation-traces":
            self._require_scope(identity, "traces:read")
            return self._traces(query)
        if path == "/v1/logs":
            self._require_scope(identity, "logs:read")
            return self._logs(query)
        if path == "/v1/diagnostics":
            self._require_scope(identity, "diagnostics:read")
            require_query_keys(query, set())
            return self._diagnostics()
        if path == "/v1/code-links":
            self._require_scope(identity, "code-links:read")
            return self._code_links(query)
        raise GatewayError(404, "not_found")

    def _filter_entity(self, item: dict[str, Any]) -> dict[str, Any]:
        entity_id = item.get("entity_id")
        rule = self.policy.entities.get(entity_id)
        if rule is None:
            raise GatewayError(404, "not_found")
        attributes = item.get("attributes", {})
        if not isinstance(attributes, dict):
            attributes = {}
        return {
            "entity_id": entity_id,
            "state": item.get("state"),
            "last_changed": item.get("last_changed"),
            "attributes": {name: attributes[name] for name in rule.attributes if name in attributes},
        }

    def _entities(self) -> dict[str, Any]:
        allowed = []
        for item in self.source.entities():
            if isinstance(item, dict) and item.get("entity_id") in self.policy.entities:
                allowed.append(self._filter_entity(item))
        allowed.sort(key=lambda item: item["entity_id"])
        return {"count": len(allowed), "entities": allowed}

    def _entity(self, entity_id: str) -> dict[str, Any]:
        if entity_id not in self.policy.entities:
            raise GatewayError(404, "not_found")
        item = self.source.entity(entity_id)
        if isinstance(item, dict) and item.get("entity_id") == entity_id:
            return self._filter_entity(item)
        raise GatewayError(404, "not_found")

    def _history(self, query: dict[str, list[str]]) -> dict[str, Any]:
        require_query_keys(query, {"end", "entity_id", "limit", "start"})
        entity_id = one(query, "entity_id")
        if entity_id not in self.policy.entities:
            raise GatewayError(404, "not_found")
        start = parse_timestamp(one(query, "start") or "", "start")
        end = parse_timestamp(one(query, "end") or "", "end")
        if end <= start or (end - start).total_seconds() > self.policy.history_max_hours * 3600:
            raise GatewayError(400, "invalid_time_window")
        limit = bounded_limit(query, self.policy.history_max_points)
        points = []
        for point in self.source.history(entity_id, start.isoformat(), end.isoformat(), limit):
            if not isinstance(point, dict) or not isinstance(point.get("timestamp"), str):
                continue
            timestamp = parse_timestamp(point["timestamp"], "fixture_timestamp")
            if start <= timestamp <= end:
                points.append({"timestamp": point["timestamp"], "state": point.get("state")})
        points.sort(key=lambda point: point["timestamp"])
        return {"entity_id": entity_id, "count": min(len(points), limit), "points": points[:limit]}

    def _traces(self, query: dict[str, list[str]]) -> dict[str, Any]:
        require_query_keys(query, {"automation_id", "limit"})
        automation_id = one(query, "automation_id")
        if automation_id not in self.policy.automation_allowlist:
            raise GatewayError(404, "not_found")
        limit = bounded_limit(query, 20, default=5)
        traces = []
        for trace in self.source.traces(automation_id)[:limit]:
            if isinstance(trace, dict):
                traces.append({key: trace[key] for key in TRACE_FIELDS if key in trace})
        return {"automation_id": automation_id, "count": len(traces), "traces": traces}

    def _logs(self, query: dict[str, list[str]]) -> dict[str, Any]:
        require_query_keys(query, {"component", "limit"})
        component = one(query, "component")
        if component not in self.policy.log_components:
            raise GatewayError(404, "not_found")
        limit = bounded_limit(query, 100)
        entries = []
        for entry in self.source.logs(component)[:limit]:
            if isinstance(entry, dict):
                entries.append({key: entry[key] for key in LOG_FIELDS if key in entry})
        return {"component": component, "count": len(entries), "entries": entries}

    def _diagnostics(self) -> dict[str, Any]:
        diagnostics = self.source.diagnostics()
        result: dict[str, Any] = {}
        for key in sorted(self.policy.diagnostic_fields):
            if key not in diagnostics:
                continue
            value = diagnostics[key]
            if key == "integration_status":
                if not isinstance(value, dict):
                    continue
                result[key] = {
                    domain: state
                    for domain, state in value.items()
                    if isinstance(domain, str)
                    and INTEGRATION_DOMAIN_RE.fullmatch(domain)
                    and isinstance(state, str)
                    and state in INTEGRATION_STATES
                }
            elif isinstance(value, (bool, int, float, str)) or value is None:
                result[key] = value
        return result

    def _code_links(self, query: dict[str, list[str]]) -> dict[str, Any]:
        require_query_keys(query, {"entity_id"})
        entity_id = one(query, "entity_id")
        if entity_id not in self.policy.entities:
            raise GatewayError(404, "not_found")
        links = []
        for link in self.source.code_links(entity_id):
            if not isinstance(link, dict):
                continue
            path = link.get("path")
            line = link.get("line")
            kind = link.get("kind")
            candidate = PurePosixPath(path) if isinstance(path, str) else None
            if (
                candidate is None
                or candidate.is_absolute()
                or ".." in candidate.parts
                or not isinstance(line, int)
                or line < 1
                or kind not in {"definition", "reference"}
            ):
                continue
            links.append({"path": str(candidate), "line": line, "kind": kind})
        return {"entity_id": entity_id, "count": len(links), "links": links}
