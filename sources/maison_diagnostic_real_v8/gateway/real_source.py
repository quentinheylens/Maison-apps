"""Fixed-destination, GET-only Supervisor Core adapter. No generic proxy."""

from __future__ import annotations

import http.client
import json
import math
import re
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlencode

from gateway import __version__
from gateway.policy import GatewayPolicy


class SourceUnavailable(Exception):
    pass


class CapabilityUnavailable(Exception):
    pass


class SupervisorReader:
    """The privileged Supervisor credential never leaves this object/container.

    The Supervisor capability is NOT read-only. All application operations below
    build fixed GET paths; no method, host, URL or header is supplied by a caller.
    """

    def __init__(self, token: str, max_bytes: int = 512 * 1024):
        if not token or any(char in token for char in "\r\n"):
            raise ValueError("missing or invalid local Supervisor credential")
        self._token = token
        self.max_bytes = max_bytes
        self._reads = deque()
        self._lock = threading.Lock()

    def _get_json(self, path: str) -> Any:
        with self._lock:
            now = time.monotonic()
            while self._reads and self._reads[0] < now - 60:
                self._reads.popleft()
            if len(self._reads) >= 30:
                raise SourceUnavailable("upstream_budget_exhausted")
            self._reads.append(now)
        connection = http.client.HTTPConnection("supervisor", 80, timeout=5)
        try:
            connection.request("GET", path, headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            })
            response = connection.getresponse()
            if response.status != 200:
                raise SourceUnavailable("upstream_unavailable")
            data = response.read(self.max_bytes + 1)
            if len(data) > self.max_bytes:
                raise SourceUnavailable("upstream_response_too_large")
            return json.loads(data)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise SourceUnavailable("upstream_unavailable") from None
        finally:
            connection.close()

    def state(self, entity_id: str) -> Any:
        if not re.fullmatch(r"(?:sensor|binary_sensor)\.[a-z0-9_]+", entity_id):
            raise SourceUnavailable("entity_not_allowed")
        return self._get_json("/core/api/states/" + quote(entity_id, safe=""))

    def history(self, entity_id: str, start: str, end: str) -> Any:
        if not re.fullmatch(r"(?:sensor|binary_sensor)\.[a-z0-9_]+", entity_id):
            raise SourceUnavailable("entity_not_allowed")
        try:
            first = datetime.fromisoformat(start.replace("Z", "+00:00"))
            last = datetime.fromisoformat(end.replace("Z", "+00:00"))
            if first.tzinfo is None or last.tzinfo is None or not 0 < (last - first).total_seconds() <= 21600:
                raise ValueError
        except (AttributeError, TypeError, ValueError):
            raise SourceUnavailable("invalid_history_window") from None
        query = urlencode({"filter_entity_id": entity_id, "end_time": end,
                           "minimal_response": "true", "no_attributes": "true"})
        return self._get_json("/core/api/history/period/" + quote(start, safe="") + "?" + query)


NUMERIC_STATE = re.compile(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")
SAFE_STATES = {"on", "off", "unknown", "unavailable"}
SAFE_ATTRIBUTES = {"device_class", "state_class", "unit_of_measurement"}
ATTRIBUTE_VALUES = {
    "state_class": {"measurement", "total", "total_increasing"},
    "device_class": {"temperature", "humidity", "energy", "power", "voltage", "current",
                     "frequency", "illuminance", "pressure", "atmospheric_pressure", "battery",
                     "carbon_dioxide", "carbon_monoxide", "pm10", "pm25", "pm1", "aqi",
                     "duration", "data_size", "data_rate", "distance", "volume", "water",
                     "wind_speed", "speed", "sound_pressure", "window", "door", "opening",
                     "heat", "moisture", "smoke", "gas", "problem", "connectivity",
                     "plug", "running", "safety", "update", "power_factor"},
    "unit_of_measurement": {"°C", "°F", "K", "%", "Wh", "kWh", "MWh", "W", "kW", "MW",
                            "V", "A", "mA", "Hz", "lx", "lm", "Pa", "hPa", "bar", "mbar",
                            "dB", "mm", "cm", "m", "km", "s", "min", "h", "ppm", "ppb",
                            "µg/m³", "m³", "m³/h", "L", "L/min", "B", "kB", "MB", "GiB",
                            "Mbit/s", "bit/s", "kbit/s", "Mbps", "rpm", "m/s", "km/h"},
}


def safe_state(value: Any) -> str:
    if isinstance(value, str) and len(value) <= 64:
        if value in SAFE_STATES:
            return value
        if NUMERIC_STATE.fullmatch(value) and math.isfinite(float(value)):
            return value
    return "[redacted-state]"


class HomeAssistantDataSource:
    mode = "supervisor-read"

    def __init__(self, policy: GatewayPolicy, reader: SupervisorReader):
        if len(policy.entities) > 16:
            raise ValueError("real mode permits at most 16 selected entities")
        for entity, rule in policy.entities.items():
            if entity.split(".", 1)[0] not in {"sensor", "binary_sensor"}:
                raise ValueError("real mode permits only sensor and binary_sensor")
            if set(rule.attributes) - SAFE_ATTRIBUTES:
                raise ValueError("real mode attribute is not allowed")
        if policy.history_max_hours > 6 or policy.history_max_points > 100:
            raise ValueError("real history is limited to 6 hours and 100 points")
        self.policy = policy
        self.reader = reader

    def entity(self, entity_id: str) -> dict[str, Any]:
        if entity_id not in self.policy.entities:
            raise SourceUnavailable("entity_not_allowed")
        raw = self.reader.state(entity_id)
        if not isinstance(raw, dict) or raw.get("entity_id") != entity_id:
            raise SourceUnavailable("invalid_upstream_shape")
        attrs = raw.get("attributes", {})
        if not isinstance(attrs, dict):
            attrs = {}
        # Positive value lists prevent names/locations hiding in selected metadata.
        filtered = {key: value for key, value in attrs.items()
                    if key in self.policy.entities[entity_id].attributes
                    and isinstance(value, str) and value in ATTRIBUTE_VALUES[key]}
        changed = raw.get("last_changed")
        try:
            if not isinstance(changed, str) or datetime.fromisoformat(
                changed.replace("Z", "+00:00")
            ).tzinfo is None:
                changed = None
        except ValueError:
            changed = None
        return {"entity_id": entity_id, "state": safe_state(raw.get("state")),
                "attributes": filtered, "last_changed": changed}

    def entities(self) -> list[dict[str, Any]]:
        deadline = time.monotonic() + 10
        result = []
        for entity in sorted(self.policy.entities):
            if time.monotonic() >= deadline:
                raise SourceUnavailable("read_deadline_exceeded")
            result.append(self.entity(entity))
        return result

    def history(self, entity_id: str, start: str, end: str, limit: int) -> list[dict[str, Any]]:
        if entity_id not in self.policy.entities:
            raise SourceUnavailable("entity_not_allowed")
        # Defense in depth: validate bounds even when called outside GatewayService.
        try:
            first = datetime.fromisoformat(start.replace("Z", "+00:00"))
            last = datetime.fromisoformat(end.replace("Z", "+00:00"))
            seconds = (last - first).total_seconds()
            if first.tzinfo is None or last.tzinfo is None or not 0 < seconds <= 6 * 3600:
                raise ValueError
            if not 1 <= limit <= 100:
                raise ValueError
        except (TypeError, ValueError):
            raise SourceUnavailable("invalid_history_window") from None
        raw = self.reader.history(entity_id, start, end)
        if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], list):
            if raw == []:
                return []
            raise SourceUnavailable("invalid_upstream_shape")
        points = []
        for point in raw[0]:
            if not isinstance(point, dict):
                continue
            # HA minimal responses omit entity_id on subsequent points.
            if point.get("entity_id", entity_id) != entity_id:
                continue
            timestamp = point.get("last_changed") or point.get("last_updated")
            if isinstance(timestamp, str):
                try:
                    instant = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    if instant.tzinfo is None or not first <= instant <= last:
                        continue
                except ValueError:
                    continue
                points.append({"timestamp": timestamp, "state": safe_state(point.get("state"))})
            if len(points) >= limit:
                break
        return points

    def traces(self, automation_id: str) -> list[dict[str, Any]]:
        raise CapabilityUnavailable("real_traces_not_enabled")

    def logs(self, component: str) -> list[dict[str, Any]]:
        raise CapabilityUnavailable("real_logs_not_enabled")

    def diagnostics(self) -> dict[str, Any]:
        return {"fixture_mode": False, "gateway_version": __version__}

    def code_links(self, entity_id: str) -> list[dict[str, Any]]:
        raise CapabilityUnavailable("real_code_index_not_installed")
