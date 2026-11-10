"""Version 2 read contract: explicit profiles, bounded fan-out, no admin calls."""

import json
import math
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import quote, urlencode, unquote, urlsplit, parse_qs

from gateway.real_source import ATTRIBUTE_VALUES, SourceUnavailable
from gateway.service import GatewayError, RateLimiter, bounded_limit, one, require_query_keys, parse_timestamp

SCOPES = {"entities:read", "history:read", "correlate:read", "evidence:read", "code-links:read"}
DOMAINS = {"sensor": "numeric", "input_number": "numeric", "number": "numeric",
           "binary_sensor": "binary", "input_boolean": "binary", "switch": "binary",
           "climate": "climate", "automation": "automation", "script": "automation", "timer": "timer",
           "input_datetime": "timestamp", "input_select": "command_enum"}
ENUMS = {"binary": {"on", "off"}, "climate": {"off", "heat", "cool", "auto", "heat_cool", "dry", "fan_only"},
         "automation": {"on", "off"}, "timer": {"active", "idle", "paused"},
         "command_enum": {"none", "pending", "start", "stop", "idle", "on", "off", "heat", "cool"}}
SENSITIVE = re.compile(r"(?:presence|occupancy|person|location|latitude|longitude|gps|camera|alarm|lock|serrure|"
                       r"phone|email|address|adresse|tracking|geocod|ssid|door|fenetre|absence|pir)", re.I)
NUMBER = re.compile(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")
ATTRIBUTES = {"numeric": {"unit_of_measurement", "device_class"}, "binary": set(),
              "climate": {"temperature", "current_temperature", "target_temp_low", "target_temp_high", "hvac_action"},
              "automation": {"last_triggered", "current"}, "timer": {"finishes_at"},
              "timestamp": {"timestamp"}, "command_enum": set()}


def numeric(value):
    try:
        return not isinstance(value, bool) and bool(NUMBER.fullmatch(str(value))) and math.isfinite(float(value))
    except (ValueError, TypeError, OverflowError):
        return False


def safe_timestamp(value):
    try:
        if isinstance(value, str) and len(value) <= 40:
            return parse_timestamp(value, "timestamp").isoformat()
    except GatewayError:
        pass
    return None


class DiagnosticPolicy:
    def __init__(self, raw):
        if not isinstance(raw, dict) or set(raw) != {"version", "entities", "identities", "history_hours",
                                                    "history_points", "rate_limit", "log_components"}:
            raise ValueError("invalid diagnostic policy fields")
        if type(raw["version"]) is not int or raw["version"] != 2:
            raise ValueError("diagnostic policy version 2 required")
        self.entities = raw["entities"]
        if not isinstance(self.entities, dict) or not 1 <= len(self.entities) <= 16:
            raise ValueError("select one to sixteen entities")
        for entity, attributes in self.entities.items():
            if (not isinstance(entity, str) or len(entity) > 200 or not re.fullmatch(r"[a-z_]+\.[a-z0-9_]+", entity)
                    or entity.split(".")[0] not in DOMAINS or SENSITIVE.search(entity)):
                raise ValueError("sensitive or unsupported entity")
            profile = DOMAINS[entity.split(".")[0]]
            if (not isinstance(attributes, list) or any(not isinstance(a, str) for a in attributes)
                    or len(attributes) != len(set(attributes)) or set(attributes) - ATTRIBUTES[profile]):
                raise ValueError("attribute not approved for profile")
        self.identities = raw["identities"]
        if not isinstance(self.identities, dict) or not 1 <= len(self.identities) <= 4:
            raise ValueError("bounded identities required")
        for identity, scopes in self.identities.items():
            if (not re.fullmatch(r"[a-z][a-z0-9_-]{2,63}", identity) or not isinstance(scopes, list)
                    or any(not isinstance(s, str) for s in scopes) or set(scopes) - SCOPES):
                raise ValueError("invalid identity scopes")
        for key, maximum in (("history_hours", 6), ("history_points", 50), ("rate_limit", 12)):
            if type(raw[key]) is not int or not 1 <= raw[key] <= maximum:
                raise ValueError("diagnostic bound exceeded")
            setattr(self, key, raw[key])
        self.log_components = raw["log_components"]
        if (not isinstance(self.log_components, list) or len(self.log_components) > 8
                or any(not isinstance(c, str) or not re.fullmatch(r"[a-z][a-z0-9_.]{1,63}", c)
                       or SENSITIVE.search(c) for c in self.log_components)):
            raise ValueError("invalid log components")

    def require_entity(self, entity):
        if entity not in self.entities:
            raise GatewayError(404, "not_found")
        return DOMAINS[entity.split(".")[0]]

    def state(self, entity, value):
        profile = self.require_entity(entity)
        if value in ("unknown", "unavailable"):
            return value
        if profile == "numeric" and numeric(value):
            return str(value)
        if profile == "timestamp" and safe_timestamp(value):
            return safe_timestamp(value)
        if isinstance(value, str) and value in ENUMS.get(profile, set()):
            return value
        return "[redacted-state]"

    def filter_entity(self, entity, raw):
        profile = self.require_entity(entity)
        if not isinstance(raw, dict) or raw.get("entity_id") != entity:
            raise SourceUnavailable("invalid upstream shape")
        source = raw.get("attributes", {})
        source = source if isinstance(source, dict) else {}
        attributes = {}
        for name in self.entities[entity]:
            value = source.get(name)
            if name in ATTRIBUTE_VALUES and isinstance(value, str) and value in ATTRIBUTE_VALUES[name]:
                attributes[name] = value
            elif name in {"temperature", "current_temperature", "target_temp_low", "target_temp_high", "current"} and numeric(value):
                attributes[name] = float(value)
            elif name in {"last_triggered", "finishes_at"} and safe_timestamp(value):
                attributes[name] = safe_timestamp(value)
            elif name == "hvac_action" and isinstance(value, str) and value in {"off", "idle", "heating", "cooling", "drying", "fan"}:
                attributes[name] = value
            elif name == "timestamp" and source.get("has_date") is True and numeric(value) and 0 <= float(value) <= 4102444800:
                attributes[name] = float(value)
        state = self.state(entity, raw.get("state"))
        if profile == "timestamp" and "timestamp" in attributes:
            state = datetime.fromtimestamp(attributes["timestamp"], timezone.utc).isoformat()
        return {"entity_id": entity, "state": state,
                "last_changed": safe_timestamp(raw.get("last_changed")), "attributes": attributes}


class CoreReadAdapter:
    """Transport injection only. No credentials, environment lookup or live default.

    A future local transport may wrap SupervisorReader._get_json. Its token is
    write-capable, and requires a separately reviewed privileged application.
    """
    def __init__(self, policy, transport):
        self.policy, self.transport = policy, transport
        self.budget = RateLimiter(30)

    def _get(self, path):
        if not self.budget.allow("core"):
            raise SourceUnavailable("source budget exceeded")
        result = self.transport.get(path)  # Fixed generated GET contract, never an arbitrary URL.
        if len(json.dumps(result, allow_nan=False).encode()) > 512 * 1024:
            raise SourceUnavailable("source response too large")
        return result

    def entity(self, entity):
        self.policy.require_entity(entity)
        return self.policy.filter_entity(entity, self._get("/core/api/states/" + quote(entity, safe="")))

    def history(self, entity, start, end, limit):
        self.policy.require_entity(entity)
        if not 0 < (end - start).total_seconds() <= self.policy.history_hours * 3600 or not 1 <= limit <= self.policy.history_points:
            raise GatewayError(400, "invalid_history_bounds")
        query = urlencode({"filter_entity_id": entity, "end_time": end.isoformat(),
                           "minimal_response": "true", "no_attributes": "true"})
        raw = self._get("/core/api/history/period/" + quote(start.isoformat(), safe="") + "?" + query)
        if raw == []:
            return []
        if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], list):
            raise SourceUnavailable("invalid history shape")
        points = []
        for item in raw[0]:
            if not isinstance(item, dict) or item.get("entity_id", entity) != entity:
                continue
            stamp = safe_timestamp(item.get("last_changed") or item.get("last_updated"))
            if stamp and start <= parse_timestamp(stamp, "timestamp") <= end:
                points.append({"timestamp": stamp, "state": self.policy.state(entity, item.get("state"))})
        points.sort(key=lambda p: p["timestamp"])
        return points[:limit]


class LocalSupervisorGET:
    """Future local wrapper for an injected SupervisorReader, never wired at boot.

    The reader owns a write-capable credential. This wrapper narrows calls, not
    the credential's privileges. The shipped manifests do not request it.
    """
    simulation = False
    def __init__(self, policy, reader):
        self.policy, self.reader = policy, reader

    def get(self, path):
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise ValueError("fixed local Core destination required")
        if parsed.path.startswith("/core/api/states/") and not parsed.query:
            entity = unquote(parsed.path.removeprefix("/core/api/states/"))
            self.policy.require_entity(entity)
            if parsed.path != "/core/api/states/" + quote(entity, safe=""):
                raise ValueError("noncanonical entity path")
        elif parsed.path.startswith("/core/api/history/period/"):
            query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=4)
            if set(query) != {"filter_entity_id", "end_time", "minimal_response", "no_attributes"}:
                raise ValueError("invalid local history request")
            entity = one(query, "filter_entity_id")
            self.policy.require_entity(entity)
            first = parse_timestamp(unquote(parsed.path.removeprefix("/core/api/history/period/")), "start")
            last = parse_timestamp(one(query, "end_time"), "end")
            if (not 0 < (last - first).total_seconds() <= self.policy.history_hours * 3600
                    or query["minimal_response"] != ["true"] or query["no_attributes"] != ["true"]):
                raise ValueError("local history bound exceeded")
        else:
            raise ValueError("local Core route refused")
        return self.reader._get_json(path)


class DiagnosticService:
    def __init__(self, policy, source, audit, *, evidence=None, code_index=None):
        self.policy, self.source, self.audit = policy, source, audit
        self.evidence, self.code_index = evidence, code_index
        self.limiter = RateLimiter(policy.rate_limit)

    def _history(self, query):
        entity = one(query, "entity_id")
        self.policy.require_entity(entity)
        start, end = parse_timestamp(one(query, "start"), "start"), parse_timestamp(one(query, "end"), "end")
        limit = bounded_limit(query, self.policy.history_points)
        if not 0 < (end - start).total_seconds() <= self.policy.history_hours * 3600:
            raise GatewayError(400, "invalid_time_window")
        return entity, start, end, limit

    def _page(self, query, maximum):
        raw = one(query, "offset", required=False) or "0"
        if not re.fullmatch(r"\d{1,4}", raw) or int(raw) > maximum:
            raise GatewayError(400, "invalid_offset")
        return int(raw), bounded_limit(query, 4, default=4)

    def handle(self, method, path, query, identity):
        request_id, status, code = str(uuid.uuid4()), 500, "internal_error"
        try:
            if method != "GET":
                raise GatewayError(405, "method_not_allowed")
            if path == "/healthz":
                require_query_keys(query, set())
                status, code = 200, "ok"
                return status, {"status": "ok", "version": "0.6.1",
                                "simulation": getattr(self.source.transport, "simulation", False) is True}
            if identity not in self.policy.identities:
                raise GatewayError(401, "unauthorized")
            if not self.limiter.allow(identity):
                raise GatewayError(429, "rate_limited")
            scopes = self.policy.identities[identity]
            route = "entities" if path.startswith("/v2/entities") else path.removeprefix("/v2/")
            scope = {"entities": "entities:read", "history": "history:read", "correlate": "correlate:read",
                     "evidence": "evidence:read", "code-links": "code-links:read"}.get(route)
            if scope is None:
                raise GatewayError(404, "not_found")
            if scope not in scopes:
                raise GatewayError(403, "forbidden")
            if path == "/v2/entities":
                require_query_keys(query, {"offset", "limit"})
                offset, limit = self._page(query, 16)
                entities = sorted(self.policy.entities)
                items = [self.source.entity(e) for e in entities[offset:offset + limit]]
                payload = {"entities": items, "count": len(items),
                           "next_offset": offset + limit if offset + limit < len(entities) else None}
            elif path.startswith("/v2/entities/"):
                require_query_keys(query, set())
                entity = path.removeprefix("/v2/entities/")
                self.policy.require_entity(entity)
                payload = self.source.entity(entity)
            elif path == "/v2/history":
                require_query_keys(query, {"entity_id", "start", "end", "limit"})
                entity, start, end, limit = self._history(query)
                points = self.source.history(entity, start, end, limit)
                payload = {"entity_id": entity, "count": len(points), "points": points}
            elif path == "/v2/correlate":
                require_query_keys(query, {"entities", "start", "end"})
                entities = one(query, "entities").split(",")
                if not 2 <= len(entities) <= 4 or len(set(entities)) != len(entities):
                    raise GatewayError(400, "invalid_correlation_entities")
                for e in entities:
                    self.policy.require_entity(e)
                first, last = parse_timestamp(one(query, "start"), "start"), parse_timestamp(one(query, "end"), "end")
                if not 0 < (last - first).total_seconds() <= min(3600, self.policy.history_hours * 3600):
                    raise GatewayError(400, "invalid_time_window")
                series = {e: self.source.history(e, first, last, self.policy.history_points) for e in entities}
                # One-minute bins, last observation in the bin, no interpolation.
                bins = {}
                for e, points in series.items():
                    for p in points:
                        slot = int(parse_timestamp(p["timestamp"], "timestamp").timestamp()) // 60
                        if numeric(p["state"]):
                            bins.setdefault(slot, {})[e] = float(p["state"])
                pairs = []
                for i, left in enumerate(entities):
                    for right in entities[i + 1:]:
                        samples = [(v[left], v[right]) for v in bins.values() if left in v and right in v]
                        coefficient = None
                        if len(samples) >= 3:
                            x, y = zip(*samples)
                            a, b = sum(x) / len(x), sum(y) / len(y)
                            numerator = sum((u - a) * (v - b) for u, v in samples)
                            denominator = math.sqrt(sum((u - a) ** 2 for u in x) * sum((v - b) ** 2 for v in y))
                            if denominator and math.isfinite(numerator) and math.isfinite(denominator):
                                coefficient = max(-1.0, min(1.0, numerator / denominator))
                        pairs.append({"left": left, "right": right, "paired_samples": len(samples), "pearson": coefficient})
                payload = {"pairs": pairs, "causality_established": False, "bin_seconds": 60}
            elif path == "/v2/evidence":
                require_query_keys(query, {"entity_id", "kind", "offset", "limit"})
                entity = one(query, "entity_id")
                self.policy.require_entity(entity)
                if self.evidence is None:
                    raise GatewayError(501, "local_extraction_required")
                offset, limit = self._page(query, 1000)
                payload = self.evidence.page(entity, one(query, "kind"), offset, limit)
            elif path == "/v2/code-links":
                require_query_keys(query, {"entity_id"})
                entity = one(query, "entity_id")
                self.policy.require_entity(entity)
                if self.code_index is None:
                    raise GatewayError(501, "local_mapping_required")
                payload = self.code_index.links(entity)
            else:
                raise GatewayError(404, "not_found")
            response = {"request_id": request_id, "data": payload}
            if len(json.dumps(response, allow_nan=False).encode()) > 256 * 1024:
                raise GatewayError(413, "response_too_large")
            status, code = 200, "allowed"
            return status, response
        except GatewayError as error:
            status, code = error.status, error.code
        except SourceUnavailable:
            status, code = 503, "source_unavailable"
        except Exception:
            status, code = 500, "internal_error"
        finally:
            self.audit.write(request_id=request_id, identity=identity, method=method if method in {"GET", "POST", "PUT", "PATCH", "DELETE"} else "OTHER",
                             route="/v2/read-contract", status=status, outcome=code)
        return status, {"request_id": request_id, "error": {"code": code}}
