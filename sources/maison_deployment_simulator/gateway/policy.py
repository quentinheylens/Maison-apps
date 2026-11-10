"""Validated positive policy for the read-only gateway."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gateway.redaction import COMPACT_SENSITIVE_KEYS, compact_key


ALLOWED_SCOPES = {
    "code-links:read",
    "diagnostics:read",
    "entities:read",
    "history:read",
    "logs:read",
    "traces:read",
}
SENSITIVE_DOMAINS = {
    "alarm_control_panel",
    "camera",
    "device_tracker",
    "lock",
    "person",
}
TOP_LEVEL_KEYS = {
    "automation_allowlist",
    "diagnostic_fields",
    "entities",
    "history",
    "identities",
    "log_components",
    "rate_limit_per_minute",
    "redact_terms",
    "version",
}
ENTITY_ID_RE = re.compile(r"[a-z][a-z0-9_]*\.[a-z0-9_]+")
ATTRIBUTE_RE = re.compile(r"[a-z_][a-z0-9_]*")
AUTOMATION_ID_RE = re.compile(r"automation\.[a-z0-9_]+")
COMPONENT_RE = re.compile(r"[a-z][a-z0-9_.]+")


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _string_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be a list of non-empty strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} contains duplicates")
    return tuple(value)


@dataclass(frozen=True)
class EntityRule:
    attributes: tuple[str, ...]


@dataclass(frozen=True)
class GatewayPolicy:
    identities: dict[str, frozenset[str]]
    entities: dict[str, EntityRule]
    automation_allowlist: frozenset[str]
    log_components: frozenset[str]
    diagnostic_fields: frozenset[str]
    history_max_hours: int
    history_max_points: int
    rate_limit_per_minute: int
    redact_terms: tuple[str, ...]

    @classmethod
    def load(cls, path: Path) -> "GatewayPolicy":
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError("policy must be a regular file of at most 1 MiB")
        value = json.loads(path.read_text(encoding="utf-8"))
        root = _require_object(value, "policy")
        unexpected = sorted(set(root) - TOP_LEVEL_KEYS)
        if unexpected:
            raise ValueError("unknown policy fields: " + ", ".join(unexpected))
        if root.get("version") != 1:
            raise ValueError("policy version must be 1")

        identities: dict[str, frozenset[str]] = {}
        for identity, raw_rule in _require_object(root.get("identities"), "identities").items():
            if (
                not isinstance(identity, str)
                or not identity
                or len(identity) > 200
                or identity != identity.strip()
                or any(ord(character) < 32 for character in identity)
            ):
                raise ValueError("invalid identity")
            rule = _require_object(raw_rule, f"identity {identity}")
            if set(rule) != {"scopes"}:
                raise ValueError(f"identity {identity} must contain only scopes")
            scopes = frozenset(_string_list(rule.get("scopes"), f"identity {identity} scopes"))
            unknown_scopes = sorted(scopes - ALLOWED_SCOPES)
            if unknown_scopes:
                raise ValueError("unknown scopes: " + ", ".join(unknown_scopes))
            identities[identity] = scopes
        if not identities:
            raise ValueError("at least one identity is required")

        entities: dict[str, EntityRule] = {}
        for entity_id, raw_rule in _require_object(root.get("entities"), "entities").items():
            if not isinstance(entity_id, str) or not ENTITY_ID_RE.fullmatch(entity_id):
                raise ValueError(f"invalid entity id: {entity_id}")
            domain = entity_id.split(".", 1)[0]
            if domain in SENSITIVE_DOMAINS:
                raise ValueError(f"sensitive entity domain is forbidden: {domain}")
            rule = _require_object(raw_rule, f"entity {entity_id}")
            if set(rule) != {"attributes"}:
                raise ValueError(f"entity {entity_id} must contain only attributes")
            attributes = _string_list(rule.get("attributes"), f"entity {entity_id} attributes")
            if any(not ATTRIBUTE_RE.fullmatch(attribute) for attribute in attributes):
                raise ValueError(f"entity {entity_id} contains an invalid attribute")
            if any(compact_key(attribute) in COMPACT_SENSITIVE_KEYS for attribute in attributes):
                raise ValueError(f"entity {entity_id} contains a sensitive attribute")
            entities[entity_id] = EntityRule(attributes=attributes)

        history = _require_object(root.get("history"), "history")
        if set(history) != {"max_hours", "max_points"}:
            raise ValueError("history must contain max_hours and max_points")
        max_hours = history.get("max_hours")
        max_points = history.get("max_points")
        rate_limit = root.get("rate_limit_per_minute")
        if not isinstance(max_hours, int) or not 1 <= max_hours <= 168:
            raise ValueError("history max_hours must be between 1 and 168")
        if not isinstance(max_points, int) or not 1 <= max_points <= 1000:
            raise ValueError("history max_points must be between 1 and 1000")
        if not isinstance(rate_limit, int) or not 1 <= rate_limit <= 600:
            raise ValueError("rate_limit_per_minute must be between 1 and 600")
        redact_terms = _string_list(root.get("redact_terms"), "redact_terms")
        if len(redact_terms) > 100 or any(
            len(term) < 3
            or len(term) > 100
            or any(ord(character) < 32 for character in term)
            for term in redact_terms
        ):
            raise ValueError("redact_terms must contain at most 100 terms of 3 to 100 characters")

        diagnostic_fields = _string_list(root.get("diagnostic_fields"), "diagnostic_fields")
        if any(not ATTRIBUTE_RE.fullmatch(field) for field in diagnostic_fields):
            raise ValueError("diagnostic_fields contains an invalid field")
        if any(compact_key(field) in COMPACT_SENSITIVE_KEYS for field in diagnostic_fields):
            raise ValueError("diagnostic_fields contains a sensitive field")

        automation_allowlist = _string_list(
            root.get("automation_allowlist"),
            "automation_allowlist",
        )
        if any(not AUTOMATION_ID_RE.fullmatch(item) for item in automation_allowlist):
            raise ValueError("automation_allowlist contains an invalid id")
        log_components = _string_list(root.get("log_components"), "log_components")
        if any(not COMPONENT_RE.fullmatch(item) for item in log_components):
            raise ValueError("log_components contains an invalid component")

        return cls(
            identities=identities,
            entities=entities,
            automation_allowlist=frozenset(automation_allowlist),
            log_components=frozenset(log_components),
            diagnostic_fields=frozenset(diagnostic_fields),
            history_max_hours=max_hours,
            history_max_points=max_points,
            rate_limit_per_minute=rate_limit,
            redact_terms=redact_terms,
        )

    def authorize(self, identity: str | None, scope: str) -> bool:
        return identity is not None and scope in self.identities.get(identity, frozenset())
