"""Local positive-schema extraction. Raw traces/messages never cross the API."""

import json
from datetime import datetime, timezone

from gateway.service import GatewayError
from maintenance.diagnostics import safe_timestamp
from maintenance.safe_fs import MAX_FILE, Tree, canonical

KINDS = {"trace", "event", "log"}
STATES = {"running", "finished", "error", "stopped", "unavailable"}
ERRORS = {"TemplateError", "TimeoutError", "ServiceNotFound", "InvalidStateError"}
EVENTS = {"state_changed", "automation_triggered", "automation_error"}


def extract(raw, policy):
    if not isinstance(raw, list) or len(raw) > 1000 or len(canonical(raw)) > MAX_FILE:
        raise ValueError("local evidence input exceeds bound")
    result = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        entity, kind = item.get("entity_id"), item.get("kind")
        if not isinstance(entity, str) or not isinstance(kind, str) or entity not in policy.entities or kind not in KINDS:
            continue
        stamp = safe_timestamp(item.get("timestamp"))
        if stamp is None:
            continue
        status = item.get("status")
        record = {"entity_id": entity, "kind": kind, "timestamp": stamp,
                  "status": status if isinstance(status, str) and status in STATES else "unavailable"}
        if kind == "log":
            if item.get("component") not in policy.log_components:
                continue
            record["component"] = item["component"]
        if kind == "event":
            if not isinstance(item.get("event_type"), str) or item.get("event_type") not in EVENTS:
                continue
            record["event_type"] = item["event_type"]
        error = item.get("error_class")
        record["error_class"] = error if isinstance(error, str) and error in ERRORS else None
        # Trace variables, messages, contexts, names, URLs and steps are absent.
        result.append(record)
    return sorted(result, key=lambda r: r["timestamp"], reverse=True)[:200]


class EvidenceVault:
    def __init__(self, raw, policy, *, now=None):
        self.records = extract(raw, policy)
        now = now or datetime.now(timezone.utc)
        self.records = [r for r in self.records
                        if 0 <= (now - datetime.fromisoformat(r["timestamp"])).total_seconds() <= 86400]

    @classmethod
    def from_local(cls, path, policy, *, now=None):
        from pathlib import Path
        path = Path(path)
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise ValueError("evidence must be private")
        tree = Tree(path.parent)
        try:
            return cls(json.loads(tree.read(path.name)), policy, now=now)
        finally:
            tree.close()

    def page(self, entity, kind, offset, limit):
        if kind not in KINDS:
            raise GatewayError(400, "invalid_evidence_kind")
        records = [r for r in self.records if r["entity_id"] == entity and r["kind"] == kind]
        page = records[offset:offset + limit]
        return {"records": page, "count": len(page), "next_offset": offset + limit if offset + limit < len(records) else None,
                "provenance": "local-extract", "full_trace_available": False}
