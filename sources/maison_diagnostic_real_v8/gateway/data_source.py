"""Read-only data-source contract and the offline fixture adapter."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Protocol


class ReadOnlyDataSource(Protocol):
    def entity(self, entity_id: str) -> dict[str, Any]: ...
    def entities(self) -> list[dict[str, Any]]: ...
    def history(self, entity_id: str, start: str, end: str, limit: int) -> list[dict[str, Any]]: ...
    def traces(self, automation_id: str) -> list[dict[str, Any]]: ...
    def logs(self, component: str) -> list[dict[str, Any]]: ...
    def diagnostics(self) -> dict[str, Any]: ...
    def code_links(self, entity_id: str) -> list[dict[str, Any]]: ...


class FixtureDataSource:
    """Read an immutable, fake dataset once at startup."""

    REQUIRED_KEYS = {"code_links", "diagnostics", "entities", "history", "logs", "traces"}
    mode = "fixture"

    def __init__(self, path: Path):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("fixture must be a regular file of at most 2 MiB")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or set(value) != self.REQUIRED_KEYS:
            raise ValueError("fixture has an invalid top-level structure")
        if not isinstance(value["entities"], list) or not isinstance(value["logs"], list):
            raise ValueError("fixture entities and logs must be lists")
        for name in ("history", "traces", "code_links", "diagnostics"):
            if not isinstance(value[name], dict):
                raise ValueError(f"fixture {name} must be an object")
        self._value = value

    def entities(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._value["entities"])

    def entity(self, entity_id: str) -> dict[str, Any]:
        return next((item for item in self.entities() if item.get("entity_id") == entity_id), {})

    def history(self, entity_id: str, start: str, end: str, limit: int) -> list[dict[str, Any]]:
        return copy.deepcopy(self._value["history"].get(entity_id, []))

    def traces(self, automation_id: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self._value["traces"].get(automation_id, []))

    def logs(self, component: str) -> list[dict[str, Any]]:
        return copy.deepcopy(
            [item for item in self._value["logs"] if item.get("component") == component]
        )

    def diagnostics(self) -> dict[str, Any]:
        return copy.deepcopy(self._value["diagnostics"])

    def code_links(self, entity_id: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self._value["code_links"].get(entity_id, []))
