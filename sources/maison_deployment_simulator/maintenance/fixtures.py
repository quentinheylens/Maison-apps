"""Synthetic local HA transport. No production identifiers or personal values."""

import copy
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, parse_qs, urlsplit

from maintenance.diagnostics import DiagnosticPolicy


def policy():
    return DiagnosticPolicy({"version": 2, "entities": {
        "sensor.technical_temperature": ["unit_of_measurement", "device_class"],
        "input_number.technical_target": [], "climate.test_heater": ["temperature", "hvac_action"],
        "automation.test_regulation": ["last_triggered", "current"]},
        "identities": {"diagnostic-simulator": ["entities:read", "history:read", "correlate:read", "evidence:read", "code-links:read"]},
        "history_hours": 1, "history_points": 50, "rate_limit": 12,
        "log_components": ["homeassistant.components.automation"]})


class SimulatedHATransport:
    simulation = True
    def __init__(self, now=None):
        self.now = now or datetime.now(timezone.utc).replace(microsecond=0)
        self.calls = []
        self.failed = False
        self.entities = {
            "sensor.technical_temperature": {"state": "21.5", "attributes": {"unit_of_measurement": "°C", "device_class": "temperature", "friendly_name": "private"}},
            "input_number.technical_target": {"state": "22", "attributes": {}},
            "climate.test_heater": {"state": "heat", "attributes": {"temperature": 22, "hvac_action": "heating"}},
            "automation.test_regulation": {"state": "on", "attributes": {"last_triggered": self.now.isoformat(), "current": 0}}}

    def get(self, path):
        from gateway.real_source import SourceUnavailable
        self.calls.append(path)
        if self.failed:
            raise SourceUnavailable("simulated source loss")
        if path.startswith("/core/api/states/"):
            entity = unquote(path.removeprefix("/core/api/states/"))
            if entity not in self.entities:
                raise SourceUnavailable("unavailable")
            return {**copy.deepcopy(self.entities[entity]), "entity_id": entity, "last_changed": self.now.isoformat()}
        if path.startswith("/core/api/history/period/"):
            query = parse_qs(urlsplit(path).query)
            entity = query["filter_entity_id"][0]
            return [[{"entity_id": entity, "state": str(20 + n),
                      "last_changed": (self.now - timedelta(minutes=30 - n * 5)).isoformat()}
                     for n in range(6)]]
        raise AssertionError("non-read or unknown Core path")
