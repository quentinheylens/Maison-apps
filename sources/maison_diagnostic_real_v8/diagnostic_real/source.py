"""Useful projections of real state, code and execution evidence."""
from datetime import datetime, timezone
import json
import re
import threading
import time
from diagnostic_real.files import ConfigReader
from diagnostic_real.reader import entity_id, window, ENTITY
from gateway.real_source import SourceUnavailable

DOMAINS = {'sensor', 'binary_sensor', 'climate', 'cover', 'switch', 'light', 'fan', 'automation',
           'script', 'input_boolean', 'input_number', 'input_datetime', 'input_select', 'number',
           'select', 'timer', 'schedule', 'water_heater', 'humidifier', 'vacuum', 'weather', 'sun'}
ATTRIBUTES = {'friendly_name', 'device_class', 'state_class', 'unit_of_measurement', 'temperature',
              'current_temperature', 'target_temp_high', 'target_temp_low', 'hvac_action', 'hvac_modes',
              'preset_mode', 'preset_modes', 'fan_mode', 'supported_features', 'min_temp', 'max_temp',
              'current_position', 'battery_level', 'last_triggered', 'mode', 'current', 'max', 'id'}
SAFE_STATE = re.compile(r'(?:[-+]?\d+(?:\.\d*)?(?:[eE][-+]?\d+)?|on|off|unknown|unavailable|'
                        r'open|closed|opening|closing|heat|cool|heat_cool|auto|dry|fan_only|idle|'
                        r'heating|cooling|home|away|eco|comfort|boost|paused|active|waiting|'
                        r'cleaning|docked|returning|error|sunrise|sunset|above_horizon|below_horizon|'
                        r'\d{4}-\d{2}-\d{2}(?:[T ][0-9:.+Z-]+)?|\d{2}:\d{2}:\d{2})')
REGISTRY_FIELDS = {
    'entities': {'entity_id', 'device_id', 'area_id', 'platform', 'disabled_by', 'hidden_by', 'name', 'original_name'},
    'devices': {'id', 'area_id', 'name', 'name_by_user', 'manufacturer', 'model', 'sw_version', 'disabled_by'},
    'areas': {'area_id', 'name', 'floor_id'},
}

def allowed(entity):
    return isinstance(entity, str) and ENTITY.fullmatch(entity) and entity.split('.')[0] in DOMAINS

def timestamp(value):
    try:
        if isinstance(value, str) and datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo:
            return value
    except ValueError:
        pass
    return None

class DiagnosticSource:
    def __init__(self, reader, config_root, privacy):
        self.reader, self.privacy = reader, privacy
        self.config = ConfigReader(config_root, privacy)
        self.cache = {}
        self.lock = threading.RLock()

    def effective_privacy(self):
        return self.cached("privacy", self.config.effective_privacy)

    def cached(self, key, fetch):
        with self.lock:
            if key not in self.cache or time.monotonic() - self.cache[key][0] > 30:
                value = fetch()
                self.cache[key] = (time.monotonic(), value)
            return self.cache[key][1]

    def state(self, raw):
        value = raw.get('state')
        state = value if isinstance(value, str) and len(value) <= 80 and SAFE_STATE.fullmatch(value) else '[redacted-state]'
        attrs = raw.get('attributes', {})
        return {'entity_id': raw['entity_id'], 'state': state,
                'last_changed': timestamp(raw.get('last_changed')),
                'last_updated': timestamp(raw.get('last_updated')),
                'attributes': self.effective_privacy().clean({k: v for k, v in attrs.items() if k in ATTRIBUTES}) if isinstance(attrs, dict) else {}}

    def states(self):
        def fetch():
            raw = self.reader.states()
            if not isinstance(raw, list) or len(raw) > 20000:
                raise SourceUnavailable('invalid_state_inventory')
            return sorted([self.state(x) for x in raw if isinstance(x, dict) and allowed(x.get('entity_id'))],
                          key=lambda x: x['entity_id'])
        return self.cached('states', fetch)

    def registry(self, kind):
        def fetch():
            raw = self.reader.registry(kind)
            if not isinstance(raw, list) or len(raw) > 20000:
                raise SourceUnavailable('invalid_registry_inventory')
            return [self.effective_privacy().clean({k: v for k, v in x.items() if k in REGISTRY_FIELDS[kind]})
                    for x in raw if isinstance(x, dict) and (kind != 'entities' or allowed(x.get('entity_id')))]
        return self.cached(kind, fetch)

    def definitions(self):
        return self.cached('definitions', self.config.snapshot)

    def history(self, entity, start, end, limit):
        entity_id(entity)
        first, last = window(start, end)
        if not allowed(entity) or not 1 <= limit <= 1000:
            raise ValueError('invalid_history_request')
        raw = self.reader.history(entity, start, end)
        if raw == []: return {'points': [], 'truncated': False}
        if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], list):
            raise SourceUnavailable('invalid_history_shape')
        result = []
        for item in raw[0]:
            if not isinstance(item, dict) or item.get('entity_id', entity) != entity: continue
            when = timestamp(item.get('last_changed') or item.get('last_updated'))
            if when and first <= datetime.fromisoformat(when.replace('Z', '+00:00')) <= last:
                state = self.state({'entity_id': entity, 'state': item.get('state')})['state']
                result.append({'timestamp': when, 'state': state})
        return {'entity_id': entity, 'points': result[:limit], 'truncated': len(result) > limit,
                'note': 'Recorder retention and include/exclude settings determine available history.'}

    def traces(self, domain, item, run=None):
        raw = self.reader.traces(domain, item, run)
        fields = {'run_id', 'state', 'script_execution', 'last_step', 'timestamp', 'error', 'domain', 'item_id'}
        def summary(value):
            if not isinstance(value, dict): raise SourceUnavailable('invalid_trace_shape')
            output = {k: self.effective_privacy().clean(v) for k, v in value.items() if k in fields}
            # Never return trace variables, changed variables, context, service results or raw config.
            if isinstance(value.get('trace'), dict):
                steps = []
                for path, rows in list(value['trace'].items())[:200]:
                    if not isinstance(rows, list): continue
                    for row in rows[:10]:
                        if isinstance(row, dict):
                            result = row.get('result', {})
                            entry = {k: self.effective_privacy().clean(row[k]) for k in ('timestamp', 'error') if k in row}
                            entry['path'] = self.effective_privacy().text(str(path))
                            if isinstance(result, dict):
                                entry['result'] = {k: result[k] for k in ('result', 'enabled') if type(result.get(k)) is bool}
                            steps.append(entry)
                output['steps'] = steps
            return output
        if run is None:
            if not isinstance(raw, list): raise SourceUnavailable('invalid_trace_shape')
            data = [summary(x) for x in raw[:50]]
        else:
            data = summary(raw)
        return {'traces': data, 'limitations': 'Absence of a trace does not prove absence of execution. Only stored traces are available; variables and service payloads are suppressed.'}

    def links(self):
        snapshot = self.definitions()
        states = {x['entity_id']: x for x in self.states()}
        objects = []
        for file in snapshot['files']:
            definition = file['definition']
            def walk(value, pointer=''):
                if isinstance(value, dict):
                    if any(k in value for k in ('trigger', 'triggers', 'action', 'actions', 'sequence', 'use_blueprint')):
                        encoded = json.dumps(value, ensure_ascii=False)
                        refs = sorted({m.group() for m in ENTITY.finditer(encoded) if allowed(m.group())})
                        objects.append({'path': file['path'], 'pointer': pointer,
                            'id': value.get('id'), 'alias': value.get('alias'), 'entity_references': refs,
                            'device_references': sorted(set(device_refs(value))),
                            'dynamic_references': '{{' in encoded or '{%' in encoded or '!input' in encoded or 'use_blueprint' in value,
                            'unavailable_references': [x for x in refs if x in states and states[x]['state'] in {'unavailable', 'unknown'}]})
                        return
                    for key, item in value.items(): walk(item, pointer+'/'+str(key).replace('~','~0').replace('/','~1'))
                elif isinstance(value, list):
                    for index, item in enumerate(value): walk(item, pointer+'/'+str(index))
            walk(definition)
        return {'revision': snapshot['revision'], 'objects': objects,
                'limitations': 'Static references are evidence, not proof of runtime target resolution or heating conflicts. Resolve templates, blueprint inputs, device registry and traces before proposing changes.'}

def device_refs(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == 'device_id':
                for ref in item if isinstance(item, list) else [item]:
                    if isinstance(ref, str): yield ref
            else: yield from device_refs(item)
    elif isinstance(value, list):
        for item in value: yield from device_refs(item)
