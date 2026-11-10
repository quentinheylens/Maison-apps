"""Offline integration and hostile-input coverage of the real diagnostic boundary."""
import hashlib
import io
import base64
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'sources' / 'maison_diagnostic_real_v8'))
from diagnostic_real.files import ConfigReader, ConfigError, ordinary, parse
from diagnostic_real.privacy import Privacy
from diagnostic_real.reader import CoreReader, ReadSocket, MAX_BYTES
from diagnostic_real.runtime import options_checked, DiagnosticTailnet
from diagnostic_real.entrypoint import prepare
from diagnostic_real.source import DiagnosticSource
from diagnostic_real.service import DiagnosticService
from gateway.network_auth import GatewayCredentials
from gateway.server import GatewayHTTPServer, handler_factory
from gateway.real_source import SourceUnavailable
CLIENT = 'example-client-credential-' + 'a' * 32
LOCAL = 'example-local-credential-' + 'b' * 32
OPTIONS = dict(enabled=True, read_approved=True, acl_reviewed=True, client_token=CLIENT, tailscale_auth_key='', redact_terms=[])

class Audit:

    def __init__(self):
        self.rows = []

    def write(self, **kw):
        self.rows.append(kw)

class Reader:

    def states(self):
        return [dict(entity_id='climate.stove', state='heat', attributes={'friendly_name': 'MCZ', 'current_temperature': 20, 'temperature': 21, 'access_token': LOCAL, 'entity_picture': 'https://example.invalid/private'}), dict(entity_id='sensor.temperature', state='unavailable', attributes={}), dict(entity_id='automation.stove', state='on', attributes={'id': 'stove', 'last_triggered': '2026-11-10T12:00:00Z'}), dict(entity_id='sensor.string', state=LOCAL, attributes={}), dict(entity_id='person.private', state='home', attributes={})]

    def registry(self, kind):
        return [dict(id='device-stove', entity_id='climate.stove', name='MCZ', serial_number=LOCAL, connections=[LOCAL], identifiers=[LOCAL], device_id='device-stove', area_id='living')]

    def traces(self, domain, item, run):
        data = dict(run_id='run-1', state='stopped', script_execution='failed', last_step='action/0', error='Failed action', changed_variables={'access_token': LOCAL}, trace={'condition/0': [{'timestamp': '2026-11-10T12:00:00Z', 'result': {'result': False, 'response': LOCAL}, 'changed_variables': {'x': LOCAL}}]})
        return data if run else [data]

    def history(self, *args):
        return [[{'entity_id': 'climate.stove', 'last_changed': '2026-11-10T12:00:00Z', 'state': 'heat'}, {'last_changed': '2026-11-10T12:01:00Z', 'state': 'off'}, {'last_changed': '2026-11-10T12:02:00Z', 'state': 'heat'}]]

class DiagnosticTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'automations.yaml').write_text('- id: stove\n  alias: MCZ schedule\n  triggers:\n    - trigger: state\n      entity_id: sensor.temperature\n  conditions: []\n  actions:\n    - action: climate.set_temperature\n      target:\n        entity_id: climate.stove\n      data:\n        temperature: 21\n')
        (self.root / 'scripts.yaml').write_text('warm:\n  alias: Warm\n  sequence:\n    - action: climate.turn_off\n      target:\n        entity_id: climate.stove\n')
        self.audit = Audit()
        self.source = DiagnosticSource(Reader(), self.root, Privacy([CLIENT, LOCAL]))
        self.service = DiagnosticService(self.source, self.audit)

    def get(self, path, **query):
        return self.service.handle('GET', path, {k: [str(v)] for k, v in query.items()}, 'codex-cloud')

    def test_discovery_and_unavailable_real_projection(self):
        status, result = self.get('/v2/entities')
        self.assertEqual(status, 200)
        rows = result['data']['items']
        self.assertEqual(len(rows), 4)
        climate = next((x for x in rows if x['entity_id'] == 'climate.stove'))
        self.assertEqual(climate['attributes']['temperature'], 21)
        self.assertEqual(climate['state'], 'heat')
        self.assertNotIn(LOCAL, json.dumps(result))
        status, result = self.get('/v2/unavailable')
        self.assertEqual(result['data']['items'][0]['entity_id'], 'sensor.temperature')

    def test_definitions_and_links_keep_operational_semantics(self):
        status, response = self.get('/v2/definitions', limit=1)
        self.assertEqual(status, 200)
        self.assertEqual(response['data']['next_offset'], 1)
        revision = response['data']['revision']
        status, _ = self.get('/v2/definitions', revision='0' * 64)
        self.assertEqual(status, 409)
        status, response = self.get('/v2/code-links', entity_id='climate.stove')
        self.assertEqual(response['data']['count'], 2)
        self.assertEqual(response['data']['items'][0]['unavailable_references'], ['sensor.temperature'])

    def test_registry_and_trace_suppress_variables_credentials_and_serials(self):
        for route, query in [('/v2/registry', {'kind': 'devices'}), ('/v2/traces', {'domain': 'automation', 'item_id': 'stove', 'run_id': 'run-1'})]:
            status, response = self.get(route, **query)
            self.assertEqual(status, 200)
            text = json.dumps(response)
            for word in (LOCAL, 'changed_variables', 'serial_number', 'connections', 'identifiers'):
                self.assertNotIn(word, text)
        self.assertIn('false', text)

    def test_history_is_bounded_and_marks_truncation(self):
        status, response = self.get('/v2/history', entity_id='climate.stove', start='2026-11-10T12:00:00Z', end='2026-11-10T13:00:00Z', limit=2)
        self.assertEqual(status, 200)
        self.assertTrue(response['data']['truncated'])
        self.assertEqual(len(response['data']['points']), 2)
        status, _ = self.get('/v2/history', entity_id='climate.stove', start='2026-11-08T12:00:00Z', end='2026-11-10T13:00:00Z')
        self.assertEqual(status, 400)

    def test_unauthorized_and_every_write_method_denied(self):
        self.assertEqual(self.service.handle('GET', '/v2/entities', {}, None)[0], 401)
        for method in ('POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'):
            self.assertEqual(self.service.handle(method, '/v2/entities', {}, 'codex-cloud')[0], 405)
        for route in ('/api/services/climate/turn_on', '/v2/proxy', '/v2/deploy', '/v2/files/../../secrets.yaml'):
            self.assertEqual(self.get(route)[0], 404)
        self.assertNotIn('climate.stove', json.dumps(self.audit.rows))

    def test_strict_query_and_pagination(self):
        for query in ({'limit': '0'}, {'limit': '201'}, {'offset': '-1'}, {'url': 'https://example.invalid'}):
            self.assertEqual(self.get('/v2/entities', **query)[0], 400)
        self.assertEqual(self.service.handle('GET', '/v2/entities', {'limit': ['1', '2']}, 'codex-cloud')[0], 400)

    def test_capability_failure_is_not_simulated_success(self):
        self.source.reader.registry = lambda _: (_ for _ in ()).throw(SourceUnavailable('permission'))
        status, result = self.get('/v2/registry', kind='devices')
        self.assertEqual(status, 503)
        self.assertNotIn('data', result)

    def test_rate_limit_and_bounded_response(self):
        for _ in range(30):
            self.assertEqual(self.get('/v2/capabilities')[0], 200)
        self.assertEqual(self.get('/v2/capabilities')[0], 429)
        self.service.rate.events.clear()
        with patch.object(self.service, 'read', return_value={'large': 'x' * (1024 * 1024)}):
            self.assertEqual(self.get('/v2/entities')[0], 413)

    def test_config_secrets_and_references(self):
        (self.root / 'secrets.yaml').write_text('stove_password: private-literal-value\n')
        (self.root / 'scripts.yaml').write_text('warm:\n  sequence:\n    - action: test.action\n      data:\n        credential: !secret stove_password\n        message: private-literal-value\n        accessToken: another-private-value\n        endpoint: https://example.invalid/secret\n')
        result = ConfigReader(self.root, Privacy()).snapshot()
        text = json.dumps(result)
        for value in ('private-literal-value', 'another-private-value', 'https://example.invalid/secret'):
            self.assertNotIn(value, text)
        self.assertEqual(parse(b'value: !secret stove_password'), {'value': {'!secret': 'stove_password'}})
        self.assertNotIn('secrets.yaml', [x['path'] for x in result['files']])

    def test_inline_alarm_codes_and_authentication_fields_are_redacted(self):
        value = Privacy().clean({'data': {'code': '1234', 'pin': '5678', 'key': 'short-key', 'auth': 'basic-value'}, 'temperature': 21})
        self.assertEqual(value['data'], {name: '[redacted]' for name in ('code', 'pin', 'key', 'auth')})
        self.assertEqual(value['temperature'], 21)

    def test_selected_includes_packages_and_blueprints(self):
        (self.root / 'configuration.yaml').write_text('automation extra: !include custom_schedule.yaml\nhttp:\n  password: never-export\nhomeassistant:\n  packages: !include_dir_named packages\n')
        (self.root / 'custom_schedule.yaml').write_text('- alias: Stove\n  actions: []\n')
        (self.root / 'packages').mkdir()
        (self.root / 'packages/heating.yaml').write_text('automation:\n  - alias: Heating\n    actions: []\n')
        (self.root / 'blueprints').mkdir()
        (self.root / 'blueprints/stove.yaml').write_text('blueprint:\n  name: Heating\n  domain: automation\n  input: {}\nactions: !input selected_actions\n')
        result = ConfigReader(self.root, Privacy()).snapshot()
        blueprint = next((x for x in result['files'] if x['path'] == 'blueprints/stove.yaml'))
        self.assertEqual(blueprint['definition']['actions'], {'!input': 'selected_actions'})
        self.assertIn('custom_schedule.yaml', [x['path'] for x in result['files']])
        self.assertIn('packages/heating.yaml', [x['path'] for x in result['files']])
        self.assertNotIn('never-export', json.dumps(result))

    def test_symlink_traversal_duplicate_alias_depth_and_size_refused(self):
        for raw in (b'a: 1\na: 2\n', b'a: &x [1]\nb: *x\n', ('a: ' + '[' * 40 + '0' + ']' * 40).encode()):
            with self.assertRaises((ValueError, ConfigError)):
                parse(raw)
        (self.root / 'scripts.yaml').unlink()
        (self.root / 'scripts.yaml').symlink_to('/etc/passwd')
        with self.assertRaises((OSError, ConfigError)):
            ConfigReader(self.root, Privacy()).snapshot()
        for path in ('../etc/passwd', '/etc/passwd', '.storage/core.config_entries'):
            with self.assertRaises(ConfigError):
                ordinary(self.root, path)

    def test_http_boundary_uses_bearer_not_identity_header(self):
        auth = GatewayCredentials([{'identity': 'codex-cloud', 'token': CLIENT}])
        server = GatewayHTTPServer(('127.0.0.1', 0), handler_factory(self.service, 'X-Gateway-Identity', auth))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:

            def request(headers, method='GET', path='/v2/entities'):
                connection = HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                connection.request(method, path, headers=headers)
                response = connection.getresponse()
                body = response.read()
                connection.close()
                return (response.status, body)
            self.assertEqual(request({'X-Gateway-Identity': 'codex-cloud'})[0], 401)
            headers = {'Authorization': 'Bearer ' + CLIENT}
            status, body = request(headers)
            self.assertEqual(status, 200)
            self.assertNotIn(LOCAL.encode(), body)
            self.assertEqual(request(headers, 'POST')[0], 405)
            self.assertEqual(request(headers, path='/v2/entities?limit=1&limit=2')[0], 400)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_runtime_approval_and_credential_environment(self):
        for gate in ('read_approved', 'acl_reviewed'):
            with self.assertRaises(ValueError):
                options_checked({**OPTIONS, gate: False})
        env, fd = prepare(OPTIONS, LOCAL)
        try:
            self.assertNotIn('SUPERVISOR_TOKEN', env)
            self.assertEqual(os.read(fd, 4096).decode(), LOCAL)
        finally:
            os.close(fd)
        env, fd = prepare(OPTIONS, LOCAL, offline=True)
        self.assertIsNone(fd)
        self.assertNotIn('HA_GATEWAY_TOKEN_FD', env)

class TransportTests(unittest.TestCase):

    def test_fixed_http_destinations_methods_and_history_encoding(self):
        calls = []

        class Response:
            status = 200

            def read(self, _):
                return b'[]'

        class Connection:

            def __init__(self, *args, **kwargs):
                calls.append(args)

            def request(self, *args, **kwargs):
                calls.append(args)

            def getresponse(self):
                return Response()

            def close(self):
                pass
        with patch('diagnostic_real.reader.http.client.HTTPConnection', Connection):
            reader = CoreReader(LOCAL)
            reader.states()
            reader.history('climate.stove', '2026-11-10T12:00:00Z', '2026-11-10T13:00:00Z')
            with self.assertRaises(ValueError):
                reader.history('../services', 'x', 'y')
        self.assertEqual(calls[0], ('supervisor', 80))
        self.assertEqual(calls[1], ('GET', '/core/api/states'))
        self.assertTrue(calls[3][1].startswith('/core/api/history/period/'))

    def test_only_named_websocket_read_commands_constructible(self):
        commands = []

        class WS:

            def __init__(self, *_):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def send(self, value):
                commands.append(value)

            def receive(self):
                return {'id': 1, 'type': 'result', 'success': True, 'result': []}
        reader = CoreReader(LOCAL, socket_factory=WS)
        reader.registry('devices')
        reader.traces('automation', 'stove')
        reader.traces('script', 'warm', 'run-1')
        self.assertEqual([x['type'] for x in commands], ['config/device_registry/list', 'trace/list', 'trace/get'])
        for args in [('services', 'x'), ('automation', '../secrets')]:
            with self.assertRaises(ValueError):
                reader.traces(*args)
        with self.assertRaises(ValueError):
            reader.registry('call_service')

    def test_websocket_upgrade_buffered_auth_and_masked_messages(self):
        sent = []

        class Sock:

            def sendall(self, data):
                sent.append(data)

            def settimeout(self, _):
                pass

        class Connection:
            sock = Sock()
            closed = False

            def __init__(self, *_, **kwargs):
                pass

            def request(self, method, path, headers):
                self.key = headers['Sec-WebSocket-Key']
                self.assertion = (method, path)

            def getresponse(self):
                connection = self

                def frame(value):
                    data = json.dumps(value).encode()
                    return bytes([129, len(data)]) + data

                class Response:
                    status = 101
                    fp = io.BytesIO(frame({'type': 'auth_required'}) + frame({'type': 'auth_ok'}))

                    def getheader(self, name, default=None):
                        if name == 'Upgrade':
                            return 'websocket'
                        if name == 'Sec-WebSocket-Accept':
                            return base64.b64encode(hashlib.sha1((connection.key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                        return default
                return Response()

            def close(self):
                self.closed = True
        with patch('diagnostic_real.reader.http.client.HTTPConnection', Connection):
            with ReadSocket(LOCAL) as ws:
                self.assertEqual(ws.connection.assertion, ('GET', '/core/websocket'))
                frame = sent[0]
                self.assertTrue(frame[1] & 128)
                size = frame[1] & 127
                mask = frame[2:6]
                decoded = bytes((value ^ mask[index % 4] for index, value in enumerate(frame[6:6 + size])))
                self.assertEqual(json.loads(decoded), {'type': 'auth', 'access_token': LOCAL})
            self.assertTrue(ws.connection.closed)

    def test_websocket_oversize_rejected_before_body_read(self):
        ws = ReadSocket(LOCAL)
        chunks = iter([bytes([129, 127]), struct.pack('!Q', MAX_BYTES + 1)])
        ws.exact = lambda _: next(chunks)
        with self.assertRaises(SourceUnavailable):
            ws.receive()

    def test_websocket_fragment_ping_and_masked_client_frame(self):
        ws = ReadSocket(LOCAL)
        chunks = iter([b'\x01\x05', b'{"a":', b'\x89\x01', b'p', b'\x80\x02', b'1}'])
        ws.exact = lambda _: next(chunks)
        frames = []
        ws.frame = lambda opcode, data: frames.append((opcode, data))
        self.assertEqual(ws.receive(), {'a': 1})
        self.assertEqual(frames, [(10, b'p')])
if __name__ == '__main__':
    unittest.main()
