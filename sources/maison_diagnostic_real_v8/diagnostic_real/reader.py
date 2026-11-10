"""Fixed Core endpoints and a minimal bounded, read-command-only WebSocket client."""
import base64
import hashlib
import http.client
import json
import os
import re
import socket
import struct
import threading
import time
from datetime import datetime
from urllib.parse import quote, urlencode
from gateway.real_source import SourceUnavailable

ENTITY = re.compile(r'[a-z][a-z0-9_]*\.[a-z0-9_]{1,200}')
IDENTIFIER = re.compile(r'[A-Za-z0-9_-]{1,128}')
MAX_BYTES = 4 * 1024 * 1024

def entity_id(value):
    if not isinstance(value, str) or not ENTITY.fullmatch(value):
        raise ValueError('invalid_entity')
    return value

def window(start, end):
    try:
        first, last = [datetime.fromisoformat(x.replace('Z', '+00:00')) for x in (start, end)]
        if first.tzinfo is None or last.tzinfo is None or not 0 < (last-first).total_seconds() <= 86400:
            raise ValueError()
        return first, last
    except (TypeError, AttributeError, ValueError):
        raise ValueError('invalid_history_window') from None

class ReadSocket:
    """Only internal local Core transport. No redirect, proxy, URL or caller headers."""
    def __init__(self, token):
        self.token = token
        self.connection = None

    def __enter__(self):
        self.connection = http.client.HTTPConnection('supervisor', 80, timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        self.connection.request('GET', '/core/websocket', headers={
            'Upgrade': 'websocket', 'Connection': 'Upgrade', 'Sec-WebSocket-Version': '13',
            'Sec-WebSocket-Key': key})
        response = self.connection.getresponse()
        expected = base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        if (response.status != 101 or response.getheader('Sec-WebSocket-Accept') != expected
                or response.getheader('Upgrade', '').lower() != 'websocket'):
            self.connection.close()
            raise SourceUnavailable('websocket_unavailable')
        self.sock = self.connection.sock
        self.stream = response.fp
        try:
            if self.receive().get('type') != 'auth_required':
                raise SourceUnavailable('unexpected_authentication')
            self.send({'type': 'auth', 'access_token': self.token})
            if self.receive().get('type') != 'auth_ok':
                raise SourceUnavailable('local_authentication_failed')
            return self
        except Exception:
            self.connection.close()
            raise

    def __exit__(self, *_):
        self.connection.close()

    def exact(self, count):
        data = bytearray()
        while len(data) < count:
            self.sock.settimeout(max(0.1, self.deadline-time.monotonic()))
            if time.monotonic() > self.deadline:
                raise SourceUnavailable("websocket_deadline_exceeded")
            part = self.stream.read(count-len(data))
            if not part:
                raise SourceUnavailable('websocket_closed')
            data.extend(part)
        return bytes(data)

    def frame(self, opcode, data):
        mask = os.urandom(4)
        length = len(data)
        prefix = bytes([0x80 | opcode])
        if length < 126: prefix += bytes([0x80 | length])
        elif length <= 65535: prefix += bytes([0x80 | 126]) + struct.pack('!H', length)
        else: prefix += bytes([0x80 | 127]) + struct.pack('!Q', length)
        self.sock.sendall(prefix + mask + bytes(x ^ mask[i % 4] for i, x in enumerate(data)))

    def send(self, value):
        self.frame(1, json.dumps(value, allow_nan=False).encode())

    def receive(self):
        self.deadline = time.monotonic() + 10
        message = bytearray()
        started = False
        for _ in range(1024):
            first, second = self.exact(2)
            opcode, final = first & 15, bool(first & 128)
            if first & 112 or second & 128:
                raise SourceUnavailable('invalid_websocket_frame')
            size = second & 127
            if size == 126: size = struct.unpack('!H', self.exact(2))[0]
            elif size == 127: size = struct.unpack('!Q', self.exact(8))[0]
            if size > MAX_BYTES - len(message):
                raise SourceUnavailable('websocket_response_too_large')
            if opcode >= 8 and (not final or size > 125):
                raise SourceUnavailable('invalid_control_frame')
            if opcode == 8:
                raise SourceUnavailable('websocket_closed')
            data = self.exact(size)
            if opcode == 9:
                self.frame(10, data)
                continue
            if opcode == 10: continue
            if (opcode == 1 and started) or (opcode == 0 and not started) or opcode not in {0, 1}:
                raise SourceUnavailable('invalid_websocket_message')
            started = True
            message.extend(data)
            if final:
                result = json.loads(message)
                if not isinstance(result, dict):
                    raise SourceUnavailable('invalid_websocket_result')
                return result
        raise SourceUnavailable('websocket_frame_budget_exceeded')

class CoreReader:
    def __init__(self, token, socket_factory=ReadSocket):
        if not token or any(x in token for x in '\r\n'):
            raise ValueError('invalid_local_credential')
        self._token = token
        self.socket_factory = socket_factory
        self.lock = threading.Lock()

    def _get(self, path):
        connection = http.client.HTTPConnection('supervisor', 80, timeout=8)
        try:
            connection.request('GET', path, headers={'Authorization': 'Bearer '+self._token,
                               'Accept': 'application/json', 'Accept-Encoding': 'identity'})
            response = connection.getresponse()
            if response.status != 200:
                raise SourceUnavailable('core_read_unavailable')
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise SourceUnavailable('core_response_too_large')
            return json.loads(raw)
        except (OSError, ValueError, http.client.HTTPException):
            raise SourceUnavailable('core_read_unavailable') from None
        finally:
            connection.close()

    def states(self):
        return self._get('/core/api/states')

    def history(self, entity, start, end):
        entity_id(entity); window(start, end)
        return self._get('/core/api/history/period/'+quote(start, safe='')+'?'+urlencode({
            'filter_entity_id': entity, 'end_time': end, 'minimal_response': 'true', 'no_attributes': 'true'}))

    def _read_command(self, command):
        try:
            with self.lock, self.socket_factory(self._token) as ws:
                ws.send({'id': 1, **command})
                response = ws.receive()
                if response.get('id') != 1 or response.get('type') != 'result' or response.get('success') is not True:
                    raise SourceUnavailable('core_read_capability_unavailable')
                return response.get('result')
        except (OSError, ValueError, http.client.HTTPException):
            raise SourceUnavailable('core_read_capability_unavailable') from None

    def registry(self, kind):
        commands = {'entities': 'config/entity_registry/list', 'devices': 'config/device_registry/list',
                    'areas': 'config/area_registry/list'}
        if kind not in commands:
            raise ValueError('invalid_registry')
        return self._read_command({'type': commands[kind]})

    def traces(self, domain, item_id, run_id=None):
        if domain not in {'automation', 'script'} or not isinstance(item_id, str) or not IDENTIFIER.fullmatch(item_id):
            raise ValueError('invalid_trace_target')
        command = {'type': 'trace/list', 'domain': domain, 'item_id': item_id}
        if run_id is not None:
            if not isinstance(run_id, str) or not IDENTIFIER.fullmatch(run_id):
                raise ValueError('invalid_run_id')
            command.update(type='trace/get', run_id=run_id)
        return self._read_command(command)
