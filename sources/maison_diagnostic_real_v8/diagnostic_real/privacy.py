"""Bounded structural export, secret references preserved, credentials suppressed."""
import math
import re
from gateway.redaction import redact_text, compact_key

SENSITIVE = ('password', 'token', 'apikey', 'credential', 'privatekey', 'clientsecret',
             'authorization', 'cookie', 'webhook', 'secret', 'username')
OPAQUE = re.compile(r'(?<![a-zA-Z0-9])[A-Za-z0-9_+/=-]{40,}(?![a-zA-Z0-9])')
ASSIGNMENT = re.compile(r'(?i)\b(password|token|api[_-]?key|secret|authorization)\s*[:=]\s*[^\s,;]+')
EXACT_SENSITIVE = {'code', 'pin', 'key', 'auth', 'passphrase', 'login'}
BLOCKED = {'shell_command', 'rest_command', 'command_line', 'python_script', 'headers',
           'variables', 'response_variable', 'event_data', 'context', 'trigger_variables'}

class Privacy:
    def __init__(self, terms=()):
        self.terms = tuple(sorted({x for x in terms if isinstance(x, str) and len(x) >= 3}, key=len, reverse=True))

    def text(self, value):
        value = redact_text(value, self.terms)
        return OPAQUE.sub('[redacted-opaque]', ASSIGNMENT.sub('[redacted-assignment]', value))[:4096]

    def clean(self, value, depth=0):
        if depth > 32:
            return '[depth-limit]'
        if isinstance(value, dict):
            if set(value) == {'!secret'}:
                return {'!secret': self.text(str(value['!secret']))}
            result = {}
            for key, child in list(value.items())[:2000]:
                key = str(key)
                name = compact_key(key)
                safe_key = self.text(key)
                if len(key) > 256 or key in BLOCKED or name in EXACT_SENSITIVE or any(x in name for x in SENSITIVE):
                    result[safe_key] = '[redacted]'
                else:
                    result[safe_key] = self.clean(child, depth + 1)
            return result
        if isinstance(value, list):
            return [self.clean(x, depth + 1) for x in value[:2000]]
        if isinstance(value, str):
            return self.text(value)
        if value is None or type(value) in (bool, int):
            return value
        if type(value) is float and math.isfinite(value):
            return value
        return '[unsupported]'
