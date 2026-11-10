"""Bounded HMAC audit with descriptor-relative I/O, including every parent."""

import hashlib
import hmac
import json
import secrets
import threading
from datetime import datetime, timezone

from maintenance.safe_fs import canonical, digest


class PrivateAudit:
    def __init__(self, tree, maximum=65536):
        self.tree, self.maximum = tree, maximum
        self.lock = threading.Lock()
        try:
            self.salt = tree.read("state/audit.salt")
        except FileNotFoundError:
            self.salt = secrets.token_bytes(32)
            tree.write("state/audit.salt", self.salt, new=True)
        if len(self.salt) != 32:
            raise ValueError("invalid audit authority")
        self._load("state/audit.jsonl")
        self._load("state/audit.previous")

    def _load(self, path):
        try:
            raw = self.tree.read(path)
        except FileNotFoundError:
            return b"", "0" * 64
        if len(raw) > self.maximum:
            raise ValueError("audit size exceeded")
        previous = "0" * 64
        for line in raw.splitlines():
            event = json.loads(line)
            signature = event.pop("event_hash")
            if event.get("previous_event_hash") != previous:
                raise ValueError("audit chain broken")
            expected = hmac.new(self.salt, canonical(event), hashlib.sha256).hexdigest()
            if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
                raise ValueError("audit signature invalid")
            previous = signature
        return raw, previous

    def write(self, *, request_id, identity, method, route, status, outcome):
        with self.lock:
            raw, previous = self._load("state/audit.jsonl")
            if len(raw) + 1024 > self.maximum:
                self.tree.write("state/audit.previous", raw)
                original = raw
                raw, previous = b"", "0" * 64
            else:
                original = raw
            event = {"request_id": request_id, "timestamp": datetime.now(timezone.utc).isoformat(),
                     "identity_ref": hmac.new(self.salt, identity.encode(), hashlib.sha256).hexdigest()[:16],
                     "method": method, "route": route, "status": status, "outcome": outcome,
                     "previous_event_hash": previous}
            event["event_hash"] = hmac.new(self.salt, canonical(event), hashlib.sha256).hexdigest()
            result = raw + json.dumps(event, sort_keys=True).encode() + b"\n"
            if len(result) > self.maximum:
                raise ValueError("audit record exceeded bound")
            self.tree.write("state/audit.jsonl", result,
                            expected=digest(original) if original else None, new=not bool(original))
