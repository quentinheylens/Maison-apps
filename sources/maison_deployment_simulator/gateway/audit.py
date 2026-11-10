"""Privacy-preserving append-only audit events."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_or_create_salt(path: Path) -> bytes:
    path = path.expanduser()
    if path.is_symlink():
        raise ValueError("audit salt must not be a symbolic link")
    if path.exists():
        if not path.is_file() or path.stat().st_mode & 0o077:
            raise ValueError("audit salt must be a regular file with 0600 permissions")
        value = path.read_bytes()
        if len(value) < 32:
            raise ValueError("audit salt must contain at least 32 bytes")
        return value
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_bytes(32)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, value)
    finally:
        os.close(descriptor)
    return value


class AuditLogger:
    def __init__(self, path: Path, salt: bytes):
        if len(salt) < 16:
            raise ValueError("audit salt must contain at least 16 bytes")
        self.path = path
        self.salt = salt
        self.lock = threading.Lock()
        self.previous_hash = "0" * 64
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
                raise ValueError("audit log must be a regular file with 0600 permissions")
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
            previous_hash = self.previous_hash
            for line in lines:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError("audit log contains invalid JSON") from exc
                if not isinstance(event, dict):
                    raise ValueError("audit log event must be an object")
                event_hash = event.pop("event_hash", None)
                if event.get("previous_event_hash") != previous_hash:
                    raise ValueError("audit log hash chain is broken")
                canonical = json.dumps(
                    event,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                expected = hmac.new(
                    self.salt,
                    canonical.encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                if not isinstance(event_hash, str) or not hmac.compare_digest(event_hash, expected):
                    raise ValueError("audit log event hash is invalid")
                previous_hash = event_hash
            self.previous_hash = previous_hash

    def reference(self, value: str | None) -> str:
        if not value:
            return "anonymous"
        return hmac.new(self.salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def write(
        self,
        *,
        request_id: str,
        identity: str | None,
        method: str,
        route: str,
        status: int,
        outcome: str,
    ) -> None:
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            event: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "request_id": request_id,
                "identity_ref": self.reference(identity),
                "method": method,
                "route": route,
                "status": status,
                "outcome": outcome,
                "previous_event_hash": self.previous_hash,
            }
            canonical = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            event_hash = hmac.new(self.salt, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
            event["event_hash"] = event_hash
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags, 0o600)
            try:
                file_mode = os.fstat(descriptor).st_mode
                if not stat.S_ISREG(file_mode) or file_mode & 0o077:
                    raise ValueError("audit log must remain a regular file with 0600 permissions")
                os.write(descriptor, (json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
            finally:
                os.close(descriptor)
            self.previous_hash = event_hash
