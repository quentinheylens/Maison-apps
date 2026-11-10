"""Two bounded local audit segments; each segment has its own verified HMAC chain."""

import os
import threading
from pathlib import Path

from gateway.audit import AuditLogger


class BoundedAuditLogger(AuditLogger):
    def __init__(self, path: Path, salt: bytes, max_bytes: int = 1024 * 1024):
        self.rotation_lock = threading.Lock()
        self.max_bytes = max_bytes
        if path.exists() and path.stat().st_size > max_bytes:
            raise ValueError("audit log exceeds configured bound")
        previous = path.with_suffix(".previous")
        if previous.exists():
            if previous.stat().st_size > max_bytes:
                raise ValueError("audit archive exceeds configured bound")
            AuditLogger(previous, salt)
        super().__init__(path, salt)

    def write(self, **kwargs):
        with self.rotation_lock:
            if self.path.exists() and self.path.stat().st_size + 1024 > self.max_bytes:
                os.replace(self.path, self.path.with_suffix(".previous"))
                self.previous_hash = "0" * 64
            super().write(**kwargs)
