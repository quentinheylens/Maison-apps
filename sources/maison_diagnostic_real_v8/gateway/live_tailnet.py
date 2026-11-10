"""Dedicated userspace node; reset persisted exposure before the daemon can resume."""

import json
import os
from pathlib import Path

from gateway.green_app import Tailnet


def clear_persisted_serve(state: Path) -> None:
    """Pinned Tailscale 1.104.4 FileStore is a JSON string map (_serve/<profile>)."""
    if not state.exists() and not state.is_symlink():
        return
    if state.is_symlink() or not state.is_file():
        raise ValueError("node state must be a private regular file")
    if state.stat().st_mode & 0o077 or state.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("node state permissions or size invalid")
    raw = json.loads(state.read_text())
    if not isinstance(raw, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in raw.items()):
        raise ValueError("unsupported node state format; refuse network startup")
    cleaned = {key: value for key, value in raw.items() if not key.startswith("_serve")}
    if cleaned == raw:
        return
    temporary = state.with_name(state.name + ".safe-new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(cleaned, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, state)
    finally:
        temporary.unlink(missing_ok=True)


class DedicatedTailnet(Tailnet):
    def __init__(self, data: Path, runtime: Path = Path("/run"), cancelled=None):
        # In pinned tailscaled, absolute --state derives VarRoot only when its
        # parent is named 'tailscale'. This also persists HTTPS certificate cache.
        super().__init__(data / "tailscale", runtime=runtime, cancelled=cancelled)

    def start(self, auth_key: str):
        if self.data.is_symlink():
            raise ValueError("node directory must not be a symbolic link")
        self.data.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.data.stat().st_mode & 0o077:
            raise ValueError("node directory must be private")
        clear_persisted_serve(self.data / "tailscale.state")
        super().start(auth_key)

    def cli(self, *args):
        # Apply all safety preferences on this node, not any existing household node.
        if args and args[0] == "up":
            args = tuple("--hostname=ha-green-read-v5" if arg.startswith("--hostname=") else arg for arg in args)
            args += ("--advertise-exit-node=false", "--advertise-routes=", "--exit-node=")
        return super().cli(*args)

    def stop(self):
        # SIGTERM cancels CLI work. Discard saved Serve on the next boot before any reconnect.
        if self.daemon is None:
            return
        super().stop()
        clear_persisted_serve(self.data / "tailscale.state")
