"""Home Assistant OS lifecycle. Dormant defaults; no enrollment during validation."""

from __future__ import annotations

import json
import os
import re
import resource
import signal
import subprocess
import threading
import time
from pathlib import Path

from gateway.audit import load_or_create_salt
from gateway.bounded_audit import BoundedAuditLogger
from gateway.data_source import FixtureDataSource
from gateway.network_auth import GatewayCredentials
from gateway.policy import GatewayPolicy
from gateway.server import GatewayHTTPServer, handler_factory
from gateway.service import GatewayService


ROOT = Path(__file__).resolve().parents[1]
OPTION_KEYS = {"mode", "activation_approved", "network_enabled", "entities", "clients",
               "redact_terms", "tailscale_auth_key"}


def enforce_installation_profile(options: dict, path: Path) -> None:
    """The first Green installation cannot be promoted through UI options."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024:
        raise ValueError("invalid installation profile")
    profile = json.loads(path.read_text())
    if (profile != {"version": 1, "simulation_only": True}
            or type(profile.get("version")) is not int or profile.get("simulation_only") is not True):
        raise ValueError("only the reviewed simulation installation profile is supported")
    if (options["mode"] != "simulation" or options["activation_approved"]
            or options["network_enabled"] or options["tailscale_auth_key"] or options["entities"]):
        raise ValueError("this installation is locked to simulation without Core or Tailscale")


def validate_options(options: dict) -> None:
    if not isinstance(options, dict) or set(options) != OPTION_KEYS:
        raise ValueError("invalid application option fields")
    if options["mode"] not in {"simulation", "real"}:
        raise ValueError("invalid application mode")
    for name in ("activation_approved", "network_enabled"):
        if type(options[name]) is not bool:
            raise ValueError("invalid activation flag")
    if (options["mode"] == "real" or options["network_enabled"]) and not options["activation_approved"]:
        raise ValueError("explicit local activation approval is required")
    if not isinstance(options["tailscale_auth_key"], str):
        raise ValueError("invalid enrollment credential")
    if options["network_enabled"] and not options["clients"]:
        raise ValueError("network exposure requires gateway credentials")
    if not isinstance(options["entities"], list) or len(options["entities"]) > 16:
        raise ValueError("select at most 16 entities")
    if not isinstance(options["clients"], list) or len(options["clients"]) > 4:
        raise ValueError("configure at most 4 clients")
    if options["clients"]:
        GatewayCredentials(options["clients"])


def make_policy(options: dict, path: Path) -> GatewayPolicy:
    if options["mode"] == "simulation":
        raw = json.loads((ROOT / "gateway/policy.example.json").read_text())
    else:
        if not options["entities"] or not options["clients"]:
            raise ValueError("real mode requires selected entities and gateway clients")
        selected = {}
        for item in options["entities"]:
            if not isinstance(item, dict) or set(item) != {"entity_id", "attributes"}:
                raise ValueError("invalid entity selection")
            if item["entity_id"] in selected:
                raise ValueError("duplicate entity selection")
            selected[item["entity_id"]] = {"attributes": item["attributes"]}
        raw = {"version": 1, "entities": selected, "automation_allowlist": [],
               "log_components": [], "diagnostic_fields": ["fixture_mode", "gateway_version"],
               "history": {"max_hours": 6, "max_points": 100}, "rate_limit_per_minute": 12}
    if options["clients"]:
        identities = [item["identity"] for item in options["clients"]]
        if len(identities) != len(set(identities)):
            raise ValueError("duplicate gateway identity")
        raw["identities"] = {identity: {"scopes": ["entities:read", "history:read",
                                                   "diagnostics:read"]} for identity in identities}
    raw["redact_terms"] = options["redact_terms"]
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(raw, stream)
    return GatewayPolicy.load(path)


class Tailnet:
    """Own userspace daemon only. Never touches the existing Tailscale app."""

    def __init__(self, data: Path, runtime: Path = Path("/run"), cancelled=None):
        self.data = data
        self.runtime = runtime
        self.socket = runtime / "ha-gateway-tailscale.sock"
        self.cancelled = cancelled or threading.Event()
        self.daemon = None
        # The Supervisor token and application credentials must not reach child processes.
        self.env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                    "HOME": str(data), "GOMEMLIMIT": "96MiB", "GOGC": "50",
                    "GOMAXPROCS": "1",
                    "TS_NO_LOGS_NO_SUPPORT": "true"}

    def cli(self, *args):
        process = subprocess.Popen(["tailscale", "--socket=" + str(self.socket), *args],
                                   env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 45
        while process.poll() is None:
            if self.cancelled.wait(0.1) or time.monotonic() >= deadline:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                raise RuntimeError("tailnet setup cancelled or timed out")
        if process.returncode != 0:
            raise RuntimeError("tailnet command failed")

    def start(self, auth_key: str):
        if not auth_key and not (self.data / "tailscale.state").is_file():
            raise ValueError("local enrollment key or existing node state is required")
        self.daemon = subprocess.Popen([
            "tailscaled", "--tun=userspace-networking", "--state=" + str(self.data / "tailscale.state"),
            "--socket=" + str(self.socket)], env=self.env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while not self.socket.exists():
            if (self.daemon.poll() is not None or time.monotonic() >= deadline
                    or self.cancelled.is_set()):
                raise RuntimeError("tailnet daemon unavailable")
            time.sleep(0.1)
        arguments = ["up", "--hostname=ha-green-read", "--accept-dns=false",
                     "--accept-routes=false", "--ssh=false", "--advertise-tags=tag:ha-read-gateway",
                     "--timeout=30s"]
        key_path = self.runtime / "ha-gateway-enrollment"
        try:
            if auth_key:
                if not re.fullmatch(r"tskey-auth-[A-Za-z0-9_-]+", auth_key):
                    raise ValueError("invalid local Tailscale enrollment key")
                descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w") as stream:
                    stream.write(auth_key)
                arguments.append("--auth-key=file:" + str(key_path))
            self.cli(*arguments)
            self.cli("serve", "reset")
            self.cli("serve", "--bg", "--https=443", "http://127.0.0.1:8765")
        finally:
            key_path.unlink(missing_ok=True)

    def stop(self):
        if self.daemon is not None and self.daemon.poll() is None:
            self.daemon.terminate()
            try:
                self.daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
                self.daemon.wait(timeout=2)


def main() -> int:
    # Discard Supervisor credentials before parsing any untrusted runtime options.
    # The simulation package requests no Core permission and never retains a token.
    os.environ.pop("SUPERVISOR_TOKEN", None)
    os.environ.pop("HASSIO_TOKEN", None)
    os.umask(0o077)
    os.nice(10)
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    options_path = Path("/data/options.json")
    if options_path.stat().st_size > 64 * 1024:
        raise ValueError("application options exceed size limit")
    options = json.loads(options_path.read_text())
    validate_options(options)
    enforce_installation_profile(options, ROOT / "installation-profile.json")
    data = Path("/data/gateway")
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    policy = make_policy(options, data / "policy.local.json")
    source = FixtureDataSource(ROOT / "gateway/fixtures/simulated.json")
    credentials = GatewayCredentials(options["clients"]) if options["clients"] else lambda headers: None
    audit = BoundedAuditLogger(data / "audit.jsonl", load_or_create_salt(data / "audit.salt"))
    service = GatewayService(policy, source, audit)
    identity = next(name for name, scopes in policy.identities.items() if "entities:read" in scopes)
    status, result = service.handle("GET", "/v1/entities", {}, identity)
    if status != 200 or result["data"]["count"] != 3:
        raise RuntimeError("simulation self-test failed")
    print("Simulation self-test: 3 fixture entities; upstream reads disabled", flush=True)
    server = GatewayHTTPServer(("127.0.0.1", 8765), handler_factory(service, "unused", credentials))
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        print("Gateway ready: simulation; Core denied; Tailscale disabled; deployment disabled", flush=True)
        while not stopped.wait(1):
            if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss > 128 * 1024:
                raise RuntimeError("gateway memory budget exceeded")
    except RuntimeError:
        if not stopped.is_set():
            raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # No raw upstream, configuration values, credentials or enrollment URLs in logs.
        print("Gateway stopped: local configuration or dependency failure", flush=True)
        raise SystemExit(1) from None
