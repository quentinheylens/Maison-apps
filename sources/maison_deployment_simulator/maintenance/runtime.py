"""Separate dormant HA OS apps. No real transport or production executor."""

import json
import os
import resource
import signal
import sys
import tempfile
import threading
from datetime import timedelta
from pathlib import Path

from gateway.audit import load_or_create_salt
from gateway.bounded_audit import BoundedAuditLogger
from maintenance.diagnostics import CoreReadAdapter, DiagnosticService
from maintenance.evidence import EvidenceVault
from maintenance.fixtures import policy, SimulatedHATransport
from maintenance.plan import FixtureGit, SimulationAuthority, prepare_plan
from maintenance.safe_fs import Sandbox, Tree, canonical
from maintenance.transactions import TransactionAgent
from maintenance.network_lock import assert_network_locked


def diagnostic_selftest():
    with tempfile.TemporaryDirectory(prefix="maison-diagnostic-") as folder:
        directory = Path(folder)
        rules, transport = policy(), SimulatedHATransport()
        audit = BoundedAuditLogger(directory / "audit.jsonl", load_or_create_salt(directory / "audit.salt"), 65536)
        service = DiagnosticService(rules, CoreReadAdapter(rules, transport), audit,
                                    evidence=EvidenceVault([], rules))
        status, result = service.handle("GET", "/v2/entities", {}, "diagnostic-simulator")
        assert status == 200 and result["data"]["count"] == 4
        query = {"entity_id": ["sensor.technical_temperature"], "start": [(transport.now - timedelta(hours=1)).isoformat()],
                 "end": [transport.now.isoformat()], "limit": ["50"]}
        status, result = service.handle("GET", "/v2/history", query, "diagnostic-simulator")
        assert status == 200 and result["data"]["count"] == 6
        assert service.handle("POST", "/v2/entities", {}, "diagnostic-simulator")[0] == 405
        assert service.handle("GET", "/v2/entities", {}, None)[0] == 401
        return {"entities": 4, "history_points": 6, "write_refused": True, "anonymous_refused": True}


def deployment_selftest():
    with tempfile.TemporaryDirectory(prefix="maison-deploy-") as folder:
        original = {"automations.yaml": b"[]\n", "scripts.yaml": b"{}\n"}
        repository = FixtureGit({"automations.yaml": b"- id: simulated\n  alias: simulated\n", "scripts.yaml": b"{}\n"})
        sandbox = Sandbox.create(Path(folder) / "workspace", original)
        try:
            authority = SimulationAuthority()
            plan = prepare_plan(repository, repository.commit, sandbox, list(original), rollback="manual")
            approval = authority.approve(plan, human_confirmed=True)
            agent = TransactionAgent(sandbox, authority)
            assert agent.apply(repository, plan, approval)["phase"] == "committed"
            assert agent.recover(manual_approval=True) == "rolled_back"
            assert all(sandbox.tree.read("live/" + name) == data for name, data in original.items())
            return {"simulated_files": 2, "commit_verified": True, "backup_verified": True, "rollback_verified": True}
        finally:
            sandbox.tree.close()


def main():
    assert_network_locked()
    os.umask(0o077)
    os.nice(10)
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    role = sys.argv[1]
    offline = sys.argv[2:] == ["--self-test-only"]
    if role not in {"diagnostic", "deployment"} or sys.argv[2:] not in ([], ["--self-test-only"]):
        raise ValueError("unsupported simulation role")
    result = diagnostic_selftest() if role == "diagnostic" else deployment_selftest()
    report = {"role": role, "version": "0.6.1" if role == "diagnostic" else "0.1.1",
              "simulation": True, "listener_started": False, "vpn_started": False, "writes_enabled": False,
              "network_syscalls_denied": True,
              "runtime_uid": os.geteuid(), "runtime_gid": os.getegid(),
              "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
              "cpu_seconds": round(resource.getrusage(resource.RUSAGE_SELF).ru_utime + resource.getrusage(resource.RUSAGE_SELF).ru_stime, 4),
              "credential_environment_clean": all(name not in os.environ and (name + "=").encode() not in Path("/proc/self/environ").read_bytes()
                  for name in ("SUPERVISOR_TOKEN", "HASSIO_TOKEN", "MAISON_GATEWAY_TOKEN", "TS_AUTHKEY")),
              "checks": result}
    print(json.dumps(report), flush=True)
    if offline:
        return 0
    # No server or receiver is installed. Normal app startup idles after testing
    # and creates only a private local health file, never a network listener.
    folder = "diagnostic-v6" if role == "diagnostic" else "deploy-simulation"
    tree = Tree("/tmp")  # Heartbeat on tmpfs, no periodic writes to Green flash.
    tree.mkdir(folder)
    tree.write(folder + "/health.json", canonical(report))
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    try:
        while not stopped.wait(5):
            if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss > 96 * 1024:
                raise RuntimeError("simulation memory budget exceeded")
            tree.write(folder + "/health.json", canonical(report))
    finally:
        tree.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("Maintenance simulation stopped: local validation failed", flush=True)
        raise SystemExit(1) from None
