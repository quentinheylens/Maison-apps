"""Local bounded heartbeat probe; only the privilege-dropping bootstrap may run it."""

import json
import os
import stat
import sys
import time
from pathlib import Path

from gateway.simulation_entrypoint import clean_environment
from maintenance.network_lock import lock_network, assert_network_locked
from maintenance.safe_fs import Tree


def main():
    lock_network()
    assert_network_locked()
    if sys.argv[1:] not in (["diagnostic"], ["deployment"]):
        raise ValueError("invalid healthcheck role")
    role = sys.argv[1]
    expected = clean_environment()
    # CPython may add this fixed locale during its startup coercion.
    if "LC_CTYPE" in os.environ:
        expected["LC_CTYPE"] = "C.UTF-8"
    if dict(os.environ) != expected or os.getgroups() or os.geteuid() != 65532 or os.getegid() != 65532:
        raise ValueError("unsafe healthcheck identity or environment")
    fields = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if any(int(fields[key].strip(), 16) for key in ("CapEff", "CapPrm", "CapInh", "CapAmb")):
        raise ValueError("healthcheck capabilities forbidden")
    if fields["NoNewPrivs"].strip() != "1" or fields["Seccomp"].strip() != "2":
        raise ValueError("healthcheck sandbox missing")
    initial_keys = {item.split(b"=", 1)[0].decode() for item in Path("/proc/self/environ").read_bytes().split(b"\0") if item}
    if not initial_keys <= set(expected):
        raise ValueError("inherited healthcheck environment forbidden")
    folder = "diagnostic-v6" if role == "diagnostic" else "deploy-simulation"
    tree = Tree("/tmp")
    try:
        parent, leaf = tree.parent(folder + "/health.json")
        try:
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096:
                    raise ValueError("unsafe health file")
                data = os.read(fd, 4097)
                if len(data) > 4096 or not 0 <= time.time() - info.st_mtime < 30:
                    raise ValueError("stale or oversized heartbeat")
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    finally:
        tree.close()
    report = json.loads(data)
    if (report.get("simulation") is not True or report.get("writes_enabled") is not False
            or report.get("listener_started") is not False or report.get("vpn_started") is not False
            or report.get("role") != role):
        raise ValueError("unsafe heartbeat")
    print(json.dumps({"healthy": True, "uid": os.geteuid(), "gid": os.getegid(),
                      "capabilities_zero": True, "credential_environment_clean": True,
                      "no_new_privileges": True, "network_syscalls_denied": True}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Simulation healthcheck refused", flush=True)
        raise SystemExit(1) from None
