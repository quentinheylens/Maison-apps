"""Discard inherited credentials by exec before importing simulation runtime."""

import json
import os
import sys
from pathlib import Path

from gateway.simulation_entrypoint import clean_environment
from maintenance.safe_fs import Tree
from maintenance.network_lock import lock_network


def validate_options(options):
    if options != {"mode": "simulation", "network_enabled": False, "execution_enabled": False}:
        raise ValueError("only dormant simulation options are accepted")
    if options.get("network_enabled") is not False or options.get("execution_enabled") is not False:
        raise ValueError("strict false flags required")


def drop_privileges():
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(65532)
        os.setuid(65532)
    if os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("runtime must not retain root")


def main():
    args = sys.argv[1:]
    if args not in (["diagnostic"], ["deployment"], ["diagnostic", "--self-test-only"], ["deployment", "--self-test-only"]):
        raise ValueError("invalid simulation arguments")
    lock_network()
    tree = Tree("/data")
    try:
        validate_options(json.loads(tree.read("options.json")))
    finally:
        tree.close()
    profile = json.loads(Path("/app/installation-profile.json").read_text())
    if profile != {"role": args[0], "production_capable": False, "simulation": True} or profile.get("production_capable") is not False or profile.get("simulation") is not True:
        raise ValueError("installed profile does not permit production")
    drop_privileges()
    os.execve(sys.executable, [sys.executable, "-m", "maintenance.runtime", *args], clean_environment())


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Maintenance refused startup: simulation only", flush=True)
        raise SystemExit(1) from None
