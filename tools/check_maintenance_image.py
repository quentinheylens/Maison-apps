#!/usr/bin/env python3
"""Offline image tests, no listeners, no tailnet and synthetic credentials only."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def check(image):
    docker = ["docker", "--host=unix:///var/run/docker.sock"]
    with tempfile.TemporaryDirectory(prefix="maintenance-image-") as folder:
        path = Path(folder) / "options.json"
        original = {"mode": "simulation", "network_enabled": False, "execution_enabled": False}
        reports = []
        for options in (original, {**original, "mode": "real"},
                        {**original, "execution_enabled": True}, {**original, "network_enabled": True}):
            path.write_text(json.dumps(options))
            name = "maintenance-test-" + uuid.uuid4().hex[:12]
            command = docker + ["run", "--rm", "--name", name, "--network", "none", "--read-only",
                "--memory", "192m", "--cpus", "0.5", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
                "--mount", f"type=bind,src={path},dst=/data/options.json,readonly"]
            for credential in ("SUPERVISOR_TOKEN", "HASSIO_TOKEN", "MAISON_GATEWAY_TOKEN", "TS_AUTHKEY"):
                command += ["--env", credential + "=synthetic-only"]
            command += [image, "--self-test-only"]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            finally:
                subprocess.run(docker + ["rm", "--force", name], capture_output=True)
            if options == original:
                if result.returncode != 0:
                    raise RuntimeError("offline image selftest failed")
                report = json.loads(result.stdout.splitlines()[-1])
                assert report["simulation"] is True and report["credential_environment_clean"] is True
                assert report["runtime_uid"] == 65532 and report["runtime_gid"] == 65532
                assert report["network_syscalls_denied"] is True
                assert report["writes_enabled"] is False and report["listener_started"] is False and report["vpn_started"] is False
                reports.append(report)
            else:
                assert result.returncode == 1
            assert "synthetic-only" not in result.stdout + result.stderr
        path.write_text(json.dumps(original))
        # Normal application lifecycle is still entirely simulated and networkless.
        lifecycle = command[:-1]
        lifecycle.remove("--rm")
        lifecycle.insert(lifecycle.index("run") + 1, "--detach")
        lifecycle[lifecycle.index("--name") + 1] = "maintenance-lifecycle-" + uuid.uuid4().hex[:12]
        container = subprocess.check_output(lifecycle, text=True).strip()
        try:
            deadline = time.monotonic() + 15
            while True:
                health = subprocess.run(docker + ["exec", container, "python3", "/app/healthcheck.py"], capture_output=True)
                if health.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("simulation local health did not become ready")
                time.sleep(0.1)
            subprocess.run(docker + ["stop", "--time", "10", container], check=True, capture_output=True)
            state = json.loads(subprocess.check_output(docker + ["inspect", container], text=True))[0]["State"]
            assert state["ExitCode"] == 0
        finally:
            subprocess.run(docker + ["rm", "--force", container], capture_output=True)
        return {"selftest": reports[0], "forged_activations_refused": 3,
                "normal_simulation_health_passed": True, "clean_stop_exit_code": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    args = parser.parse_args()
    print(json.dumps(check(args.image), indent=2))
