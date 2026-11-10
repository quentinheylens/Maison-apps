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
        path.touch(mode=0o600)
        path.chmod(0o600)  # Supervisor options can be root-only, even for the health bootstrap.
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
        index = lifecycle.index(image)
        lifecycle[index:index] = ["--health-interval", "1s", "--health-start-period", "1s", "--health-timeout", "5s"]
        container = subprocess.check_output(lifecycle, text=True).strip()
        try:
            metadata = json.loads(subprocess.check_output(docker + ["inspect", container], text=True))[0]
            health_command = metadata["Config"]["Healthcheck"]["Test"]
            assert health_command == ["CMD", "python3", "-m", "maintenance.entrypoint", "healthcheck"]
            # Direct probes must fail, both as root and as an unprivileged user
            # with the synthetic credentials still inherited from Docker exec.
            role = reports[0]["role"]
            for user in ("0:0", "65532:65532"):
                refused = subprocess.run(docker + ["exec", "--user", user, container,
                    "python3", "/app/healthcheck.py", role], capture_output=True, text=True)
                assert refused.returncode == 1 and "synthetic-only" not in refused.stdout + refused.stderr
            deadline = time.monotonic() + 15
            while True:
                health = subprocess.run(docker + ["exec", container, *health_command[1:]], capture_output=True)
                if health.returncode == 0:
                    health_isolation = json.loads(health.stdout)
                    assert health_isolation == {"healthy": True, "uid": 65532, "gid": 65532,
                        "capabilities_zero": True, "credential_environment_clean": True,
                        "no_new_privileges": True, "network_syscalls_denied": True}
                    assert b"synthetic-only" not in health.stdout + health.stderr
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("simulation local health did not become ready")
                time.sleep(0.1)
            # Also wait for Docker's own scheduler to run the shipped command;
            # inspecting only PID 1 or an administrative exec is insufficient.
            while True:
                state = json.loads(subprocess.check_output(docker + ["inspect", container], text=True))[0]["State"]
                if state.get("Health", {}).get("Status") == "healthy":
                    scheduled = state["Health"]["Log"][-1]
                    assert scheduled["ExitCode"] == 0 and "synthetic-only" not in scheduled["Output"]
                    assert json.loads(scheduled["Output"]) == health_isolation
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Docker-scheduled simulation health did not become ready")
                time.sleep(0.1)
            # Freeze only the synthetic application's heartbeat, so a concurrent
            # refresh cannot conceal a forged file. All mutations stay in tmpfs.
            subprocess.run(docker + ["kill", "--signal", "STOP", container], check=True, capture_output=True)
            try:
                folder = "diagnostic-v6" if role == "diagnostic" else "deploy-simulation"
                file = "/tmp/" + folder + "/health.json"
                original_health = subprocess.check_output(docker + ["exec", "--user", "65532:65532", container,
                    "python3", "-c", "import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())", file])
                for attack in ("stale", "future", "oversize", "symlink", "hardlink", "unsafe_flags"):
                    forge = """import json,os,pathlib,sys,time
p=pathlib.Path(sys.argv[1]); attack=sys.argv[2]
if attack=='stale': os.utime(p,(time.time()-60,)*2)
elif attack=='future': os.utime(p,(time.time()+60,)*2)
elif attack=='oversize': p.write_bytes(b'x'*4097)
elif attack=='symlink': p.unlink(); p.symlink_to('/data/options.json')
elif attack=='hardlink': os.link(p,str(p)+'.link')
elif attack=='unsafe_flags':
 r=json.loads(p.read_bytes()); r['writes_enabled']=True; p.write_text(json.dumps(r))
"""
                    subprocess.run(docker + ["exec", "--user", "65532:65532", container,
                        "python3", "-c", forge, file, attack], check=True, capture_output=True)
                    rejected = subprocess.run(docker + ["exec", container, *health_command[1:]], capture_output=True)
                    assert rejected.returncode == 1, "unsafe heartbeat accepted: " + attack
                    restore = """import pathlib,sys
p=pathlib.Path(sys.argv[1]); p.unlink(); pathlib.Path(str(p)+'.link').unlink(missing_ok=True); p.write_bytes(sys.stdin.buffer.read())
"""
                    subprocess.run(docker + ["exec", "--interactive", "--user", "65532:65532", container,
                        "python3", "-c", restore, file], input=original_health, check=True, capture_output=True)
                assert subprocess.run(docker + ["exec", container, *health_command[1:]], capture_output=True).returncode == 0
            finally:
                subprocess.run(docker + ["kill", "--signal", "CONT", container], check=True, capture_output=True)
            # Inspect the shipped PID 1, not the separate Docker-exec collector:
            # an administrative exec does not inherit the runtime's seccomp filter.
            probe = """import json,pathlib
fields=dict(line.split(':',1) for line in pathlib.Path('/proc/1/status').read_text().splitlines() if ':' in line)
assert fields['Uid'].split()==['65532']*4 and fields['Gid'].split()==['65532']*4
assert fields['Groups'].split()==[]
assert all(int(fields[name].strip(),16)==0 for name in ('CapEff','CapPrm','CapInh','CapAmb'))
assert fields['NoNewPrivs'].strip()=='1' and fields['Seccomp'].strip()=='2'
assert not pathlib.Path('/config').exists() and not pathlib.Path('/var/run/docker.sock').exists()
assert not any(key+b'=' in pathlib.Path('/proc/1/environ').read_bytes() for key in
 (b'SUPERVISOR_TOKEN',b'HASSIO_TOKEN',b'MAISON_GATEWAY_TOKEN',b'TS_AUTHKEY'))
print(json.dumps({'runtime_capabilities_zero':True,'no_new_privileges':True,'seccomp_active':True,
 'production_config_absent':True,'docker_socket_absent':True,'inherited_credentials_absent':True}))
"""
            isolation = json.loads(subprocess.check_output(docker + ["exec", "--user", "65532:65532", container,
                                                                     "python3", "-c", probe], text=True))
            dependency_probe = """import importlib.util,json,platform,ssl,zlib
assert platform.python_version()=='3.15.2'
assert all(importlib.util.find_spec(name) is None for name in ('sqlite3','_sqlite3','pip','ensurepip'))
assert zlib.ZLIB_RUNTIME_VERSION=='1.4'
assert zlib.decompress(zlib.compress(b'offline-simulation'))==b'offline-simulation'
print(json.dumps({'python':platform.python_version(),'openssl':ssl.OPENSSL_VERSION,'zlib':zlib.ZLIB_RUNTIME_VERSION,
 'sqlite_absent':True,'pip_and_ensurepip_absent':True,'compression_roundtrip_passed':True}))
"""
            minimized_runtime = json.loads(subprocess.check_output(docker + ["exec", "--user", "65532:65532", container,
                "python3", "-c", dependency_probe], text=True))
            metadata = json.loads(subprocess.check_output(docker + ["inspect", container], text=True))[0]
            host = metadata["HostConfig"]
            assert host["Privileged"] is False and host["ReadonlyRootfs"] is True
            assert host["NetworkMode"] == "none" and host["PidMode"] != "host"
            assert not host.get("CapAdd") and not host.get("Devices")
            assert not metadata["Config"].get("ExposedPorts")
            assert all(mount["Destination"] in {"/data/options.json", "/tmp"} for mount in metadata["Mounts"])
            assert all(not mount["RW"] for mount in metadata["Mounts"] if mount["Destination"] == "/data/options.json")
            isolation.update({"container_unprivileged": True, "rootfs_read_only": True,
                              "network_namespace_none": True, "mounts_limited_to_synthetic_options_and_tmp": True})
            subprocess.run(docker + ["stop", "--time", "10", container], check=True, capture_output=True)
            state = json.loads(subprocess.check_output(docker + ["inspect", container], text=True))[0]["State"]
            assert state["ExitCode"] == 0
        finally:
            subprocess.run(docker + ["rm", "--force", container], capture_output=True)
        return {"minimized_runtime": minimized_runtime, "selftest": reports[0], "runtime_isolation": isolation, "healthcheck_isolation": health_isolation,
                "unsafe_direct_healthchecks_refused": 2, "forged_heartbeats_refused": 6, "forged_activations_refused": 3,
                "normal_simulation_health_passed": True, "docker_scheduled_healthcheck_passed": True, "clean_stop_exit_code": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    args = parser.parse_args()
    print(json.dumps(check(args.image), indent=2))
