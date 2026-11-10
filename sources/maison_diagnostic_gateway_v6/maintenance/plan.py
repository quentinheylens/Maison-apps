"""Version 2 simulation plans; local approvals bind the exact canonical plan."""

import hashlib
import hmac
import json
import re
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import PurePosixPath

from maintenance.safe_fs import MAX_FILE, canonical, digest, relative

REPOSITORY = "simulation-fixture/maintenance"
HEX = re.compile(r"[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
RISKS = ("low", "moderate", "high", "critical")


def timestamp(value):
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if instant.tzinfo is None:
        raise ValueError("timestamp must be timezone aware")
    return instant.astimezone(timezone.utc)


def file_rule(path):
    parts = relative(path)
    if path == "automations.yaml":
        return "high", "automation"
    if path == "scripts.yaml":
        return "high", "script"
    if len(parts) >= 2 and parts[0] == "dashboards" and PurePosixPath(path).suffix in {".yaml", ".yml"}:
        return "moderate", "manual-dashboard"
    if len(parts) >= 2 and parts[0] == "docs" and PurePosixPath(path).suffix == ".md":
        return "low", "none"
    raise ValueError("file outside the simulation deployment allowlist")


def content_risk(path, before, after):
    risk, _ = file_rule(path)
    if PurePosixPath(path).suffix in {".yaml", ".yml"}:
        text = (before + b"\n" + after).decode("utf-8").casefold()
        if re.search(r"(?:lock\.|alarm_control_panel\.|camera\.|shell_command|python_script|rest_command|"
                     r"command_line|homeassistant\.restart|hassio\.|supervisor\.)", text):
            raise ValueError("known critical or executable configuration has no executor")
        if path.startswith("dashboards/") and re.search(r"(?:call-service|perform-action|service:|action:)", text):
            risk = "high"
    return risk


def git_bytes(repository, commit, path):
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise ValueError("full immutable commit required")
    relative(path)
    if isinstance(repository, FixtureGit):
        if repository.commit != commit or repository.compute_commit() != commit:
            raise ValueError("fixture commit mismatch")
        data = repository.files[path]
        if len(data) > MAX_FILE:
            raise ValueError("fixture blob exceeds bound")
        return data
    run = lambda *args: subprocess.check_output(["git", "-C", str(repository), *args], stderr=subprocess.DEVNULL)
    if run("rev-parse", "--verify", commit + "^{commit}").decode().strip() != commit:
        raise ValueError("commit mismatch")
    info = run("ls-tree", commit, "--", path).decode().strip()
    if not info.startswith("100644 blob ") or info.split("\t", 1)[-1] != path:
        raise ValueError("candidate must be an ordinary Git blob")
    # ls-tree checks size before reading; no archive extraction or Git hooks.
    blob = info.split()[2]
    if int(run("cat-file", "-s", blob)) > MAX_FILE:
        raise ValueError("candidate exceeds bound")
    return run("cat-file", "blob", blob)


class FixtureGit:
    """In-memory real Git object hashes for the Git-free simulation images.

    This is not a repository fetch or a trusted GitHub attestation. Host tests
    separately use git_bytes with an actual repository and full commit object.
    """
    def __init__(self, files):
        self.files = dict(files)
        for name in self.files:
            relative(name)
        self.commit = self.compute_commit()

    def compute_commit(self):
        def obj(kind, value):
            return hashlib.sha1(kind.encode() + b" " + str(len(value)).encode() + b"\0" + value).digest()
        root = {}
        for name, content in self.files.items():
            node = root
            parts = relative(name)
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = content
        def tree(node):
            entries = []
            for name, value in sorted(node.items(), key=lambda pair: pair[0] + ("/" if isinstance(pair[1], dict) else "")):
                mode, sha = (b"40000", tree(value)) if isinstance(value, dict) else (b"100644", obj("blob", value))
                entries.append(mode + b" " + name.encode() + b"\0" + sha)
            return obj("tree", b"".join(entries))
        content = (b"tree " + tree(root).hex().encode() +
                   b"\nauthor Simulator <simulation@example.invalid> 0 +0000\n"
                   b"committer Simulator <simulation@example.invalid> 0 +0000\n\nOffline fixture\n")
        return obj("commit", content).hex()


def validate_plan(plan):
    expected = {"version", "repository", "base_ref", "commit", "execution_enabled", "simulation",
                "operation_id", "created_at", "expires_at", "risk", "rollback", "files"}
    if not isinstance(plan, dict) or set(plan) != expected:
        raise ValueError("invalid simulation plan fields")
    if (type(plan["version"]) is not int or plan["version"] != 2
            or plan["execution_enabled"] is not False or plan["simulation"] is not True
            or plan["repository"] != REPOSITORY or plan["base_ref"] != "develop"
            or not isinstance(plan["commit"], str) or not COMMIT.fullmatch(plan["commit"])
            or not re.fullmatch(r"sim-[a-f0-9]{32}", plan["operation_id"])):
        raise ValueError("plan is not a disabled simulation plan")
    created, expires = timestamp(plan["created_at"]), timestamp(plan["expires_at"])
    if not 0 < (expires - created).total_seconds() <= 3600:
        raise ValueError("plan lifetime exceeds one hour")
    if plan["risk"] not in RISKS or plan["rollback"] not in {"manual", "on-failure"}:
        raise ValueError("invalid risk or rollback policy")
    if not isinstance(plan["files"], list) or not 1 <= len(plan["files"]) <= 8:
        raise ValueError("plan needs one to eight files")
    paths = set()
    for entry in plan["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "before", "after", "reload"}:
            raise ValueError("invalid file entry")
        risk, reload = file_rule(entry["path"])
        if entry["path"] in paths or entry["reload"] != reload:
            raise ValueError("duplicate file or incorrect reload")
        if RISKS.index(plan["risk"]) < RISKS.index(risk):
            raise ValueError("risk cannot be downgraded")
        if any(not isinstance(entry[k], str) or not HEX.fullmatch(entry[k]) for k in ("before", "after")):
            raise ValueError("invalid content hash")
        paths.add(entry["path"])
    if plan["risk"] == "critical":
        raise ValueError("critical interventions have no executor in this version")
    return plan


def prepare_plan(repository, commit, sandbox, paths, *, rollback="manual", now=None):
    from datetime import timedelta
    import uuid
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate paths")
    now = now or datetime.now(timezone.utc)
    entries = []
    highest = "low"
    total = 0
    for path in paths:
        risk, reload = file_rule(path)
        before = sandbox.tree.read("live/" + path)
        after = git_bytes(repository, commit, path)
        risk = content_risk(path, before, after)
        total += len(before) + len(after)
        if total > 2 * 1024 * 1024:
            raise ValueError("transaction bytes exceed bound")
        highest = max((highest, risk), key=RISKS.index)
        entries.append({"path": path, "before": digest(before), "after": digest(after), "reload": reload})
    plan = {"version": 2, "repository": REPOSITORY, "base_ref": "develop", "commit": commit,
            "execution_enabled": False, "simulation": True, "operation_id": "sim-" + uuid.uuid4().hex,
            "created_at": now.isoformat(), "expires_at": (now + timedelta(minutes=30)).isoformat(),
            "risk": highest, "rollback": rollback, "files": entries}
    return validate_plan(plan)


class SimulationAuthority:
    """Ephemeral test-only guardian. Not an implementation of human consent."""
    def __init__(self):
        self._key = secrets.token_bytes(32)

    def approve(self, plan, *, human_confirmed, now=None):
        validate_plan(plan)
        now = now or datetime.now(timezone.utc)
        if human_confirmed is not True or not timestamp(plan["created_at"]) <= now < timestamp(plan["expires_at"]):
            raise ValueError("specific, current simulated approval required")
        payload = {"simulation": True, "plan_digest": digest(canonical(plan)),
                   "nonce": secrets.token_hex(16), "expires_at": plan["expires_at"]}
        return {"payload": payload, "signature": hmac.new(self._key, canonical(payload), hashlib.sha256).hexdigest()}

    def verify(self, plan, approval, now=None):
        validate_plan(plan)
        now = now or datetime.now(timezone.utc)
        if not isinstance(approval, dict) or set(approval) != {"payload", "signature"}:
            raise ValueError("approval required")
        payload = approval["payload"]
        if (not isinstance(payload, dict) or set(payload) != {"simulation", "plan_digest", "nonce", "expires_at"}
                or payload["simulation"] is not True
                or payload["plan_digest"] != digest(canonical(plan))
                or payload["expires_at"] != plan["expires_at"]
                or not re.fullmatch(r"[a-f0-9]{32}", payload["nonce"])
                or not timestamp(plan["created_at"]) <= now < timestamp(plan["expires_at"])):
            raise ValueError("approval does not bind this current operation")
        expected = hmac.new(self._key, canonical(payload), hashlib.sha256).hexdigest()
        if not isinstance(approval["signature"], str) or not hmac.compare_digest(expected, approval["signature"]):
            raise ValueError("approval signature mismatch")
        return payload["nonce"]
