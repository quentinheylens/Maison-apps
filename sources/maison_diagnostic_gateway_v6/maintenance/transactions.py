"""Durable, bounded deployment/rollback exercises in /tmp sandboxes only."""

import fcntl
import json
import os
import stat
from pathlib import PurePosixPath

import yaml

from maintenance.private_audit import PrivateAudit
from maintenance.plan import RISKS, content_risk, git_bytes, validate_plan
from maintenance.safe_fs import canonical, digest


class SimulatedCrash(BaseException):
    """Test fault that models process loss, not an ordinary validation failure."""


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        self.node_count = getattr(self, "node_count", 0) + 1
        self.node_depth = getattr(self, "node_depth", 0) + 1
        try:
            if self.node_count > 20000 or self.node_depth > 32 or self.check_event(yaml.AliasEvent):
                raise ValueError("YAML complexity limit exceeded")
            return super().compose_node(parent, index)
        finally:
            self.node_depth -= 1


def unique_mapping(loader, node):
    result = {}
    for key, value in node.value:
        name = loader.construct_object(key)
        if name in result:
            raise ValueError("duplicate YAML key")
        result[name] = loader.construct_object(value)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
for tag in ("!secret", "!include", "!include_dir_list", "!include_dir_merge_list",
            "!include_dir_named", "!include_dir_merge_named"):
    StrictLoader.add_constructor(tag, lambda loader, node: loader.construct_scalar(node))


class SimulatedCore:
    """No network, subprocess, restart, backup API or actual reload implementation."""
    def __init__(self, *, fail_validate=False, fail_reload=False, fail_verify=False):
        self.fail_validate, self.fail_reload, self.fail_verify = fail_validate, fail_reload, fail_verify
        self.reloads = []

    def validate(self, candidate):
        for path, content in candidate.items():
            if PurePosixPath(path).suffix in {".yaml", ".yml"}:
                parsed = yaml.load(content, Loader=StrictLoader)
                expected = list if path == "automations.yaml" else dict
                if not isinstance(parsed, expected):
                    raise ValueError("invalid candidate YAML structure")
        return not self.fail_validate

    def reload(self, operations):
        if self.fail_reload:
            return False
        self.reloads.append(sorted(set(operations) - {"none", "manual-dashboard"}))
        return True

    def verify(self):
        return not self.fail_verify


class TransactionAgent:
    def __init__(self, sandbox, authority, core=None):
        self.sandbox, self.authority = sandbox, authority
        self.tree = sandbox.tree
        self.core = core or SimulatedCore()
        if not isinstance(self.core, SimulatedCore):
            raise ValueError("only the simulated Core is accepted")
        self.audit = PrivateAudit(self.tree)

    def _lock(self):
        parent, name = self.tree.parent("state/transaction.lock")
        try:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("unsafe transaction lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(fd)
            raise ValueError("another transaction is active") from None
        return fd

    def _journal(self):
        value = json.loads(self.tree.read("state/transaction.json"))
        if (not isinstance(value, dict) or set(value) != {"plan", "plan_digest", "approval_nonce", "phase"}
                or value["phase"] not in {"preparing", "backed_up", "applying", "checking", "committed",
                                           "manual_required", "rolling_back", "rolled_back"}
                or value["plan_digest"] != digest(canonical(validate_plan(value["plan"])))):
            raise ValueError("invalid transaction journal")
        return value

    def _save(self, state, phase):
        state["phase"] = phase
        self.tree.write("state/transaction.json", canonical(state))
        self.audit.write(request_id=state["plan"]["operation_id"], identity="simulated-local-operator",
                         method="OTHER", route="/simulation/transaction", status=409 if phase == "manual_required" else 200,
                         outcome=phase)

    def apply(self, repository, plan, approval, *, fault=None):
        plan = json.loads(canonical(plan))
        approval = json.loads(canonical(approval))
        validate_plan(plan)
        nonce = self.authority.verify(plan, approval)
        lock = self._lock()
        state = None
        try:
            try:
                previous = self._journal()
            except FileNotFoundError:
                previous = None
            if previous and previous["phase"] not in {"committed", "rolled_back"}:
                raise ValueError("recover the pending transaction first")
            try:
                used = json.loads(self.tree.read("state/used-approvals.json"))
            except FileNotFoundError:
                used = []
            if nonce in used or len(used) >= 100:
                raise ValueError("approval replay or bounded ledger exhausted")
            candidate = {}
            total, growth, largest = 0, 0, 0
            for entry in plan["files"]:
                path = entry["path"]
                old = self.tree.read("live/" + path)
                new = git_bytes(repository, plan["commit"], path)
                if digest(old) != entry["before"] or digest(new) != entry["after"]:
                    raise ValueError("baseline or exact commit changed")
                if RISKS.index(plan["risk"]) < RISKS.index(content_risk(path, old, new)):
                    raise ValueError("content risk was downgraded")
                candidate[path] = new
                total += len(old) + len(new)
                growth += max(0, len(new) - len(old))
                largest = max(largest, len(new))
            if total > 2 * 1024 * 1024:
                raise ValueError("transaction bytes exceed bound")
            # Reserve growth of live files, one atomic temporary and audit/state
            # overhead as well as the backup and staging copies.
            if self.tree.usage() + total + growth + largest + 256 * 1024 > 8 * 1024 * 1024:
                raise ValueError("sandbox disk budget exceeded")
            # Validation is a bounded YAML/structure test only, never an official
            # HA check or execution of automations in the candidate.
            if not self.core.validate(candidate):
                raise ValueError("candidate validation refused")
            self.tree.write("state/used-approvals.json", canonical(used + [nonce]))
            state = {"plan": plan, "plan_digest": digest(canonical(plan)), "approval_nonce": nonce}
            self._save(state, "preparing")
            for entry in plan["files"]:
                path = entry["path"]
                backup = "backups/" + plan["operation_id"] + "/" + path
                self.tree.mkdir(str(PurePosixPath(backup).parent))
                self.tree.write(backup, self.tree.read("live/" + path), new=True)
                if digest(self.tree.read(backup)) != entry["before"]:
                    raise ValueError("backup verification failed")
                self.tree.mkdir(str(PurePosixPath("staged/" + path).parent))
                self.tree.write("staged/" + path, candidate[path])
            self._save(state, "backed_up")
            if fault:
                fault("backed_up", self)
            self.authority.verify(plan, approval)  # Expired approval cannot start the copies.
            # Check every baseline before starting, then again per replacement.
            for entry in plan["files"]:
                if digest(self.tree.read("live/" + entry["path"])) != entry["before"]:
                    raise ValueError("concurrent baseline drift")
            self._save(state, "applying")
            for entry in plan["files"]:
                path = entry["path"]
                data = self.tree.read("staged/" + path)
                if digest(data) != entry["after"]:
                    raise ValueError("staged content changed")
                self.tree.write("live/" + path, data, expected=entry["before"])
                if fault:
                    fault(path, self)
            if any(digest(self.tree.read("live/" + e["path"])) != e["after"] for e in plan["files"]):
                raise ValueError("post-copy hash mismatch")
            self._save(state, "checking")
            if not self.core.reload([e["reload"] for e in plan["files"]]) or not self.core.verify():
                raise ValueError("simulated reload or postcheck failed")
            self._save(state, "committed")
            return {"simulation": True, "phase": "committed", "files": len(plan["files"]), "writes_enabled": False}
        except Exception:
            if state is not None:
                if plan["rollback"] == "on-failure":
                    self._restore(state)
                else:
                    self._save(state, "manual_required")
            raise
        finally:
            os.close(lock)

    def _restore(self, state):
        plan = validate_plan(state["plan"])
        if state["plan_digest"] != digest(canonical(plan)):
            raise ValueError("journal plan corrupted")
        backups = {}
        # Validate ALL files before the first restore; do not overwrite a new
        # edit or a corrupted backup just to claim a successful rollback.
        try:
            for e in plan["files"]:
                path = e["path"]
                data = self.tree.read("backups/" + plan["operation_id"] + "/" + path)
                current = digest(self.tree.read("live/" + path))
                if digest(data) != e["before"] or current not in {e["before"], e["after"]}:
                    raise ValueError("rollback conflict or corrupted backup")
                backups[path] = data
        except Exception:
            self._save(state, "manual_required")
            raise
        self._save(state, "rolling_back")
        for e in plan["files"]:
            path = e["path"]
            current = digest(self.tree.read("live/" + path))
            if current != e["before"]:
                self.tree.write("live/" + path, backups[path], expected=e["after"])
        if any(digest(self.tree.read("live/" + e["path"])) != e["before"] for e in plan["files"]):
            raise ValueError("restored hash mismatch")
        # Restoring bytes cannot prove restored physical state. Reload/verify
        # failures leave a manual incident, never an automatic restart loop.
        if not self.core.reload([e["reload"] for e in plan["files"]]) or not self.core.verify():
            self._save(state, "manual_required")
            raise ValueError("restored bytes need manual activation verification")
        self._save(state, "rolled_back")

    def recover(self, *, manual_approval=False):
        lock = self._lock()
        try:
            state = self._journal()
            if state["phase"] == "rolled_back":
                return "rolled_back"
            if state["phase"] == "committed" and manual_approval is not True:
                raise ValueError("successful deployments need a separate simulated rollback approval")
            if state["plan"]["rollback"] != "on-failure" and manual_approval is not True:
                raise ValueError("specific simulated rollback approval required")
            self._restore(state)
            return "rolled_back"
        finally:
            os.close(lock)
