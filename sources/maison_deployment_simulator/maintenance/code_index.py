"""Local linking to exact Git blobs, including Mission 2 entity pseudonyms."""

import hashlib
import hmac
import re
from pathlib import PurePosixPath

from maintenance.plan import git_bytes


def mission2_alias(key, entity):
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("local pseudonymization key unavailable")
    value = hmac.new(key, ("entity\0" + entity).encode(), hashlib.sha256).hexdigest()[:16]
    return entity.split(".")[0] + ".entity_ref_" + value


class CodeIndex:
    def __init__(self, repository, commit, policy, paths, *, local_key=None, reviewed_aliases=None):
        if not isinstance(paths, list) or len(paths) > 500 or len(paths) != len(set(paths)):
            raise ValueError("bounded approved code paths required")
        aliases = reviewed_aliases or {}
        if set(aliases) - set(policy.entities):
            raise ValueError("alias for an unapproved entity")
        self.commit = commit
        self.references = {entity: [] for entity in policy.entities}
        patterns = {}
        for entity in policy.entities:
            extra = aliases.get(entity, [])
            if not isinstance(extra, list) or len(extra) > 4:
                raise ValueError("bounded local aliases required")
            names = [entity] + extra
            if local_key is not None:
                names.append(mission2_alias(local_key, entity))
            if any(not isinstance(n, str) or not re.fullmatch(r"[a-z_]+\.[a-z0-9_]+", n) for n in names):
                raise ValueError("invalid local alias")
            patterns[entity] = re.compile(r"(?<![a-z0-9_.])(?:" + "|".join(map(re.escape, names)) + r")(?![a-z0-9_])")
        total = 0
        for path in paths:
            candidate = PurePosixPath(path)
            if (candidate.suffix not in {".yaml", ".yml", ".json"}
                    or any(p.startswith(".") for p in candidate.parts)
                    or candidate.name in {"secrets.yaml", "options.json", "policy.local.json"}):
                raise ValueError("code path not exportable")
            data = git_bytes(repository, commit, path)
            total += len(data)
            if total > 8 * 1024 * 1024:
                raise ValueError("code index byte budget exceeded")
            for line, content in enumerate(data.decode().splitlines(), 1):
                for entity, pattern in patterns.items():
                    if pattern.search(content) and len(self.references[entity]) < 100:
                        self.references[entity].append({"path": path, "line": line, "kind": "reference"})

    def links(self, entity):
        # No alias table, raw line, key or guessed reverse mapping is returned.
        return {"commit": self.commit, "references": self.references[entity],
                "complete": False, "dynamic_templates_resolved": False}
