#!/usr/bin/env python3
"""Simulation catalogue tooling. No Home Assistant, Supervisor or deployment access."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import zipfile

APPS = {"maison_diagnostic_gateway_v6": ("diagnostic", "0.6.1"),
        "maison_deployment_simulator": ("deployment", "0.1.1")}
ARCHES = {"aarch64": "arm64", "amd64": "amd64"}
BASE = 'python:3.15.2-alpine3.24@sha256:a0f2e268f2ce8f3709611a90054ec6a8ae31f6251f5896b8648b9bb99835e30a'
RUNTIME_HARDENING = 'ADD --checksum=sha256:7b05bc778b8b25cd880835b40114182bd4d1581717504d0129c810c0a14291cb https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/zlib-1.4-r0.apk /tmp/zlib-amd64.apk\nADD --checksum=sha256:d3e30d012a3445222b0b4a28f1d4d97ce67387f8b48561921111696da174f0de https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/zlib-1.4-r0.apk /tmp/zlib-arm64.apk\nRUN --network=none python3 - <<\'HARDEN\'\nimport hashlib,platform,subprocess,zlib\nfrom pathlib import Path\narch={\'x86_64\':\'amd64\',\'aarch64\':\'arm64\'}[platform.machine()]\nfile=Path(\'/tmp/zlib-\'+arch+\'.apk\')\nchecksums={\'amd64\': \'7b05bc778b8b25cd880835b40114182bd4d1581717504d0129c810c0a14291cb\', \'arm64\': \'d3e30d012a3445222b0b4a28f1d4d97ce67387f8b48561921111696da174f0de\'}\nassert hashlib.sha256(file.read_bytes()).hexdigest()==checksums[arch]\nsubprocess.run([\'apk\',\'--no-network\',\'verify\',str(file)],check=True)\nsubprocess.run([\'apk\',\'--no-network\',\'add\',str(file)],check=True)\nfrom pathlib import Path\nimport subprocess,sysconfig,shutil,importlib.util\nblocks=Path(\'/lib/apk/db/installed\').read_text().split(\'\\n\\n\')\nrecord=next(block for block in blocks if \'\\nP:.python-rundeps\\n\' in \'\\n\'+block+\'\\n\')\ndeps=next(line[2:].split() for line in record.splitlines() if line.startswith(\'D:\'))\nassert deps.count(\'so:libsqlite3.so.0\')==1\nsubprocess.run([\'apk\',\'--no-network\',\'add\',*[x for x in deps if x!=\'so:libsqlite3.so.0\']],check=True)\nsubprocess.run([\'apk\',\'--no-network\',\'del\',\'.python-rundeps\'],check=True)\nstdlib=Path(sysconfig.get_path(\'stdlib\')); site=Path(sysconfig.get_path(\'purelib\'))\nfor name in (\'sqlite3\',\'ensurepip\'):shutil.rmtree(stdlib/name)\nfor file in (stdlib/\'lib-dynload\').glob(\'_sqlite3.*.so\'):file.unlink()\nfor file in [site/\'pip\',*site.glob(\'pip-*.dist-info\')]:shutil.rmtree(file)\nfor name in (\'pip\',\'pip3\',\'pip3.14\'):(Path(\'/usr/local/bin\')/name).unlink(missing_ok=True)\nassert all(importlib.util.find_spec(name) is None for name in (\'sqlite3\',\'_sqlite3\',\'pip\',\'ensurepip\'))\nassert not list(Path(\'/usr/lib\').glob(\'libsqlite3.so*\'))\n\n# Load zlib in a fresh interpreter after replacing its shared library.\nsubprocess.run([\'python3\',\'-c\',"import zlib; assert zlib.ZLIB_RUNTIME_VERSION==\'1.4\'; assert zlib.decompress(zlib.compress(b\'offline-simulation\'))==b\'offline-simulation\'"],check=True)\nfor file in Path(\'/tmp\').glob(\'zlib-*.apk\'):file.unlink()\nHARDEN\n'
FLAGS = "homeassistant_api hassio_api auth_api docker_api host_network host_pid host_dbus full_access ingress".split()
GATEWAY = "__init__ audit bounded_audit data_source policy real_source redaction service simulation_entrypoint".split()
MAINTENANCE = "__init__ code_index diagnostics entrypoint evidence fixtures network_lock plan private_audit runtime safe_fs transactions".split()
MODULES = {f"{group}/{name}.py" for group, names in (("gateway", GATEWAY), ("maintenance", MAINTENANCE)) for name in names}
YAML_FILES = "__init__ composer constructor cyaml dumper emitter error events loader nodes parser reader representer resolver scanner serializer tokens".split()
PAYLOAD = MODULES | {f"yaml/{name}.py" for name in YAML_FILES} | {
    "app.json", "Dockerfile", "installation-profile.json", "PyYAML-LICENSE", "healthcheck.py"}
ROOT_FILES = {"repository.yaml", "catalog-policy.json", "README.md", "SECURITY.md",
              "DEPENDENCIES.json", "NOTICE.md",
              "tools/catalog.py", "tools/check_maintenance_image.py",
              ".github/workflows/verify.yml", ".github/workflows/publish.yml"}
CREDENTIALS = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:gh[opsu]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b|(?i:authorization\s*[:=]\s*bearer\s+[A-Za-z0-9._~-]{16,})")


def run(*args, **kwargs):
    return subprocess.check_output(list(args), text=True, **kwargs).strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def read_json(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON member")
            value[key] = item
        return value
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def ordinary(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 512 * 1024:
        raise ValueError("ordinary bounded file required")
    return path.read_bytes()


def recipe(role):
    return (f"FROM {BASE}\n{RUNTIME_HARDENING}WORKDIR /app\nCOPY gateway /app/gateway\nCOPY maintenance /app/maintenance\n"
            "COPY yaml /app/yaml\nCOPY PyYAML-LICENSE /app/PyYAML-LICENSE\n"
            "COPY installation-profile.json /app/installation-profile.json\nCOPY healthcheck.py /app/healthcheck.py\n"
            f"ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MAISON_ROLE={role}\n"
            'HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["python3", "-m", "maintenance.entrypoint", "healthcheck"]\n'
            f'ENTRYPOINT ["python3", "-m", "maintenance.entrypoint", "{role}"]\n').encode()


def config_checked(config, slug, version=None):
    version = version or APPS[slug][1]
    fields = set(FLAGS) | {"name", "version", "slug", "description", "arch", "startup", "boot", "init", "timeout",
                           "apparmor", "ports", "map", "tmpfs", "options", "schema"}
    if set(config) != fields or config["slug"] != slug or config["version"] != version:
        raise ValueError("unreviewed configuration fields or version")
    if any(config[key] is not False for key in FLAGS + ["init"]):
        raise ValueError("application privilege forbidden")
    if (config["boot"] != "manual" or config["arch"] != ["aarch64", "amd64"] or config["startup"] != "application"
            or config["ports"] != {} or config["map"] != [] or config["apparmor"] is not True
            or config["tmpfs"] is not True or type(config["timeout"]) is not int or config["timeout"] != 30):
        raise ValueError("unsafe runtime settings")
    if config["options"] != {"mode": "simulation", "network_enabled": False, "execution_enabled": False} or any(
            config["options"][key] is not False for key in ("network_enabled", "execution_enabled")):
        raise ValueError("simulation flags required")
    if config["schema"] != {"mode": "list(simulation)", "network_enabled": "bool", "execution_enabled": "bool"}:
        raise ValueError("simulation schema required")
    if any(not isinstance(config[key], str) or len(config[key]) > 160 for key in ("name", "description")):
        raise ValueError("bounded public descriptions required")
    return config


def validate(root):
    root = Path(root).resolve()
    policy = read_json(root / "catalog-policy.json")
    if set(policy) != {"format", "repository", "publication_enabled", "channel", "versions"} or policy["format"] != 1:
        raise ValueError("unknown catalogue policy")
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9-]{0,63}", policy["repository"])
            or type(policy["publication_enabled"]) is not bool or policy["channel"] != "simulation"
            or policy["versions"] != {slug: value[1] for slug, value in APPS.items()}):
        raise ValueError("simulation policy required")
    repository = read_json(root / "repository.yaml")  # JSON is valid YAML, no parser dependency.
    if repository != {"name": "Maison — Simulation apps", "url": "https://github.com/" + policy["repository"]}:
        raise ValueError("canonical repository required")
    inventory = read_json(root / "source-manifest.json")
    expected = ROOT_FILES | {f"sources/{slug}/{name}" for slug in APPS for name in PAYLOAD}
    if inventory.get("format") != 1 or set(inventory.get("files", {})) != expected:
        raise ValueError("closed source manifest required")
    present = set()
    total = 0
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if path.is_symlink():
            raise ValueError("symbolic link forbidden")
        if path.is_dir():
            continue
        data = ordinary(path)
        total += len(data)
        if total > 8 * 1024 * 1024:
            raise ValueError("bounded catalogue required")
        if CREDENTIALS.search(data.decode("utf-8")):
            raise ValueError("possible credential in distribution; publication refused")
        present.add(relative)
        if relative in expected and relative != "catalog-policy.json":
            if inventory["files"][relative] != {"sha256": sha(data), "bytes": len(data)}:
                raise ValueError("source manifest hash mismatch")
    # Policy enables publication only after a separate reviewed change. It never grants HA rights.
    promoted = {f"{slug}/{name}" for slug in APPS for name in ("config.yaml", "DOCS.md", "CHANGELOG.md")}
    if not expected | {"source-manifest.json"} <= present or present - expected - {"source-manifest.json"} - promoted - {"release-record.json"}:
        raise ValueError("unexpected or missing distribution files")
    for slug, (role, version) in APPS.items():
        base = root / "sources" / slug
        config_checked(read_json(base / "app.json"), slug)
        if ordinary(base / "Dockerfile") != recipe(role):
            raise ValueError("unreviewed Docker recipe")
        profile = read_json(base / "installation-profile.json")
        if (profile != {"role": role, "production_capable": False, "simulation": True}
                or profile["production_capable"] is not False or profile["simulation"] is not True):
            raise ValueError("simulation installation profile required")
    dependencies_checked(root)
    if present & promoted or "release-record.json" in present:
        record = read_json(root / "release-record.json")
        release_checked(record, policy, exact_versions=False)
        if not promoted <= present:
            raise ValueError("incomplete approved catalogue")
        for slug in APPS:
            config = read_json(root / slug / "config.yaml")
            version = record["images"][slug]["version"]
            if config.pop("image", None) != image_name(policy, slug) or config.pop("breaking_versions", None) != [version]:
                raise ValueError("approved metadata differs from released simulation")
            config_checked(config, slug, version=version)
    return policy


def exact_commit(root, commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or run("git", "rev-parse", "HEAD", cwd=root) != commit:
        raise ValueError("exact public source commit required")
    if run("git", "status", "--porcelain", "--untracked-files=all", cwd=root):
        raise ValueError("clean public source required")


def image_name(policy, slug):
    # Preserve GitHub's canonical case everywhere else, including workflow identity.
    return "ghcr.io/" + policy["repository"].lower() + "/" + slug


def dependencies_checked(root):
    record = read_json(Path(root) / "DEPENDENCIES.json")
    dependency = record["vendored"]
    if (record["format"] != 1 or record["runtime_base"] != BASE
            or dependency["name"] != "PyYAML" or dependency["version"] != "6.0.3" or dependency["license"] != "MIT"
            or dependency["source_sha256"] != "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f"
            or dependency["license_sha256"] != "8d3928f9dc4490fd635707cb88eb26bd764102a7282954307d3e5167a577e8a4"
            or set(dependency["python_files"]) != {name + ".py" for name in YAML_FILES}):
        raise ValueError("unreviewed dependency provenance")
    for slug in APPS:
        base = Path(root) / "sources" / slug
        if sha(ordinary(base / "PyYAML-LICENSE")) != dependency["license_sha256"]:
            raise ValueError("dependency licence differs from upstream")
        for name, checksum in dependency["python_files"].items():
            if sha(ordinary(base / "yaml" / name)) != checksum:
                raise ValueError("vendored code differs from reviewed upstream")


def check_image_archive(path, root, slug, arch, commit, image_id):
    """Inspect, never extract or execute, Docker's own saved image layers."""
    expected = {name: ordinary(Path(root) / "sources" / slug / name)
                for name in PAYLOAD - {"Dockerfile", "app.json"}}
    actual = {}
    with tarfile.open(path, "r:*") as archive:
        manifest = json.loads(archive.extractfile("manifest.json").read(1024 * 1024))
        if len(manifest) != 1 or len(manifest[0]["Layers"]) > 32:
            raise ValueError("one bounded Docker image required")
        config_bytes = archive.extractfile(manifest[0]["Config"]).read(1024 * 1024)
        config = json.loads(config_bytes)
        labels = config["config"]["Labels"]
        version = APPS[slug][1]
        expected_labels = {"io.hass.version": version, "io.hass.type": "app", "io.hass.arch": arch,
            "org.opencontainers.image.source": "https://github.com/" + read_json(Path(root) / "catalog-policy.json")["repository"],
            "org.opencontainers.image.revision": commit, "org.opencontainers.image.version": version}
        if (config["config"].get("Healthcheck", {}).get("Test") !=
                ["CMD", "python3", "-m", "maintenance.entrypoint", "healthcheck"]
                or config["config"].get("Entrypoint") != ["python3", "-m", "maintenance.entrypoint", APPS[slug][0]]):
            raise ValueError("unreviewed healthcheck or application entrypoint")
        env = config["config"].get("Env", [])
        env_keys = {value.split("=", 1)[0] for value in env}
        if (labels != expected_labels or env_keys != {"PATH", "LANG", "PYTHON_VERSION", "PYTHON_SHA256",
                "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED", "MAISON_ROLE"} or len(env) != len(env_keys)
                or CREDENTIALS.search(json.dumps(config))):
            raise ValueError("unreviewed image environment or metadata")
        if ("sha256:" + sha(config_bytes) != image_id or config["architecture"] != ARCHES[arch]
                or labels.get("org.opencontainers.image.revision") != commit
                or labels.get("io.hass.version") != APPS[slug][1] or labels.get("io.hass.arch") != arch):
            raise ValueError("archive image identity mismatch")
        for layer in manifest[0]["Layers"]:
            with tarfile.open(fileobj=archive.extractfile(layer), mode="r|*") as contents:
                for member in contents:
                    name = member.name.removeprefix("./")
                    if not name.startswith("app/") or member.isdir():
                        continue
                    relative = name[4:]
                    if not member.isfile() or relative not in expected or member.size > 512 * 1024:
                        raise ValueError("unreviewed application image layer")
                    actual[relative] = contents.extractfile(member).read(512 * 1024 + 1)
    if actual != expected:
        raise ValueError("image code differs from reviewed source")


def build(root, output, commit):
    root, output = Path(root).resolve(), Path(output).absolute()
    policy = validate(root)
    exact_commit(root, commit)
    if output.exists() or output.resolve() != output or root == output or root in output.parents:
        raise ValueError("new build output outside checkout required")
    output.mkdir(mode=0o700)
    records = []
    for slug, (role, version) in APPS.items():
        for arch, platform in ARCHES.items():
            tag = image_name(policy, slug) + ":" + version + "-" + arch
            subprocess.run(["docker", "build", "--platform", "linux/" + platform, "--tag", tag,
                "--label", "io.hass.version=" + version, "--label", "io.hass.type=app", "--label", "io.hass.arch=" + arch,
                "--label", "org.opencontainers.image.source=https://github.com/" + policy["repository"],
                "--label", "org.opencontainers.image.revision=" + commit,
                "--label", "org.opencontainers.image.version=" + version,
                str(root / "sources" / slug)], check=True)
            if arch == "amd64":
                subprocess.run(["python3", "-I", str(root / "tools/check_maintenance_image.py"), tag], check=True)
            path = output / (slug + "-" + arch + ".tar")
            subprocess.run(["docker", "save", "--output", str(path), tag], check=True)
            image_id = run("docker", "image", "inspect", "--format", "{{.Id}}", tag)
            check_image_archive(path, root, slug, arch, commit, image_id)
            records.append({"slug": slug, "arch": arch, "tag": tag,
                            "image_id": image_id,
                            "archive": path.name, "sha256": file_sha(path)})
    record = {"format": 1, "repository": policy["repository"], "commit": commit,
              "simulation": True, "images": records}
    (output / "tested.json").write_bytes(canonical(record))
    return record


def file_sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tested_checked(tested, policy, commit):
    if (set(tested) != {"format", "repository", "commit", "simulation", "images"} or tested["format"] != 1
            or tested["simulation"] is not True or tested["commit"] != commit or tested["repository"] != policy["repository"]):
        raise ValueError("tested image source mismatch")
    expected = {(slug, arch) for slug in APPS for arch in ARCHES}
    seen = set()
    for record in tested["images"]:
        slug, arch = record["slug"], record["arch"]
        if (slug, arch) not in expected or (slug, arch) in seen:
            raise ValueError("unexpected tested architecture")
        seen.add((slug, arch))
        if (set(record) != {"slug", "arch", "tag", "image_id", "archive", "sha256"}
                or record["archive"] != slug + "-" + arch + ".tar"
                or record["tag"] != image_name(policy, slug) + ":" + APPS[slug][1] + "-" + arch
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", record["image_id"])
                or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])):
            raise ValueError("tested image record invalid")
    if seen != expected:
        raise ValueError("all four tested images required")


def publication_allowed(policy, commit, confirmation, env):
    if (policy["publication_enabled"] is not True or policy["repository"].lower().startswith("example-")
            or confirmation != "PUBLISH-SIMULATION-" + commit or env.get("GITHUB_REPOSITORY") != policy["repository"]
            or env.get("GITHUB_SHA") != commit or env.get("GITHUB_REF") != "refs/heads/main"
            or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or env.get("CATALOG_PROTECTED_ENVIRONMENT") != "catalog-publication"):
        raise ValueError("publication not explicitly enabled and approved")


def absent(tag, policy=None):
    result = subprocess.run(["docker", "manifest", "inspect", tag], capture_output=True, text=True, timeout=60)
    if result.returncode == 0:
        raise ValueError("version tag already exists; never replace")
    error = result.stderr.lower()
    if not any(message in error for message in ("manifest unknown", "no such manifest", "name unknown")):
        # GHCR may answer denied for a package that has never existed. Use the
        # authenticated package API, not an interpretation of an auth error.
        if policy is not None and any(message in error for message in ("denied", "unauthorized")):
            owner, repository = policy["repository"].split("/")
            slug = tag.split(":")[-2].rsplit("/", 1)[-1]
            if slug in APPS and tag.startswith(image_name(policy, slug) + ":"):
                owner_type = json.loads(run("gh", "api", "users/" + owner)).get("type")
                if owner_type in {"User", "Organization"}:
                    endpoint = ("orgs/" if owner_type == "Organization" else "users/") + owner + "/packages/container/" + repository.lower() + "%2F" + slug
                    found = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True, timeout=60)
                    if found.returncode != 0 and re.search(r"\bHTTP 404\b", found.stderr):
                        return
        raise ValueError("cannot establish tag absence; publication refused")


def protected_environment(policy):
    data = json.loads(run("gh", "api", "repos/" + policy["repository"] + "/environments/catalog-publication"))
    if data.get("can_admins_bypass") is not False:
        raise ValueError("publication environment must disable administrator bypass")
    if not any(rule.get("type") == "required_reviewers" and rule.get("reviewers")
               for rule in data.get("protection_rules", [])):
        raise ValueError("protected publication environment with a required reviewer must already exist")


def publish(root, artifacts, output, commit, confirmation):
    root, artifacts, output = Path(root).resolve(), Path(artifacts).resolve(), Path(output).absolute()
    policy = validate(root)
    publication_allowed(policy, commit, confirmation, os.environ)
    exact_commit(root, commit)
    protected_environment(policy)
    tested = read_json(artifacts / "tested.json")
    tested_checked(tested, policy, commit)
    if {item.name for item in artifacts.iterdir()} != {"tested.json"} | {item["archive"] for item in tested["images"]}:
        raise ValueError("unexpected tested artifact content")
    if output.exists() or output.resolve() != output or root == output or root in output.parents:
        raise ValueError("new release output outside checkout required")
    # Authenticate only through the future workflow; no registry credential or token is handled here.
    for record in tested["images"]:
        path = artifacts / record["archive"]
        if (path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1
                or path.stat().st_size > 256 * 1024 * 1024 or file_sha(path) != record["sha256"]):
            raise ValueError("tested archive integrity mismatch")
        check_image_archive(path, root, record["slug"], record["arch"], commit, record["image_id"])
        absent(record["tag"], policy)
    for slug in APPS:
        absent(image_name(policy, slug) + ":" + APPS[slug][1], policy)
    # Loading archives is allowed only after exact checks. These are CI's own bounded build artifacts.
    for record in tested["images"]:
        subprocess.run(["docker", "load", "--input", str(artifacts / record["archive"])], check=True)
        if run("docker", "image", "inspect", "--format", "{{.Id}}", record["tag"]) != record["image_id"]:
            raise ValueError("loaded image ID mismatch")
        meta = json.loads(run("docker", "image", "inspect", record["tag"]))[0]
        labels = meta["Config"]["Labels"]
        if (meta["Architecture"] != ARCHES[record["arch"]] or labels.get("org.opencontainers.image.revision") != commit
                or labels.get("io.hass.arch") != record["arch"] or labels.get("io.hass.version") != APPS[record["slug"]][1]):
            raise ValueError("image source or architecture mismatch")
    output.mkdir(mode=0o700)
    for record in tested["images"]:
        subprocess.run(["docker", "push", record["tag"]], check=True)
    released = {}
    for slug in APPS:
        tag = image_name(policy, slug) + ":" + APPS[slug][1]
        children = [record["tag"] for record in tested["images"] if record["slug"] == slug]
        subprocess.run(["docker", "buildx", "imagetools", "create", "--tag", tag, *children], check=True)
        index = json.loads(run("docker", "buildx", "imagetools", "inspect", "--raw", tag))
        platforms = {item.get("platform", {}).get("architecture") for item in index.get("manifests", [])}
        if platforms != {"amd64", "arm64"}:
            raise ValueError("registry manifest architecture mismatch")
        expected_children = {json.loads(run("docker", "buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", child))["digest"] for child in children}
        if {item.get("digest") for item in index["manifests"]} != expected_children or len(index["manifests"]) != 2:
            raise ValueError("registry manifest differs from published images")
        descriptor = json.loads(run("docker", "buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", tag))
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", descriptor.get("digest", "")):
            raise ValueError("registry descriptor digest missing")
        released[slug] = {"image": image_name(policy, slug), "version": APPS[slug][1], "digest": descriptor["digest"]}
    record = {"format": 1, "repository": policy["repository"], "commit": commit, "simulation": True, "images": released}
    (output / "release-record.json").write_bytes(canonical(record))
    # Metadata is not applied to the catalogue. It is a separate reviewed promotion PR.
    return record


def release_checked(record, policy, exact_versions=True):
    if (set(record) != {"format", "repository", "commit", "simulation", "images"} or record["format"] != 1
            or record["repository"] != policy["repository"] or record["simulation"] is not True
            or not re.fullmatch(r"[0-9a-f]{40}", record["commit"]) or set(record["images"]) != set(APPS)):
        raise ValueError("invalid release record")
    for slug, value in record["images"].items():
        if (set(value) != {"image", "version", "digest"} or value["image"] != image_name(policy, slug)
                or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["version"])
                or (exact_versions and value["version"] != APPS[slug][1])
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"])):
            raise ValueError("invalid released digest")


def approved_config(root, policy, slug):
    config = config_checked(read_json(Path(root) / "sources" / slug / "app.json"), slug)
    # Every version is marked breaking so HA requires a manual update even if auto-update was enabled accidentally.
    return {**config, "image": image_name(policy, slug), "breaking_versions": [APPS[slug][1]]}


def verify_registry(record, policy):
    # Empty Docker configuration ensures that the Green will not need registry credentials.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="catalog-anonymous-") as folder:
        for slug, value in record["images"].items():
            tag = value["image"] + ":" + value["version"]
            # Built-in manifest command works even when the buildx plugin is in ~/.docker.
            run("docker", "--config", folder, "manifest", "inspect", value["image"] + "@" + value["digest"])
            descriptor = json.loads(run("docker", "buildx", "imagetools", "inspect",
                                        "--format", "{{json .Manifest}}", tag))
            if descriptor.get("digest") != value["digest"]:
                raise ValueError("public registry tag differs from approved digest")
            subprocess.run(["gh", "attestation", "verify", "oci://" + value["image"] + "@" + value["digest"],
                "--repo", policy["repository"], "--signer-workflow", policy["repository"] + "/.github/workflows/publish.yml",
                "--source-digest", record["commit"], "--deny-self-hosted-runners"], check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def promote(root, release, output):
    root, output = Path(root).resolve(), Path(output).absolute()
    policy, record = validate(root), read_json(release)
    if policy["publication_enabled"] is not True:
        raise ValueError("catalogue not approved for publication")
    release_checked(record, policy)
    exact_commit(root, record["commit"])
    if output.exists() or output.resolve() != output or root == output or root in output.parents:
        raise ValueError("new promotion output outside checkout required")
    verify_registry(record, policy)
    output.mkdir(mode=0o700)
    for slug in APPS:
        target = output / slug
        target.mkdir()
        (target / "config.yaml").write_bytes(canonical(approved_config(root, policy, slug)))
        (target / "DOCS.md").write_text("# Simulation only\n\nInstall and start manually after review. No Home Assistant/Supervisor permissions, network, VPN or production writes. Keep protection enabled and auto-update, autostart and watchdog disabled. Existing apps are independent.\n")
        (target / "CHANGELOG.md").write_text(f"# {APPS[slug][1]}\n\nSimulation only. Public source commit: `{record['commit']}`. See release-record.json and verified build attestations.\n")
    (output / "release-record.json").write_bytes(canonical(record))
    with zipfile.ZipFile(output / "catalog-promotion.zip", "w", compression=zipfile.ZIP_STORED) as bundle:
        for path in sorted(output.rglob("*")):
            if path.is_file() and path.suffix != ".zip":
                bundle.write(path, path.relative_to(output))
    return {"promotion_prepared": True, "applied": False, "installed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("validate", "build", "publish", "promote"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--confirmation")
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--release", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "validate":
            policy = validate(args.root)
            result = {"valid": True, "simulation": True, "publication_enabled": policy["publication_enabled"]}
        elif args.operation == "build":
            result = build(args.root, args.output, args.commit)
        elif args.operation == "publish":
            result = publish(args.root, args.artifacts, args.output, args.commit, args.confirmation)
        else:
            result = promote(args.root, args.release, args.output)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError, tarfile.TarError, subprocess.SubprocessError):
        print(json.dumps({"refused": True, "reason": "catalogue verification or operation failed"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
