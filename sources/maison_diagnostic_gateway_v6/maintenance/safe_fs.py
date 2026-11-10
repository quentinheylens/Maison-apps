"""Descriptor-relative bounded I/O for a private, explicitly marked sandbox."""

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path, PurePosixPath

MAX_FILE = 512 * 1024
MARKER = {"format": 1, "purpose": "maison-offline-simulation", "production": False}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def relative(value):
    if not isinstance(value, str) or not value or len(value) > 240:
        raise ValueError("invalid relative path")
    path = PurePosixPath(value)
    if (str(path) != value or path.is_absolute() or ".." in path.parts
            or any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in value)
            or any(p.startswith(".") for p in path.parts)):
        raise ValueError("unsafe path")
    return path.parts


class Tree:
    def __init__(self, root):
        self.root = Path(root)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def close(self):
        os.close(self.fd)

    def usage(self):
        count, size = 0, 0
        def walk(fd):
            nonlocal count, size
            with os.scandir(fd) as entries:
                for entry in entries:
                    count += 1
                    if count > 2000:
                        raise ValueError("workspace file count exceeded")
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        try:
                            walk(child)
                        finally:
                            os.close(child)
                    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise ValueError("unsafe workspace object")
                    else:
                        size += info.st_size
            return size
        return walk(self.fd)

    def mkdir(self, name):
        fd = os.dup(self.fd)
        try:
            for part in relative(name):
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = new
        finally:
            os.close(fd)

    def parent(self, name):
        parts = relative(name)
        fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = new
            return fd, parts[-1]
        except BaseException:
            os.close(fd)
            raise

    def read(self, name):
        parent, leaf = self.parent(name)
        try:
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
                    raise ValueError("file type, hardlink or size refused")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    data = stream.read(MAX_FILE + 1)
                if len(data) > MAX_FILE:
                    raise ValueError("file exceeds bound")
                return data
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    def write(self, name, data, expected=None, *, new=False):
        if not isinstance(data, bytes) or len(data) > MAX_FILE:
            raise ValueError("write exceeds bound")
        parent, leaf = self.parent(name)
        temporary = "safe-new-" + uuid.uuid4().hex
        try:
            if expected is not None and digest(self.read(name)) != expected:
                raise ValueError("concurrent file change")
            try:
                info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("unsafe destination object")
                if new:
                    raise ValueError("destination already exists")
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            # Recheck immediately before replacement. Cooperating writers also
            # hold the transaction flock. This is not a multi-file atomic CAS.
            if expected is not None and digest(self.read(name)) != expected:
                raise ValueError("concurrent file change")
            os.replace(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)


class Sandbox:
    """Only disposable temporary workspaces; no alternative production root."""
    def __init__(self, root):
        root = Path(root).absolute()
        if root.resolve() != root or root == Path("/tmp") or Path("/tmp") not in root.parents:
            raise ValueError("simulation workspace must be a physical child of /tmp")
        self.tree = Tree(root)
        try:
            if os.fstat(self.tree.fd).st_mode & 0o077:
                raise ValueError("simulation workspace must be private")
            if json.loads(self.tree.read("sandbox.json")) != MARKER:
                raise ValueError("invalid simulation marker")
        except (FileNotFoundError, json.JSONDecodeError):
            self.tree.close()
            raise ValueError("simulation marker unavailable") from None
        except BaseException:
            self.tree.close()
            raise
        self.root = root

    @classmethod
    def create(cls, root, files):
        root = Path(root).absolute()
        if root.exists() or root.resolve() != root or Path("/tmp") not in root.parents:
            raise ValueError("use a new physical temporary directory")
        root.mkdir(mode=0o700)
        for folder in ("live", "staged", "backups", "state"):
            (root / folder).mkdir(mode=0o700)
        (root / "sandbox.json").write_bytes(canonical(MARKER))
        os.chmod(root / "sandbox.json", 0o600)
        for name, content in files.items():
            relative(name)
            target = root / "live" / name
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            target.write_bytes(content)
            os.chmod(target, 0o600)
        return cls(root)
