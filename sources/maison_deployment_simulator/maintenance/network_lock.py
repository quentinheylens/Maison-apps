"""Irreversible process/descendant socket denial on Linux AMD64 and ARM64.

No capability, external library, daemon, network namespace or network probe.
The normal runtime and fixed healthcheck both install this filter. Operator
Docker exec is outside this process boundary; this is not network:none on HA OS.
"""

import ctypes
import errno
import platform
import socket
import sys
import os
import stat


class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("instructions", ctypes.POINTER(Filter))]


def lock_network():
    if sys.platform != "linux":
        raise RuntimeError("Linux network sandbox required")
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        audit_arch, denied = 0xC000003E, {41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 53, 288, 299, 307}
    elif machine in {"aarch64", "arm64"}:
        audit_arch, denied = 0xC00000B7, {198, 199, 200, 201, 202, 203, 206, 207, 210, 211, 212, 242, 243, 269}
    else:
        raise RuntimeError("unreviewed syscall architecture")
    # io_uring can submit network operations without the ordinary socket calls.
    denied |= {425, 426, 427, 438}  # Also prevent pidfd_getfd socket theft.
    deny = 0x00050000 | errno.EPERM
    instructions = [(0x20, 0, 0, 4), (0x15, 1, 0, audit_arch), (0x06, 0, 0, 0x80000000),
                    (0x20, 0, 0, 0), (0x35, 0, 1, 0x40000000), (0x06, 0, 0, deny)]
    for number in sorted(denied):
        instructions.extend([(0x15, 0, 1, number), (0x06, 0, 0, deny)])
    instructions.append((0x06, 0, 0, 0x7FFF0000))
    array = (Filter * len(instructions))(*(Filter(*i) for i in instructions))
    program = Program(len(instructions), array)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    # NoNewPrivs prevents privilege gain on exec and permits unprivileged seccomp.
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.addressof(program), 0, 0) != 0:
        raise RuntimeError("network sandbox unavailable")
    # No pre-existing network descriptors may survive exec into the runtime.
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        try:
            if fd > 2:
                os.close(fd)
            elif stat.S_ISSOCK(os.fstat(fd).st_mode):
                raise RuntimeError("socket-backed standard descriptor refused")
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


def assert_network_locked():
    # Socket creation is tested only; no connect, DNS, address or packet is used.
    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
        try:
            test = socket.socket(family, socket.SOCK_STREAM)
        except OSError as error:
            if error.errno == errno.EPERM:
                continue
            raise RuntimeError("network sandbox probe inconclusive") from None
        test.close()
        raise RuntimeError("network sandbox did not deny socket creation")
    try:
        pair = socket.socketpair()
    except OSError as error:
        if error.errno == errno.EPERM:
            return True
        raise RuntimeError("network sandbox probe inconclusive") from None
    for member in pair:
        member.close()
    raise RuntimeError("network sandbox did not deny socketpair")
