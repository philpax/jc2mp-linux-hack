#!/usr/bin/env python3
"""Work around the JC2-MP launcher crash on Proton without changing game files.

Steam > JC2-MP > Properties > Launch Options:
    python3 "/absolute/path/to/jc2mp_launch.py" -- %command%

Requires Linux x86-64 and 64-bit Python 3.10+. No third-party dependencies.
Remove the launch option to disable the workaround. Stop any existing JC2-MP
processes before launching. A ptrace restriction may prevent the script from
working; the script does not change system security settings or require root.

The launcher injects Jcmp.dll into a suspended JustCause2.exe, then calls
VirtualFree on the remote allocation's address in its own process. Under Proton
that address can coincide with the launcher's heap. Freeing the heap crashes
the launcher before ResumeThread, leaving the game suspended without a window.

The script traces the launch command's descendants and replaces the bad
VirtualFree call and argument pushes with NOPs before the launcher entry point.
The remote allocation (one page) remains until game exit. The launcher's DLL
injection wait is extended from 10 to 60 seconds: Steam's full launch path can
exceed the original timeout, which otherwise leaves the game suspended.

Jcmp.dll also copies a function's first five bytes without relocating relative
jumps. Wine's memcpy export starts with such a jump, so the copied trampoline
jumps into unrelated heap data. The script resolves that jump before Jcmp builds
its hook.

The base game's GUI initialization also checks for COM registration
{808C8FA6-C09F-4CD0-85BF-78DF85877A7B}. It is absent in the tested Wine prefix;
the failure path overwrites a return address and exits the game during loading.
The script makes that check return success, then detaches all traced tasks.
All three workarounds are in memory only; no game files or registry keys change.

Known mod build: Steam 1867542. Tested with Proton Experimental 11.0 (20261014).
The launcher, mod DLL and base game are hash-checked; unsupported builds or Wine
function prologues are rejected. Main menu interaction and online play are verified.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import os
import platform
import signal
import struct
import sys
from pathlib import Path

BUILD_SHA256 = "aee951a154e82ce9c873ffff17037d550a563a55a22d0c8a1a4bcd19ac1ff368"
PATCH_RVA = 0x3741
JCMP_SHA256 = "c4868f28aca9503b04d61a95925decee2945f99e8dbd4c064cd492ffc369edd4"
HOOK_BUILDER_RVA = 0x1D6690
GAME_SHA256 = "1966f28b80c8ac6e57e7e059526294de97fcd99aa11c444c601963e12bd94ff8"
GAME_BASE = 0x400000
GUI_CHECK_RVA = 0x412A0
GUI_CHECK_ORIGINAL = bytes.fromhex("81 ec 84 00 00 00")
ORIGINAL = bytes.fromhex("68 00 80 00 00 6a 00 57 ff 15 28 b0 40 00")

PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5
PTRACE_POKEUSER = 6
PTRACE_CONT = 7
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_DETACH = 17
PTRACE_SYSCALL = 24
PTRACE_GETEVENTMSG = 0x4201
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207
PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_TRACEFORK = 2
PTRACE_O_TRACEVFORK = 4
PTRACE_O_TRACECLONE = 8
PTRACE_O_TRACEEXEC = 16
PTRACE_O_EXITKILL = 0x100000
PTRACE_EVENT_EXEC = 4
PTRACE_EVENT_STOP = 128
WAIT_ALL = 0x40000000
# Linux x86-64 struct user: u_debugreg[0], [6], [7]. Compat tasks use this ABI too.
DR0, DR6, DR7 = 848, 896, 904
WORD_SIZE = ctypes.sizeof(ctypes.c_long)


class Registers(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "r15",
            "r14",
            "r13",
            "r12",
            "rbp",
            "rbx",
            "r11",
            "r10",
            "r9",
            "r8",
            "rax",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "orig_rax",
            "rip",
            "cs",
            "eflags",
            "rsp",
            "ss",
            "fs_base",
            "gs_base",
            "ds",
            "es",
            "fs",
            "gs",
        )
    ]


def ptrace(request, pid, address=0, data=0):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = libc.ptrace(request, pid, ctypes.c_void_p(address), ctypes.c_void_p(data))
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, f"ptrace({request:#x}, {pid}): {os.strerror(error)}")
    return result


def read_memory(pid, address, size):
    result = bytearray()
    while len(result) < size:
        word = ptrace(PTRACE_PEEKDATA, pid, address + len(result))
        result.extend((word & ((1 << (8 * WORD_SIZE)) - 1)).to_bytes(WORD_SIZE, "little"))
    return bytes(result[:size])


def write_memory(pid, address, data):
    for offset in range(0, len(data), WORD_SIZE):
        chunk = data[offset : offset + WORD_SIZE]
        at = address + offset
        original = read_memory(pid, at, WORD_SIZE)
        word = int.from_bytes(chunk + original[len(chunk) :], "little")
        ptrace(PTRACE_POKEDATA, pid, at, word)


def inspect_launcher(path):
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != BUILD_SHA256:
        raise ValueError(f"unsupported launcher SHA-256 {digest}; no process was patched")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise ValueError("launcher has no PE header")
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x10B:
        raise ValueError("launcher is not a 32-bit PE executable")
    entry_rva, image_base = (
        struct.unpack_from("<II", data, optional + 16)[0],
        struct.unpack_from("<I", data, optional + 28)[0],
    )
    stat = path.stat()
    return entry_rva, image_base, (os.major(stat.st_dev), os.minor(stat.st_dev), stat.st_ino)


def mapped_base(maps, identity):
    for line in maps.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 5 or int(fields[2], 16) != 0:
            continue
        major, minor = (int(part, 16) for part in fields[3].split(":"))
        mapped = (major, minor, int(fields[4]))
        # Btrfs can expose different device numbers through stat and maps.
        if mapped == identity or (
            mapped[2] == identity[2]
            and len(fields) == 6
            and fields[5].endswith("/JcmpLauncher.exe")
        ):
            return int(fields[0].split("-")[0], 16)
    return None


def expected_bytes(base, preferred_base):
    pointer = struct.unpack_from("<I", ORIGINAL, 10)[0] + base - preferred_base
    return ORIGINAL[:10] + struct.pack("<I", pointer)


def patch_launcher(pid, base, preferred_base):
    address = base + PATCH_RVA
    expected = expected_bytes(base, preferred_base)
    actual = read_memory(pid, address, len(expected))
    if actual != expected:
        raise ValueError(
            f"instruction mismatch at {address:#x}: expected {expected.hex()}, got {actual.hex()}"
        )
    # Skip the argument pushes and VirtualFree call together to preserve ESP.
    # The remote DLL-path allocation remains until the game exits (one page).
    replacement = b"\x90" * len(expected)
    write_memory(pid, address, replacement)
    if read_memory(pid, address, len(replacement)) != replacement:
        raise ValueError("in-memory patch verification failed")
    wait_site = base + 0x3719
    wait_original = bytes.fromhex("68 10 27 00 00")
    if read_memory(pid, wait_site, 5) != wait_original:
        raise ValueError("unsupported injection wait instruction")
    # Steam's full launch path can take longer than the original ten seconds
    # to finish injection. A timeout exits the launcher without ResumeThread.
    wait_replacement = b"\x68" + struct.pack("<I", 60_000)
    write_memory(pid, wait_site, wait_replacement)
    if read_memory(pid, wait_site, 5) != wait_replacement:
        raise ValueError("injection wait workaround verification failed")
    print(f"jc2mp-launch: patched PID {pid} at {address:#x}; game files unchanged", flush=True)


def set_breakpoint(pid, address):
    # A hardware execution breakpoint stops the launcher at its entry point.
    # The section is still zero-filled when the mapping appears, so the entry
    # cannot be guarded with an int3 written at map time.
    ptrace(PTRACE_POKEUSER, pid, DR0, address)
    ptrace(PTRACE_POKEUSER, pid, DR6, 0)
    ptrace(PTRACE_POKEUSER, pid, DR7, 1)


def clear_breakpoint(pid):
    ptrace(PTRACE_POKEUSER, pid, DR7, 0)
    ptrace(PTRACE_POKEUSER, pid, DR0, 0)
    ptrace(PTRACE_POKEUSER, pid, DR6, 0)


def trace_launch(command, launcher, timeout):
    entry_rva, preferred_base, identity = inspect_launcher(launcher)
    jcmp = launcher.with_name("Jcmp.dll")
    if hashlib.sha256(jcmp.read_bytes()).hexdigest() != JCMP_SHA256:
        raise ValueError("unsupported Jcmp.dll build; no process was patched")
    game_tasks = {}
    hook_fixed = False
    gate_read, gate_write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(gate_write)
            os.read(gate_read, 1)
            os.close(gate_read)
            os.execvp(command[0], command)
        except OSError as error:
            print(f"jc2mp-launch: exec failed: {error}", file=sys.stderr, flush=True)
            os._exit(127)
    os.close(gate_read)
    tracked = {child}
    syscall_tasks = set()
    breakpoints = {}
    patched = False
    detaching = False
    child_status = None

    def deadline(_signum, _frame):
        raise TimeoutError(f"launcher patch did not complete within {timeout} seconds")

    old_alarm = signal.signal(signal.SIGALRM, deadline)
    try:
        options = (
            PTRACE_O_TRACESYSGOOD
            | PTRACE_O_TRACEFORK
            | PTRACE_O_TRACEVFORK
            | PTRACE_O_TRACECLONE
            | PTRACE_O_TRACEEXEC
            | PTRACE_O_EXITKILL
        )
        ptrace(PTRACE_SEIZE, child, 0, options)
        signal.alarm(timeout)
        os.close(gate_write)
        gate_write = None
        while tracked:
            pid, status = os.waitpid(-1, WAIT_ALL)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                tracked.discard(pid)
                syscall_tasks.discard(pid)
                breakpoints.pop(pid, None)
                if pid == child:
                    child_status = status
                continue
            if not os.WIFSTOPPED(status):
                continue
            tracked.add(pid)
            event = status >> 16
            stopped_signal = os.WSTOPSIG(status)
            if event in (1, 2, 3):
                spawned = ctypes.c_ulong()
                ptrace(PTRACE_GETEVENTMSG, pid, 0, ctypes.addressof(spawned))
                tracked.add(spawned.value)
                if pid in game_tasks and not hook_fixed:
                    game_tasks[spawned.value] = game_tasks[pid]
            if event == PTRACE_EVENT_EXEC:
                # Wine maps Windows executables after exec; observe its mapping
                # syscalls until the launcher appears, then break at its entry.
                executable = os.readlink(f"/proc/{pid}/exe")
                argv = Path(f"/proc/{pid}/cmdline").read_bytes().lower().split(b"\0")
                is_launcher = any(arg.endswith(b"jcmplauncher.exe") for arg in argv)
                is_bootstrap = any(arg.endswith(b"steam.exe") for arg in argv)
                if any(arg.endswith(b"justcause2.exe") for arg in argv) and not hook_fixed:
                    game_tasks[pid] = None
                if (
                    Path(executable).name
                    in ("wine", "wine64", "wine-preloader", "wine64-preloader")
                    and is_launcher
                    and not is_bootstrap
                ):
                    syscall_tasks.add(pid)
            if pid in game_tasks and not hook_fixed:
                if game_tasks[pid] is None:
                    maps = Path(f"/proc/{pid}/maps").read_text()
                    entries = [
                        line
                        for line in maps.splitlines()
                        if line.endswith("/Jcmp.dll") and int(line.split()[2], 16) == 0
                    ]
                    if entries:
                        base = int(entries[0].split("-")[0], 16)
                        set_breakpoint(pid, base + HOOK_BUILDER_RVA)
                        game_tasks[pid] = base
                elif stopped_signal == signal.SIGTRAP and event == 0:
                    registers = Registers()
                    ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(registers))
                    if registers.rip == game_tasks[pid] + HOOK_BUILDER_RVA:
                        original = registers.rcx
                        code = read_memory(pid, original, 5)
                        if code[0] != 0xE9:
                            raise ValueError("unsupported Wine function prologue")
                        target = original + 5 + struct.unpack_from("<i", code, 1)[0]
                        # Jcmp copies five bytes without relocating a relative jump.
                        # Hook Wine's implementation, not its jump-only export stub.
                        if read_memory(pid, target, 5) != bytes.fromhex("55 89 e5 57 56"):
                            raise ValueError("unsupported Wine implementation prologue")
                        maps = Path(f"/proc/{pid}/maps").read_text().splitlines()
                        game = next(
                            (
                                line.split(maxsplit=5)[5]
                                for line in maps
                                if line.endswith("/JustCause2.exe")
                                and int(line.split("-")[0], 16) == GAME_BASE
                            ),
                            None,
                        )
                        if (
                            game is None
                            or hashlib.sha256(Path(game).read_bytes()).hexdigest() != GAME_SHA256
                        ):
                            raise ValueError("unsupported JustCause2.exe build or image base")
                        check = GAME_BASE + GUI_CHECK_RVA
                        if read_memory(pid, check, len(GUI_CHECK_ORIGINAL)) != GUI_CHECK_ORIGINAL:
                            raise ValueError("unsupported GUI registration check prologue")
                        # This check requires a COM registration absent in Wine. Its
                        # failure path overwrites its return address and exits the game.
                        # Return success without changing the prefix registry.
                        replacement = bytes.fromhex("b0 01 c3 90 90 90")
                        write_memory(pid, check, replacement)
                        if read_memory(pid, check, len(replacement)) != replacement:
                            raise ValueError("GUI registration workaround verification failed")
                        print("jc2mp-launch: patched GUI registration check", flush=True)
                        registers.rcx = target
                        ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(registers))
                        clear_breakpoint(pid)
                        hook_fixed = True
                        detaching = True
                        stopped_signal = 0
                        print(
                            f"jc2mp-launch: resolved Wine hook {original:#x} -> {target:#x}",
                            flush=True,
                        )
                        for other in tracked - {pid}:
                            try:
                                ptrace(PTRACE_INTERRUPT, other)
                            except OSError as error:
                                if error.errno != errno.ESRCH:
                                    raise
            if pid in syscall_tasks and pid not in breakpoints:
                registers = Registers()
                ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(registers))
                mapping_calls = (90, 125, 192) if registers.cs == 0x23 else (9, 10)
                base = None
                if registers.orig_rax in mapping_calls:
                    base = mapped_base(Path(f"/proc/{pid}/maps").read_text(), identity)
                if base is not None:
                    breakpoints[pid] = base
                    set_breakpoint(pid, base + entry_rva)
                    syscall_tasks.discard(pid)
            if stopped_signal == signal.SIGTRAP and event == 0 and pid in breakpoints:
                registers = Registers()
                ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(registers))
                base = breakpoints[pid]
                if registers.rip == base + entry_rva:
                    patch_launcher(pid, base, preferred_base)
                    clear_breakpoint(pid)
                    del breakpoints[pid]
                    patched = True
                    stopped_signal = 0
            deliver = 0 if event or stopped_signal == (signal.SIGTRAP | 0x80) else stopped_signal
            if detaching:
                if pid in breakpoints:
                    clear_breakpoint(pid)
                    del breakpoints[pid]
                # The entry breakpoint belongs to this wrapper, not Wine.
                if stopped_signal == signal.SIGTRAP:
                    deliver = 0
                if pid in game_tasks and game_tasks[pid] is not None:
                    clear_breakpoint(pid)
                ptrace(PTRACE_DETACH, pid, 0, deliver)
                tracked.discard(pid)
            else:
                watch_maps = pid in syscall_tasks or (
                    pid in game_tasks and game_tasks[pid] is None and not hook_fixed
                )
                request = PTRACE_SYSCALL if watch_maps else PTRACE_CONT
                try:
                    ptrace(request, pid, 0, deliver)
                except OSError as error:
                    if error.errno != errno.ESRCH:
                        raise
                    tracked.discard(pid)
        signal.alarm(0)
        if not patched or not hook_fixed:
            raise RuntimeError("launch ended before both workarounds could be applied")
        if child_status is None:
            _, child_status = os.waitpid(child, 0)
        code = os.waitstatus_to_exitcode(child_status)
        return 128 - code if code < 0 else code
    except BaseException:
        # Stop only this command's traced descendants. Never search for or kill
        # an existing Wine session belonging to another launch.
        for pid in tracked | ({child} if child_status is None else set()):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        raise
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_alarm)
        if gate_write is not None:
            os.close(gate_write)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--launcher", type=Path, help="path to JcmpLauncher.exe")
    parser.add_argument(
        "--timeout", type=int, default=90, help="patch deadline in seconds (default: 90)"
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a launch command is required after --")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if sys.platform != "linux" or platform.machine() != "x86_64" or WORD_SIZE != 8:
        parser.error("the in-memory patch requires Linux x86-64 with 64-bit Python")
    launcher = args.launcher
    if launcher is None:
        install = os.environ.get("STEAM_COMPAT_INSTALL_PATH")
        if install:
            launcher = Path(install) / "JcmpLauncher.exe"
        else:
            launcher = next(
                (Path(arg) for arg in command if Path(arg).name == "JcmpLauncher.exe"), None
            )
    if launcher is None:
        parser.error("set --launcher or run from this game's Steam launch options")
    try:
        return trace_launch(command, launcher.resolve(strict=True), args.timeout)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"jc2mp-launch: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
