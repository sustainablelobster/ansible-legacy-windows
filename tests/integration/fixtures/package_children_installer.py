"""Spawn a journal-owned installer child and grandchild with detached streams."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import subprocess
import sys
import time
import types

# The built-in Windows binding is part of the pinned interpreter, not ctypes.
import _winapi  # pylint: disable=import-error


def receipt(root, role, parent, **extra):
    """Write the exact owned process identity and additional operation fields.

    :param str root: Journal-owned workspace.
    :param str role: Parent, child or grandchild.
    :param int parent: Recorded parent PID; zero for the installer root.
    :param extra: Operation-specific receipt fields.
    """
    data = {
        "workspace": root,
        "role": role,
        "pid": os.getpid(),
        "parent": parent,
        "utc": time.time(),
        "cwd": os.getcwd(),
    }
    data.update(extra)
    with open(os.path.join(root, role + ".json"), "w", encoding="utf-8") as stream:
        json.dump(data, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def spawn(root, role, operation, code, delay):
    """Start the next owned generation without inherited output streams.

    :param str root: Journal-owned workspace.
    :param str role: Next generation's role.
    :param str operation: Install or remove the owned registry entry.
    :param str code: Requested installer root return code.
    :param str delay: Grandchild delay in seconds.
    :returns: Exact newly started process ID after closing our native handles.
    :rtype: int
    """
    command = subprocess.list2cmdline(
        [
            sys.executable,
            "-S",
            __file__,
            root,
            role,
            operation,
            code,
            delay,
            str(os.getpid()),
        ]
    )
    # No inherited handles and no console means no unused root/SSH pipe can
    # keep output EOF pending. No BREAKAWAY flag: children still inherit the
    # actual installer job. CPython3.4's built-in binding owns this ABI.
    process, thread, pid, _tid = _winapi.CreateProcess(
        sys.executable,
        command,
        None,
        None,
        False,
        0x08000000,
        None,
        root,
        subprocess.STARTUPINFO(),
    )
    _winapi.CloseHandle(thread)
    _winapi.CloseHandle(process)
    return pid


def main():
    """Run only the exact workspace's guarded owned installer operation.

    :returns: This generation's intentionally distinct return code.
    :rtype: int
    """
    assert sys.version_info[:3] == (3, 4, 4)
    root, role, operation, code, delay, parent = sys.argv[1:]
    with open(
        os.path.join(root, "registry-package-journal.json"), encoding="utf-8"
    ) as stream:
        journal = json.load(stream)
    assert journal["workspace"] == root and not journal["verified"]
    assert os.path.basename(root).startswith(
        "legacy-windows-package-registry-test-children-"
    )
    assert operation in ("install", "remove") and role in (
        "parent",
        "child",
        "grandchild",
    )
    if role == "parent":
        child = spawn(root, "child", operation, code, delay)
        receipt(root, role, int(parent), child=child, code=int(code))
        # Establish both generations before root exit; neither descendant keeps
        # the package's stdout/stderr handles, so only a tree watcher waits them.
        deadline = time.monotonic() + 5
        while not os.path.exists(os.path.join(root, "grandchild.json")):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        print("owned parent stdout")
        sys.stderr.write("owned parent stderr\n")
        return int(code)
    if role == "child":
        child = spawn(root, "grandchild", operation, code, delay)
        receipt(root, role, int(parent), child=child, code=19)
        return 19
    receipt(root, role, int(parent), code=29)
    time.sleep(float(delay))
    program = os.path.join(root, "registry_installer.py")
    with open(program, encoding="utf-8") as stream:
        source = stream.read()
    installer = types.ModuleType("owned_registry_installer")
    # Execute the unchanged maintained installer in-process: the detached
    # grandchild, not an extra unobserved fourth generation, makes the effect.
    # pylint: disable=exec-used
    exec(
        compile(source, program, "exec"), installer.__dict__
    )  # pylint: disable=exec-used
    sys.argv = [program, root, operation, "HKCU", "native", "UninstallString"]
    assert installer.__dict__["main"]() == 0
    return 29


if __name__ == "__main__":
    sys.exit(main())
