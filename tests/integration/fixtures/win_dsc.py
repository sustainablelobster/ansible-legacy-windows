"""Journal and observe only the owned classic DSC File test workspace."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import json
import os
import sys
import tempfile


# This fixture runs alone through stdin on the guest. Keep its security snapshot
# and atomic journal self-contained; importing a test package would change what
# the recovery test has to stage and protect.
# pylint: disable=duplicate-code
def _security(path):
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.GetFileSecurityW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    api.GetFileSecurityW.restype = ctypes.c_int
    needed = ctypes.c_uint32()
    api.GetFileSecurityW(path, 7, None, 0, ctypes.byref(needed))
    assert needed.value and ctypes.get_last_error() == 122
    buffer = ctypes.create_string_buffer(needed.value)
    if not api.GetFileSecurityW(path, 7, buffer, needed.value, ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    return base64.b64encode(buffer.raw[: needed.value]).decode("ascii")


def _file(path):
    if not os.path.exists(path):
        return None
    stat = os.stat(path)
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    api.GetFileAttributesW.restype = ctypes.c_uint32
    attributes = api.GetFileAttributesW(path)
    assert attributes != 0xFFFFFFFF and not attributes & 0x400
    result = {
        "attributes": attributes,
        "security": _security(path),
        "mtime": stat.st_mtime,
        "ctime": stat.st_ctime,
        "directory": os.path.isdir(path),
    }
    if not result["directory"]:
        with open(path, "rb") as stream:
            result["body_base64"] = base64.b64encode(stream.read()).decode("ascii")
    return result


def _read(workspace):
    with open(os.path.join(workspace, "journal.json"), encoding="utf-8") as stream:
        record = json.load(stream)
    assert record["workspace"] == workspace
    return record


def _write(workspace, record):
    descriptor, temporary = tempfile.mkstemp(prefix=".dsc-journal-", dir=workspace)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(record, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, os.path.join(workspace, "journal.json"))
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


# pylint: enable=duplicate-code


def _observe(workspace):
    record = _read(workspace)
    allowed = {
        "journal.json",
        "sentinel.bin",
        "source.txt",
        "managed.txt",
        "managed-dir",
    }
    assert set(os.listdir(workspace)) <= allowed
    directory = os.path.join(workspace, "managed-dir")
    assert not os.path.isdir(directory) or os.listdir(directory) == []
    protected = {
        name: _file(os.path.join(workspace, name))
        for name in ("sentinel.bin", "source.txt")
    }
    assert protected == record["protected"]
    return {
        "protected": protected,
        "output": {
            name: _file(os.path.join(workspace, name))
            for name in ("managed.txt", "managed-dir")
        },
        "python": sys.version,
    }


def _setup(workspace):
    assert os.listdir(workspace) == []
    # Register all output names while absent, before a DSC request can write them.
    _write(
        workspace, {"workspace": workspace, "outputs": ["managed.txt", "managed-dir"]}
    )
    for name, content in (
        ("sentinel.bin", b"protected sentinel\x00\xff"),
        ("source.txt", "source λ content".encode("utf-8")),
    ):
        # The setup loop is deliberately local to this fixture's owned names.
        # pylint: disable=duplicate-code
        path = os.path.join(workspace, name)
        with open(path, "wb") as stream:
            stream.write(content)
        os.utime(path, (1234567890, 1234567890))
    record = _read(workspace)
    record["protected"] = {
        name: _file(os.path.join(workspace, name))
        for name in ("sentinel.bin", "source.txt")
    }
    _write(workspace, record)
    return _observe(workspace)


# pylint: enable=duplicate-code


def _reset(workspace):
    # Standalone recovery must check this fixture's own observation before
    # removing only journaled outputs, without another staged dependency.
    # pylint: disable=duplicate-code
    _observe(workspace)
    record = _read(workspace)
    for name in record["outputs"]:
        path = os.path.join(workspace, name)
        if os.path.isdir(path):
            assert os.listdir(path) == []
            os.rmdir(path)
        elif os.path.isfile(path):
            os.remove(path)
    return _observe(workspace)


def _prepare(workspace):
    _reset(workspace)
    case = json.loads(base64.b64decode(sys.argv[3]).decode("utf-8"))
    seed = case.get("seed")
    if seed == "directory":
        os.mkdir(os.path.join(workspace, "managed-dir"))
    elif seed is not None:
        path = os.path.join(workspace, "managed.txt")
        with open(path, "wb") as stream:
            stream.write(seed.encode("utf-8-sig"))
        os.utime(path, (1234567890, 1234567890))
    return _observe(workspace)


def _cleanup(workspace):
    # Keep the standalone restoration boundary next to its own ownership check.
    # pylint: disable=duplicate-code
    _reset(workspace)
    record = _read(workspace)
    record["restored"] = True
    _write(workspace, record)
    return {"restored": True, "state": _observe(workspace)}


def _finalize(workspace):
    # Finalization uses this fixture's literal protected-file allowlist below.
    # pylint: disable=duplicate-code
    record = _read(workspace)
    assert record["restored"]
    state = _observe(workspace)
    assert all(value is None for value in state["output"].values())
    for name in ("sentinel.bin", "source.txt", "journal.json"):
        os.remove(os.path.join(workspace, name))
    assert os.listdir(workspace) == []
    return {"finalized": True}


def _main():
    # Each stdin fixture independently enforces its runtime and workspace prefix.
    # pylint: disable=duplicate-code
    assert sys.version_info[:3] == (3, 4, 4)
    workspace, operation = sys.argv[1:3]
    assert os.path.basename(workspace).startswith("legacy-windows-win-dsc-")
    assert os.path.samefile(os.path.dirname(workspace), tempfile.gettempdir())
    operations = {
        "setup": _setup,
        "observe": _observe,
        "prepare": _prepare,
        "cleanup": _cleanup,
        "finalize": _finalize,
    }
    print(json.dumps(operations[operation](workspace), sort_keys=True))


# The independent stdin entry point is intentionally identical to other fixtures.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    _main()
