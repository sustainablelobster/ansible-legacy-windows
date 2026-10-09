"""Observe and recover the journal-owned credentialed DSC workspace."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import hashlib
import json
import os
import sys
import tempfile


# Independent fixtures repeat this native security read so recovery evidence
# does not depend on another workflow's mutable test helper.
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


# pylint: enable=duplicate-code
def _file(path):
    with open(path, "rb") as stream:
        content = stream.read()
    return {
        "body": base64.b64encode(content).decode("ascii"),
        "security": _security(path),
    }


def _marker(path):
    with open(path, "rb") as stream:
        content = stream.read()
    return {"sha256": hashlib.sha256(content).hexdigest(), "security": _security(path)}


def _read(workspace):
    with open(os.path.join(workspace, "journal.json"), encoding="utf-8") as stream:
        record = json.load(stream)
    assert record["workspace"] == workspace
    return record


# Keep this atomic journal write beside its owned recovery logic rather than
# coupling independent DSC and PowerShell fixtures through a shared helper.
# pylint: disable=duplicate-code
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
def _configuration():
    root = os.path.join(os.environ["SystemRoot"], "System32", "Configuration")
    result = {}
    for name in ("Current.mof", "Pending.mof", "Previous.mof", "MetaConfig.mof"):
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            result[name] = None
        else:
            with open(path, "rb") as stream:
                content = stream.read()
            result[name] = {
                "sha256": hashlib.sha256(content).hexdigest(),
                "security": _security(path),
            }
    return result


def _observe(workspace):
    record = _read(workspace)
    assert set(os.listdir(workspace)) <= {
        "journal.json",
        "sentinel.bin",
        "managed.txt",
        "audit.jsonl",
        "marker.txt",
    }
    assert _file(os.path.join(workspace, "sentinel.bin")) == record["sentinel"]
    assert _marker(os.path.join(workspace, "marker.txt")) == record["marker"]
    assert _configuration() == record["configuration"]
    audit = []
    path = os.path.join(workspace, "audit.jsonl")
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig") as stream:
            audit = [json.loads(line) for line in stream if line.strip()]
    managed = os.path.join(workspace, "managed.txt")
    return {
        "audit": audit,
        "managed": _file(managed) if os.path.isfile(managed) else None,
        "configuration": _configuration(),
        "python": sys.version,
        "protected": True,
    }


def _setup(workspace):
    assert os.listdir(workspace) == []
    _write(workspace, {"workspace": workspace})
    with open(os.path.join(workspace, "sentinel.bin"), "wb") as stream:
        stream.write(b"protected credentialed DSC sentinel\x00\xff")
    with open(os.path.join(workspace, "marker.txt"), "wb") as stream:
        stream.write(globals()["DSC_TEST_SECRET"].encode("utf-8"))
    record = _read(workspace)
    record.update(
        sentinel=_file(os.path.join(workspace, "sentinel.bin")),
        marker=_marker(os.path.join(workspace, "marker.txt")),
        configuration=_configuration(),
    )
    _write(workspace, record)
    return _observe(workspace)


def _cleanup(workspace):
    before = _observe(workspace)
    for name in ("managed.txt", "audit.jsonl"):
        path = os.path.join(workspace, name)
        if os.path.isfile(path):
            os.remove(path)
    after = _observe(workspace)
    assert after["managed"] is None and not after["audit"]
    return {"before": before, "after": after, "restored": True}


def _finalize(workspace):
    observed = _observe(workspace)
    assert observed["managed"] is None and not observed["audit"]
    assert set(os.listdir(workspace)) == {"journal.json", "sentinel.bin", "marker.txt"}
    os.remove(os.path.join(workspace, "marker.txt"))
    os.remove(os.path.join(workspace, "sentinel.bin"))
    os.remove(os.path.join(workspace, "journal.json"))
    return {"empty": not os.listdir(workspace)}


def _cache_secrets(secrets):
    root = os.path.join(os.environ["SystemRoot"], "System32", "Configuration")
    patterns = [
        secret.encode(encoding)
        for secret in secrets
        for encoding in ("utf-8", "utf-16-le", "utf-16-be")
        if secret
    ]
    scanned = []
    for directory, directories, names in os.walk(root):
        assert not any(
            os.path.islink(os.path.join(directory, name)) for name in directories
        )
        for name in names:
            path = os.path.join(directory, name)
            assert not os.path.islink(path)
            assert os.path.getsize(path) <= 16 * 1024 * 1024
            with open(path, "rb") as stream:
                content = stream.read()
            if any(pattern in content for pattern in patterns):
                raise ValueError(
                    "DSC cache exposes a supplied secret at "
                    + os.path.relpath(path, root)
                )
            scanned.append(os.path.relpath(path, root))
            assert len(scanned) <= 5000
    return {"scanned": sorted(scanned), "secrets_absent": True}


def main():
    """Run one bounded journal operation supplied through the private fixture.

    :raises AssertionError: Ownership or protected native state no longer matches.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    workspace, operation = sys.argv[1:]
    functions = {
        "setup": _setup,
        "observe": _observe,
        "cleanup": _cleanup,
        "finalize": _finalize,
    }
    if operation == "scan":
        # Supply test secrets through the existing stdin program, not guest
        # process arguments or journal files that could themselves retain them.
        print(json.dumps(_cache_secrets(globals()["DSC_TEST_SECRETS"]), sort_keys=True))
        return
    print(json.dumps(functions[operation](workspace), sort_keys=True))


if __name__ == "__main__":
    main()
