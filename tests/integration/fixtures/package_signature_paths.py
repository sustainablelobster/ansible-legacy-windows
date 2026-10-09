"""Verify signature path selection without changing existing packages or keys."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import hashlib
import json
import os
import shutil
import sys

# Reuse the measured native file/security observation, not the MSI lifecycle.
import package_msp_fixture as base  # pylint: disable=import-error

# These private fixture observations are the established native boundary.
# pylint: disable=protected-access

ROOT, OPERATION = sys.argv[1:3]
JOURNAL = os.path.join(ROOT, "signature-paths-journal.json")
CASES = (
    "plain.exe",
    "unmatched[7].exe",
    "matched[1].exe",
    "multiple[12].exe",
    "validmany[12].exe",
    "tick`x.exe",
    "escaped`[1`].exe",
    "double``.exe",
    "folder[3]\\command.exe",
    "missing[4]\\command.exe",
)
INVALID = (
    "matched1.exe",
    "multiple2.exe",
    "tickx.exe",
    "escaped[1].exe",
    "double`.exe",
    "folder3\\command.exe",
)
SIGNED = CASES + ("multiple1.exe", "validmany1.exe", "validmany2.exe")


def _metadata(path):
    value = base._file_state(path)
    content = value.pop("bytes")
    value.update(sha256=hashlib.sha256(content).hexdigest(), size=len(content))
    return value


def _files():
    return {
        os.path.relpath(os.path.join(directory, name), ROOT): _metadata(
            os.path.join(directory, name)
        )
        for directory, _folders, files in os.walk(ROOT)
        for name in files
        if os.path.join(directory, name) != JOURNAL
    }


def _directories():
    return sorted(
        os.path.relpath(directory, ROOT)
        for directory, _folders, _files_ in os.walk(ROOT)
    )


def _write(record):
    with open(JOURNAL, "w", encoding="utf-8") as stream:
        json.dump(record, stream, default=base._encode, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def _setup():
    assert not os.listdir(ROOT)
    system = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    record = {
        "workspace": ROOT,
        "system": system,
        "protected": _metadata(system),
        "files": {},
        "directories": ["."],
    }
    sample = (
        base64.b64decode(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else None
    )
    if sample is not None:
        assert sample[:2] == b"MZ" and len(sample) > 128
    _write(record)
    for name in SIGNED + INVALID:
        target = os.path.join(ROOT, name)
        parent = os.path.dirname(target)
        if not os.path.isdir(parent):
            os.mkdir(parent)
            record["directories"] = _directories()
            _write(record)
        if name in INVALID:
            with open(target, "wb") as stream:
                stream.write(b"not a real exe")
        elif sample is not None:
            with open(target, "wb") as stream:
                stream.write(sample)
        else:
            shutil.copyfile(system, target)
        record["files"][name] = _metadata(target)
        _write(record)
    return {"cases": CASES, "python": sys.version, "original": record}


def _observe():
    with open(JOURNAL, encoding="utf-8") as stream:
        record = json.load(stream, object_hook=base._decode)
    assert record["workspace"] == ROOT
    observed = {
        "protected": _metadata(record["system"]),
        "files": _files(),
        "directories": _directories(),
    }
    for field, value in observed.items():
        assert value == record[field]
    return {"literal_protection": True, "original": record, "observed": observed}


def _same(left, right):
    assert type(left) is type(right)
    if isinstance(left, dict):
        assert set(left) == set(right)
        pairs = ((left[name], right[name]) for name in left)
    elif isinstance(left, list):
        assert len(left) == len(right)
        pairs = zip(left, right)
    else:
        assert left == right
        return
    for first, second in pairs:
        _same(first, second)


def _compare():
    pair = json.loads(base64.b64decode(sys.argv[3]).decode("utf-8"))
    for first, second in zip(pair["native"]["results"], pair["original"]["results"]):
        native, original = dict(first), dict(second)
        for value in (native, original):
            value.pop("invocation", None)
            value.pop("exception", None)
        _same(native, original)
    assert (
        len(pair["native"]["results"]) == len(pair["original"]["results"]) == len(CASES)
    )
    return {"complete_typed_public_equal": True, "cases": len(CASES)}


def main():
    """Run the owned sample operation on actual Python 3.4.4.

    :raises AssertionError: Runtime, ownership, protection or public parity fails.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    assert os.path.basename(ROOT).startswith("legacy-windows-signature-wildcard-")
    operation = {"setup": _setup, "observe": _observe, "compare": _compare}[OPERATION]
    print(json.dumps(operation(), default=base._encode, sort_keys=True))


if __name__ == "__main__":
    main()
