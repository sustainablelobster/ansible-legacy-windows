"""Own signature samples while reusing the exact measured MSI recovery boundary."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import hashlib
import json
import os
import shutil
import sys
import tempfile

import legacy_windows_package_signature as signature  # pylint: disable=import-error
import package_msp_fixture as base  # pylint: disable=import-error

# The concrete frozen fixture provides the already-reviewed native observations.
# pylint: disable=protected-access

ROOT, OPERATION = sys.argv[1:3]
SAMPLES = ("signed cmd.exe", "altered cmd.exe", "unsigned.exe")


def _sources():
    return {
        name: base._file_state(os.path.join(ROOT, name))
        for name in SAMPLES
        if os.path.isfile(os.path.join(ROOT, name))
    }


def _protected_samples(record):
    assert _sources() == record["signature"]["sources"]
    assert (
        base._file_state(record["signature"]["system_cmd"])
        == record["signature"]["protected_system_cmd"]
    )


def _setup():
    ready = base._setup()
    record = base._read()
    system = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    protected = base._file_state(system)
    record["signature"] = {
        "system_cmd": system,
        "protected_system_cmd": protected,
        "sources": {},
    }
    base._write(record)
    shutil.copyfile(system, os.path.join(ROOT, SAMPLES[0]))
    # Change only a DOS-stub byte in the owned copy. Preserve a valid PE layout
    # and never execute this deliberately modified signature test sample.
    altered = bytearray(protected["bytes"])
    assert altered[:2] == b"MZ" and len(altered) > 128
    altered[64] ^= 1
    with open(os.path.join(ROOT, SAMPLES[1]), "wb") as stream:
        stream.write(altered)
    with open(os.path.join(ROOT, SAMPLES[2]), "wb") as stream:
        stream.write(b"not a real exe")
    record["signature"]["sources"] = _sources()
    base._write(record)
    _protected_samples(record)
    return dict(
        ready,
        native_status={
            name: signature.status(os.path.join(ROOT, name)) for name in SAMPLES
        },
        sample_sha256={
            name: hashlib.sha256(value["bytes"]).hexdigest()
            for name, value in record["signature"]["sources"].items()
        },
    )


def _prepare():
    record = base._read()
    _protected_samples(record)
    state = base._prepare()
    return dict(
        state,
        signature_sources=_sources(),
        protected_system_cmd=record["signature"]["protected_system_cmd"],
    )


def _observe():
    record = base._read()
    _protected_samples(record)
    return dict(
        base._snapshot(),
        signature_sources=_sources(),
        protected_system_cmd=base._file_state(record["signature"]["system_cmd"]),
    )


def _cleanup():
    if not os.path.exists(base.JOURNAL):
        assert os.listdir(ROOT) == []
        return {"restored": True, "journal_absent": True}
    record = base._read()
    if "signature" in record:
        # A setup failure must leave an exact journal of completed owned writes;
        # do not silently adopt an unknown or incompletely recorded sample.
        _protected_samples(record)
    result = base._cleanup()
    assert set(os.listdir(ROOT)) <= set(SAMPLES) | {
        "patch.msi",
        "patch.msp",
        "msp-journal.json",
        "fixture.log",
    }
    return dict(result, signature_sources_unchanged=True, system_cmd_unchanged=True)


def main():
    """Run bounded read/fixture operations on actual Python3.4.4.

    :raises AssertionError: Ownership, provenance or literal recovery fails.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    assert os.path.basename(ROOT).startswith("legacy-windows-package-signature-test-")
    # Workspace validation is independent of the package payload it protects.
    # pylint: disable=duplicate-code
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.GetLongPathNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    library.GetLongPathNameW.restype = ctypes.c_uint32

    def _canonical(path):
        buffer = ctypes.create_unicode_buffer(32768)
        count = library.GetLongPathNameW(path, buffer, len(buffer))
        assert 0 < count < len(buffer)
        return os.path.normcase(buffer.value.rstrip("\\"))

    assert _canonical(os.path.dirname(ROOT)) == _canonical(tempfile.gettempdir())
    assert not os.path.islink(ROOT)
    # pylint: enable=duplicate-code
    # Each fixture exposes its own bounded operations while reusing the MSI journal.
    # pylint: disable=duplicate-code
    operation = {
        "journal": base._journal,
        "setup": _setup,
        "prepare": _prepare,
        "observe": _observe,
        "cleanup": _cleanup,
        "finalize": base._finalize,
    }[OPERATION]
    # pylint: enable=duplicate-code
    print(json.dumps(operation(), default=base._encode, sort_keys=True))


if __name__ == "__main__":
    main()
