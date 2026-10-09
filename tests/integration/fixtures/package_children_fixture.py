"""Extend the existing literal registry recovery with owned process-tree proof."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import subprocess
import sys
import time

import package_registry_fixture as base  # pylint: disable=import-error

# Reuse the exact maintained registry/private-runtime observation boundary.
# pylint: disable=protected-access

ROOT, OPERATION = sys.argv[1:3]
ROLES = ("parent", "child", "grandchild")
PROGRAM = "tree_installer.py"
BASE_SOURCES = base.source_files


def sources():
    """Observe protected installer inputs including the tree program.

    :returns: Literal source file states.
    :rtype: dict
    """
    value = BASE_SOURCES()
    path = os.path.join(ROOT, PROGRAM)
    if os.path.isfile(path):
        value[PROGRAM] = base.file_state(path)
    return value


base.source_files = sources


def receipts():
    """Read and validate only the three exact owned process receipts.

    :returns: Raw receipt data and protected file states.
    :rtype: dict
    """
    value = {}
    for role in ROLES:
        path = os.path.join(ROOT, role + ".json")
        if os.path.isfile(path):
            state = base.file_state(path)
            raw_receipt = state["bytes"]
            data = json.loads(raw_receipt.decode("utf-8"))
            assert data["workspace"] == ROOT and data["role"] == role
            assert isinstance(data["pid"], int) and not isinstance(data["pid"], bool)
            assert isinstance(data["parent"], int) and not isinstance(
                data["parent"], bool
            )
            assert data["pid"] > 0 and data["parent"] >= 0
            value[role] = {"data": data, "file": state}
    if value:
        assert set(value) == set(ROLES)
        assert value["parent"]["data"]["child"] == value["child"]["data"]["pid"]
        assert value["child"]["data"]["parent"] == value["parent"]["data"]["pid"]
        assert value["child"]["data"]["child"] == value["grandchild"]["data"]["pid"]
        assert value["grandchild"]["data"]["parent"] == value["child"]["data"]["pid"]
    return value


def running():
    """Query native process identities selecting only the owned workspace.

    :returns: Raw native process fields for the owned tree.
    :rtype: list
    """
    with base.WmiConnection() as connection:
        rows = connection.query(
            "SELECT ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate "
            "FROM Win32_Process WHERE Name='registry installer.exe'",
            [
                "ProcessId",
                "ParentProcessId",
                "ExecutablePath",
                "CommandLine",
                "CreationDate",
            ],
        )
    return [
        row
        for row in rows
        if row["CommandLine"] and ROOT.lower() in row["CommandLine"].lower()
    ]


def settle():
    """Wait naturally for only receipt-matched owned processes to finish.

    :returns: Complete original receipts retained throughout the wait.
    :rtype: dict
    """
    expected = receipts()
    deadline = time.monotonic() + 30
    while True:
        active = running()
        if not active:
            return expected
        assert expected
        for row in active:
            assert row["ProcessId"] in [
                value["data"]["pid"] for value in expected.values()
            ]
            assert os.path.normcase(row["ExecutablePath"]) == os.path.normcase(
                base.INSTALLER
            )
            assert os.path.join(ROOT, PROGRAM).lower() in row["CommandLine"].lower()
        assert time.monotonic() < deadline, active
        time.sleep(0.05)


def clear_tree():
    """Remove exact unmodified receipts after every owned process exits."""
    recorded = settle()
    for role, value in recorded.items():
        path = os.path.join(ROOT, role + ".json")
        assert base.file_state(path) == value["file"]
        os.remove(path)


def setup():
    """Extend the existing private-runtime journal with this tree fixture.

    :returns: Proven input hashes, product identity and interpreter home.
    :rtype: dict
    """
    # The existing fixture validates its original four source names first.
    base.source_files = BASE_SOURCES
    try:
        ready = base.setup()
    finally:
        base.source_files = sources
    record = base.read()
    record["sources"][PROGRAM] = base.file_state(os.path.join(ROOT, PROGRAM))
    for location, command in record["uninstall_commands"].items():
        assert location.split("/")[0] in ("HKLM", "HKCU") and command
        record["uninstall_commands"][location] = subprocess.list2cmdline(
            [
                base.INSTALLER,
                "-S",
                os.path.join(ROOT, PROGRAM),
                ROOT,
                "parent",
                "remove",
                "0",
                "1",
                "0",
            ]
        )
    base.write(record)
    assert sources() == record["sources"]
    return dict(
        ready,
        sha256={name: value["sha256"] for name, value in record["sources"].items()},
        installer=base.INSTALLER,
        tree_program=os.path.join(ROOT, PROGRAM),
    )


def prepare():
    """Prepare the owned entry after the preceding tree settles completely.

    :returns: Full protected baseline and exact operation boundary.
    :rtype: dict
    """
    clear_tree()
    started = base.now()
    # Restrict the existing preparation to the exact owned HKCU native entry.
    sys.argv = sys.argv[:4] + ["HKCU", "native", "UninstallString"]
    value = base.prepare()
    return dict(value, started=started, receipts=receipts(), running=running())


def observe():
    """Capture the complete registry boundary plus the real owned tree.

    :returns: Raw protected states, receipts and native process fields.
    :rtype: dict
    """
    value = base.snapshot()
    return dict(value, receipts=receipts(), running=running())


def cleanup():
    """Restore the recorded baseline only after the owned tree exits.

    :returns: Exact before/after recovery and owned absence proofs.
    :rtype: dict
    """
    clear_tree()
    value = base.cleanup()
    assert not running() and not receipts()
    return dict(value, process_tree_absent=True, receipt_files_absent=True)


def main():
    """Operate only on a journal-owned disposable registry process fixture."""
    assert sys.version_info[:3] == (3, 4, 4)
    base.validate_workspace()
    assert os.path.basename(ROOT).startswith(
        "legacy-windows-package-registry-test-children-"
    )
    operation = {
        "journal": base.journal,
        "setup": setup,
        "prepare": prepare,
        "observe": observe,
        "cleanup": cleanup,
        "finalize": base.finalize,
    }[OPERATION]
    print(json.dumps(operation(), default=base.encode, sort_keys=True))


if __name__ == "__main__":
    main()
