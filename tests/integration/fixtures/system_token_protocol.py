"""Observe real one-shot pipe rejection, deadlines, and identity recovery."""

# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later
# This observer checks the production helper's native authentication boundary.
# pylint: disable=protected-access,import-outside-toplevel,import-error

import ctypes
import json
import os
import subprocess
import sys
import time
import uuid


def _thread_sid(helper, security, kernel):
    token = ctypes.c_void_p()
    if not security.OpenThreadToken(
        kernel.GetCurrentThread(), 8, True, ctypes.byref(token)
    ):
        assert ctypes.get_last_error() == 1008
        return None
    try:
        return helper._sid(security, kernel, token)
    finally:
        assert kernel.CloseHandle(token)


def _pipe(helper, security, kernel, caller, name):
    with helper._attributes(security, kernel, caller) as attributes:
        # Independently create the same documented pipe ABI, not a mock peer.
        # pylint: disable=duplicate-code
        result = kernel.CreateNamedPipeW(
            "\\\\.\\pipe\\" + name,
            3 | 0x80000,
            4 | 2 | 1,
            1,
            64,
            64,
            0,
            ctypes.byref(attributes),
        )
        # pylint: enable=duplicate-code
    return result


# Native handles and rejection observations share this one bounded lifetime.
# pylint: disable-next=too-many-locals
def _reject_peer(helper, root, kind):
    security, kernel = helper._libraries()
    caller = helper._caller_sid(security, kernel)
    assert caller != "S-1-5-18"
    before = _thread_sid(helper, security, kernel)
    name, nonce = "legacy_windows_system_" + uuid.uuid4().hex, uuid.uuid4().hex
    pipe = _pipe(helper, security, kernel, caller, name)
    assert pipe not in (None, helper._INVALID)
    child = None
    try:
        collision = _pipe(helper, security, kernel, caller, name)
        assert collision in (None, helper._INVALID)
        assert ctypes.get_last_error() == 5
        connected = kernel.ConnectNamedPipe(pipe, None)
        assert connected or ctypes.get_last_error() in (535, 536)
        if kind != "timeout":
            sent = nonce if kind == "identity" else uuid.uuid4().hex
            # The pipe must close before communicate can observe the rejected
            # peer's natural exit; a Popen context would wait too early here.
            child = subprocess.Popen(  # pylint: disable=consider-using-with
                [sys.executable, os.path.abspath(__file__), root, "client", name, sent],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        try:
            helper._read_message(
                kernel,
                pipe,
                nonce.encode("ascii"),
                time.monotonic() + (0.25 if child is None else 5),
            )
            token = helper._duplicate_client(security, kernel, pipe)
        except ValueError as error:
            expected = {
                "identity": "peer is not LocalSystem",
                "nonce": "Unexpected",
                "timeout": "Timed out",
            }[kind]
            assert expected in str(error), str(error)
        else:
            kernel.CloseHandle(token)
            raise AssertionError("An unauthenticated peer was accepted")
    finally:
        assert kernel.CloseHandle(pipe)
        if child is not None:
            output, errors = child.communicate(timeout=5)
            assert child.returncode == 0 and not errors, (output, errors)
            assert json.loads(output.decode("ascii"))["server_closed"]
    assert _thread_sid(helper, security, kernel) == before
    return {
        "kind": kind,
        "caller": caller,
        "thread_before": before,
        "thread_after": before,
        "namespace_collision_rejected": True,
        "rejected": True,
    }


def main():
    """Verify real native rejection without creating an account or service.

    :raises AssertionError: A rejected peer or native identity check is invalid.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    root = sys.argv[1]
    sys.path.insert(0, root)
    import legacy_windows_system_token as helper

    if sys.argv[2] == "client":
        try:
            helper._client(helper._libraries()[1], sys.argv[3], sys.argv[4])
        except OSError as error:
            assert getattr(error, "winerror", None) in (109, 232, 233)
            print(json.dumps({"server_closed": True}))
        else:
            raise AssertionError("A rejected peer received acknowledgement")
        return
    assert sys.argv[2] == "observe"
    results = [
        _reject_peer(helper, root, kind) for kind in ("identity", "nonce", "timeout")
    ]
    print(json.dumps({"python": list(sys.version_info[:3]), "results": results}))


if __name__ == "__main__":
    main()
