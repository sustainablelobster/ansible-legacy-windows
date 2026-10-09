# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later

"""Diagnose native token access without changing account rights or passwords."""

import ctypes
import json
import sys
from collections import Counter


# Diagnostic records keep each observed API result beside its native handle.
# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def probe(directory):
    """Inspect available SYSTEM process tokens with scoped privilege restoration.

    :param str directory: Directory containing the exact copied native helpers.
    :returns: Interpreter, native failures and eligible SYSTEM token observations.
    :rtype: dict
    :raises OSError: If opening the caller token or restoring privileges fails.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    sys.path.insert(0, directory)
    # The fixture observes the production ABI and records each acquisition step.
    import legacy_windows_runas_token as token_helper  # pylint: disable=import-outside-toplevel,import-error

    # Private native calls are the intentionally inspected acquisition boundary.
    # pylint: disable=protected-access
    security, kernel, processes = token_helper._libraries()
    process_token = ctypes.c_void_p()
    if not security.OpenProcessToken(
        kernel.GetCurrentProcess(), 0x28, ctypes.byref(process_token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    failures = Counter()
    result = {"python": list(sys.version_info[:3]), "system_tokens": []}
    try:
        with token_helper._privilege(security, process_token, "SeDebugPrivilege"):
            for pid in token_helper._process_ids(processes):
                process = kernel.OpenProcess(0x400, False, pid)
                if not process:
                    failures["OpenProcess:" + str(ctypes.get_last_error())] += 1
                    continue
                token, duplicate = ctypes.c_void_p(), ctypes.c_void_p()
                try:
                    opened = False
                    for access in (0xF, 0xA, 8):
                        if security.OpenProcessToken(
                            process, access, ctypes.byref(token)
                        ):
                            opened = True
                            break
                        failures[
                            "OpenProcessToken:{0}:{1}".format(
                                access, ctypes.get_last_error()
                            )
                        ] += 1
                    if not opened:
                        continue
                    data = token_helper._information(security, token, 1)
                    if (
                        token_helper.account.sid_to_string(
                            ctypes.c_void_p.from_buffer(data).value
                        )
                        != "S-1-5-18"
                    ):
                        continue
                    record = {"pid": pid, "opened_access": access}
                    result["system_tokens"].append(record)
                    privileges = token_helper._information(security, token, 3)
                    record["privileges"] = ctypes.c_uint32.from_buffer(privileges).value
                    for level in (0, 2):
                        if not security.DuplicateTokenEx(
                            token, 0x02000000, None, level, 1, ctypes.byref(duplicate)
                        ):
                            record["duplicate_" + str(level)] = ctypes.get_last_error()
                            continue
                        record["duplicate_" + str(level)] = True
                        try:
                            with token_helper._privilege(
                                security, duplicate, "SeTcbPrivilege"
                            ):
                                active = bool(
                                    security.ImpersonateLoggedOnUser(duplicate)
                                )
                                record["impersonate_" + str(level)] = (
                                    True if active else ctypes.get_last_error()
                                )
                                if active and not security.RevertToSelf():
                                    raise ctypes.WinError(ctypes.get_last_error())
                        finally:
                            kernel.CloseHandle(duplicate)
                            duplicate.value = None
                except OSError as error:
                    failures["query:" + str(getattr(error, "winerror", None))] += 1
                finally:
                    if token:
                        kernel.CloseHandle(token)
                    kernel.CloseHandle(process)
    finally:
        kernel.CloseHandle(process_token)
    result["failures"] = dict(failures)
    return result


if __name__ == "__main__":
    print(json.dumps(probe(sys.argv[1]), sort_keys=True))
