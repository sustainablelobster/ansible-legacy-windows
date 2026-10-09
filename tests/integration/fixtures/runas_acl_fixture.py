# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later

"""Exercise NULL-DACL preservation against the actual staged runas helper."""

import ctypes
import hashlib
import json
import os
import sys
from contextlib import contextmanager


@contextmanager
def _dacl(security, kernel, directory):
    descriptor, dacl = ctypes.c_void_p(), ctypes.c_void_p()
    text = ctypes.c_wchar_p()
    try:
        # The independent observation intentionally repeats this fixed native ABI.
        # pylint: disable=duplicate-code
        status = security.GetNamedSecurityInfoW(
            directory,
            1,
            4,
            None,
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        # pylint: enable=duplicate-code
        if status:
            raise ctypes.WinError(status)
        if not security.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, 4, ctypes.byref(text), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        yield dacl, text.value
    finally:
        if text:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        if descriptor:
            kernel.LocalFree(descriptor)


def _observe_preservation(security, kernel, target):
    # The verified target helper, rather than a duplicate algorithm, is under test.
    import legacy_windows_runas as runas  # pylint: disable=import-outside-toplevel,import-error

    result = {}
    with _dacl(security, kernel, target) as (original_dacl, original_text):
        result["original"] = original_text
        try:
            status = security.SetNamedSecurityInfoW(
                target, 1, 4 | 0x80000000, None, None, None, None
            )
            if status:
                raise ctypes.WinError(status)
            with _dacl(security, kernel, target) as (before, before_text):
                result["null_before"] = not bool(before)
                result["before"] = before_text
            # This concrete staging boundary is the behavior under regression test.
            # pylint: disable=protected-access
            runas._grant_task_read(security, kernel, target, "S-1-5-32-545")
            # pylint: enable=protected-access
            with _dacl(security, kernel, target) as (after, after_text):
                result["null_after"] = not bool(after)
                result["after"] = after_text
        finally:
            status = security.SetNamedSecurityInfoW(
                target, 1, 4 | 0x80000000, None, None, original_dacl, None
            )
            if status:
                raise ctypes.WinError(status)
        with _dacl(security, kernel, target) as (_restored, restored_text):
            result["restored"] = restored_text
    os.rmdir(target)
    result["owned_child_absent"] = not os.path.exists(target)
    return result


def verify_null_dacl(directory, expected_hashes):
    """Verify unrestricted access survives the helper and restore the owned ACL.

    :param str directory: Existing exclusively owned fixture workspace.
    :param dict expected_hashes: SHA-256 values of the copied target helper closure.
    :returns: Actual Python version, byte identities and native ACL observations.
    :rtype: dict
    :raises AssertionError: The interpreter, helper bytes or ACL behavior differ.
    :raises OSError: A native query, ACL update or directory operation fails.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    for name, expected in expected_hashes.items():
        with open(os.path.join(directory, name), "rb") as stream:
            assert hashlib.sha256(stream.read()).hexdigest() == expected
    sys.path.insert(0, directory)
    # The exact copied target helper is intentionally imported after byte checks.
    import legacy_windows_runas as runas  # pylint: disable=import-outside-toplevel,import-error

    security, kernel = runas._libraries()  # pylint: disable=protected-access
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = ctypes.c_int
    target = os.path.join(directory, "owned-null-dacl")
    os.mkdir(target)
    # Protect only this owned child so restoration does not recompute inheritance.
    with _dacl(security, kernel, target) as (inherited, _inherited_text):
        status = security.SetNamedSecurityInfoW(
            target, 1, 4 | 0x80000000, None, None, inherited, None
        )
        if status:
            raise ctypes.WinError(status)
    result = _observe_preservation(security, kernel, target)
    result.update(python=list(sys.version_info[:3]), helper_hashes=expected_hashes)
    return result


if __name__ == "__main__":
    print(json.dumps(verify_null_dacl(sys.argv[1], json.loads(sys.argv[2]))))
