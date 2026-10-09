# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and change advanced system audit policy with the native auditpol tool."""

import csv
import io
import subprocess

# The ordinary Python action stages both process helpers beside this file.
from legacy_windows_process import run_command  # pylint: disable=import-error


def run_auditpol(arguments):
    """Execute auditpol without a shell and retain its exit status and streams.

    :param arguments: Individual native auditpol arguments.
    :type arguments: list of str
    :returns: Native process result, including launch failures.
    :rtype: dict
    :raises OSError: Communication with the already-started process fails.
    """
    command = subprocess.list2cmdline(["auditpol.exe"] + arguments)
    return run_command(
        "auditpol.exe",
        command,
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )


def catalogue():
    """List installed category and subcategory names in native enumeration order.

    :returns: A pair of category and subcategory name lists.
    :rtype: tuple
    :raises OSError: The native utility is unavailable or cannot list policies.
    :raises ValueError: The utility returns an unexpected CSV schema.
    """
    categories = run_auditpol(["/list", "/category", "/r"])
    subcategories = run_auditpol(["/list", "/subcategory:*", "/r"])
    for label, result in (("categories", categories), ("subcategories", subcategories)):
        if result["rc"]:
            raise OSError(
                "Failed to retrieve audit policy {0}: {1}".format(
                    label, result.get("stderr") or result.get("msg", "")
                )
            )
    names = []
    for result in (categories, subcategories):
        table = csv.DictReader(io.StringIO(result["stdout"]))
        headings = [
            name for name in table.fieldnames or [] if name.startswith("Category")
        ]
        if len(headings) != 1:
            raise ValueError("auditpol returned no unique Category CSV column.")
        # PowerShell's unquoted CSV conversion removes auditpol's indentation.
        names.append([row[headings[0]].strip() for row in table])
    return names[0], [name for name in names[1] if name not in names[0]]


def get_policy(selector, name):
    """Read the selected policy, retaining native errors as the upstream result.

    :param str selector: Validated category or subcategory selector.
    :param str name: Installed display name selected by the caller.
    :returns: Lowercase subcategory-to-setting mapping, or native error text.
    :rtype: dict or str
    :raises ValueError: Successful utility output has an unexpected CSV schema.
    :raises OSError: Communication with the native process fails.
    """
    result = run_auditpol(["/get", "/r", "/" + selector + ":" + name])
    if result["rc"]:
        return result.get("stderr") or result.get("msg", "")
    table = csv.DictReader(io.StringIO(result["stdout"]))
    if not {"Subcategory", "Inclusion Setting"}.issubset(table.fieldnames or []):
        raise ValueError(
            "auditpol returned no Subcategory or Inclusion Setting column."
        )
    policy = {}
    for row in table:
        subcategory = row["Subcategory"].lower()
        if subcategory in policy:
            raise ValueError("auditpol returned duplicate subcategory " + subcategory)
        policy[subcategory] = row["Inclusion Setting"].lower()
    return policy


def set_policy(selector, name, success, failure):
    """Set both auditing flags for the validated category or subcategory.

    :param str selector: Validated category or subcategory selector.
    :param str name: Installed display name selected by the caller.
    :param bool success: Whether successful events are audited.
    :param bool failure: Whether failed events are audited.
    :returns: Complete native process result, including a failed setter.
    :rtype: dict
    :raises OSError: Communication with the native process fails.
    """
    return run_auditpol(
        [
            "/set",
            "/" + selector + ":" + name,
            "/success:" + ("enable" if success else "disable"),
            "/failure:" + ("enable" if failure else "disable"),
        ]
    )
