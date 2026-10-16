"""Read owned IIS pool configuration with AppCmd, independently of the module."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET


def read_pools(prefix):
    """Return native effective and explicitly stored settings for owned pools.

    :param prefix: Unique prefix allocated by the integration playbook.
    :type prefix: str
    :returns: Pool settings indexed by their suffix after the prefix.
    :rtype: dict
    :raises OSError: AppCmd is unavailable or its native read fails.
    :raises ValueError: AppCmd does not provide a pool's configuration element.
    """
    appcmd = os.path.expandvars(r"%SystemRoot%\Sysnative\inetsrv\appcmd.exe")
    if not os.path.isfile(appcmd):
        appcmd = os.path.expandvars(r"%SystemRoot%\System32\inetsrv\appcmd.exe")
    with subprocess.Popen(
        [appcmd, "list", "apppool", "/config", "/xml"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        output, _error = process.communicate()
        if process.returncode:
            raise OSError(
                "AppCmd pool read failed with rc={0}.".format(process.returncode)
            )
    result = {}
    for pool in ET.fromstring(output).findall("APPPOOL"):
        name = pool.get("APPPOOL.NAME", "")
        if not name.startswith(prefix):
            continue
        configuration = pool.find("add")
        if configuration is None:
            raise ValueError("AppCmd omitted configuration for owned pool " + name)
        result[name[len(prefix) :]] = {
            "runtime": pool.get("RuntimeVersion"),
            "explicit_runtime": configuration.get("managedRuntimeVersion"),
            "pipeline": pool.get("PipelineMode"),
            "configuration_sha256": hashlib.sha256(
                ET.tostring(configuration, encoding="utf-8")
            ).hexdigest(),
        }
    return result


if __name__ == "__main__":
    print(json.dumps(read_pools(sys.argv[1]), sort_keys=True))
