# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Exercise interrupted certificate finalization on an owned gateway fixture."""

import binascii
import hashlib
import json
import subprocess
import sys

from legacy_community_windows_iis_ssl import endpoint  # pylint: disable=import-error
from legacy_community_windows_rds import (  # pylint: disable=import-error
    Gateway,
    manage,
)
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error


def _snapshot(configuration_path):
    with WmiConnection(r"ROOT\CIMV2\TerminalServices") as provider:
        row = provider.query(
            "SELECT * FROM Win32_TSGatewayServerSettings",
            ["CertHash", "IsConfigured"],
        )[0]
    with open(configuration_path, "rb") as stream:
        configuration_digest = hashlib.sha256(stream.read()).hexdigest()
    return {
        "certificate": binascii.hexlify(bytes(row["CertHash"] or []))
        .decode("ascii")
        .upper(),
        "configured": row["IsConfigured"],
        "configuration_digest": configuration_digest,
        "endpoints": [
            endpoint({"ip": address, "port": 443}, "", "", "0", query=True)
            for address in ("0.0.0.0", "::")
        ],
        "service": binascii.hexlify(
            subprocess.check_output(["sc.exe", "query", "TSGateway"])
        ).decode("ascii"),
    }


def _recover(thumbprint):
    native_call = Gateway.call
    calls = []

    def _interrupt(gateway, path, method, inputs=None):
        calls.append(method)
        if method == "Configure":
            raise OSError("Owned fixture interrupted certificate finalization")
        return native_call(gateway, path, method, inputs)

    Gateway.call = _interrupt
    try:
        try:
            manage("win_rds_settings", {"certificate_hash": thumbprint})
        except OSError as error:
            if str(error) != "Owned fixture interrupted certificate finalization":
                raise
        else:
            raise AssertionError("The certificate assignment was not interrupted.")
    finally:
        Gateway.call = native_call
    assert calls == ["SetCertificate", "Configure"], calls

    def _record(gateway, path, method, inputs=None):
        calls.append(method)
        return native_call(gateway, path, method, inputs)

    Gateway.call = _record
    try:
        recovered = manage("win_rds_settings", {"certificate_hash": thumbprint})
    finally:
        Gateway.call = native_call
    assert calls == ["SetCertificate", "Configure", "Configure"], calls
    return {"methods": calls, "recovered": recovered}


def main():
    """Print native recovery evidence or the current bounded fixture state."""
    operation, thumbprint, configuration_path = sys.argv[1:]
    result = _recover(thumbprint) if operation == "recover" else {}
    result["state"] = _snapshot(configuration_path)
    assert result["state"]["certificate"] == thumbprint
    assert result["state"]["configured"]
    print(json.dumps(result))


if __name__ == "__main__":
    main()
