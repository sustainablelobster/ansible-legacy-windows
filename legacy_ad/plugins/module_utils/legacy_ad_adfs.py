# Copyright 2026 Ansible Project
# Copyright 2026 sustainablelobster
# Management behavior derived from microsoft.ad 1.12.1; vendor calls run on PS2 too.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage AD FS through its installed vendor commands, including the 2.0 snap-in."""

import base64
import json
import os
import re
import subprocess

from legacy_ad_arguments import as_int32  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_dictionary,
    as_string,
    as_string_list,
)

# AD FS 2.0 already requires PowerShell and .NET 3.5 SP1. Its framework JSON
# serializer lets the fixed PS2-compatible script receive arguments as data;
# no user value is inserted into executable PowerShell text or command lines.
_VENDOR_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
Add-Type -AssemblyName System.Web.Extensions
$json = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$json.MaxJsonLength = [Int32]::MaxValue
try {
    # PowerShell 2 consumes redirected text through its input pipeline; reading
    # Console.In again returns an empty stream. JSON whitespace is insignificant.
    $request = $json.DeserializeObject(($input | Out-String))
    if (-not (Get-Command Get-AdfsRelyingPartyTrust -ErrorAction SilentlyContinue)) {
        $snapin = Get-PSSnapin -Registered | Where-Object {
            $_.Name -eq 'Microsoft.Adfs.PowerShell'
        }
        if ($snapin) {
            Add-PSSnapin Microsoft.Adfs.PowerShell
        }
        else {
            Import-Module ADFS
        }
    }
    $p = @{}
    foreach ($key in $request['parameters'].Keys) {
        $p[$key] = $request['parameters'][$key]
    }
    $result = @{}
    switch ($request['operation']) {
        'inspect' {
            $trust = Get-AdfsRelyingPartyTrust -Name $p['Name'] -ErrorAction Stop
            $result['trust'] = $null
            if ($trust) {
                $row = @{
                    Identifier = [string[]]@($trust.Identifier)
                    Enabled = $trust.Enabled
                    MonitoringEnabled = $trust.MonitoringEnabled
                    IssuanceTransformRules = $trust.IssuanceTransformRules
                    IssuanceAuthorizationRules = $trust.IssuanceAuthorizationRules
                }
                foreach ($name in @('AutoUpdateEnabled', 'TokenLifetime', 'Notes',
                                    'AccessControlPolicyName', 'SignatureAlgorithm',
                                    'EncryptClaims')) {
                    $row[$name] = $trust.$name
                }
                $result['trust'] = $row
            }
            $commands = @{}
            foreach ($name in @('Add-AdfsRelyingPartyTrust',
                               'Set-AdfsRelyingPartyTrust',
                               'Enable-AdfsRelyingPartyTrust',
                               'Disable-AdfsRelyingPartyTrust',
                               'Remove-AdfsRelyingPartyTrust',
                               'New-AdfsSamlEndpoint')) {
                $command = Get-Command $name -ErrorAction SilentlyContinue
                if ($command) { $commands[$name] = [string[]]@($command.Parameters.Keys) }
            }
            $result['commands'] = $commands
        }
        'probe_metadata' {
            $response = [Net.WebRequest]::Create([Uri]$p['Uri']).GetResponse()
            $response.Close()
        }
        'create' {
            if ($p.ContainsKey('MetadataUrl')) { $p['MetadataUrl'] = [Uri]$p['MetadataUrl'] }
            if ($p.ContainsKey('WSFedEndpoint')) { $p['WSFedEndpoint'] = [Uri]$p['WSFedEndpoint'] }
            if ($p.ContainsKey('Identifier')) { $p['Identifier'] = [string[]]$p['Identifier'] }
            if ($p.ContainsKey('EndpointUris')) {
                $endpoints = @($p['EndpointUris'] | ForEach-Object {
                    New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $_
                })
                $p.Remove('EndpointUris')
                $p['SamlEndpoint'] = $endpoints
            }
            Add-AdfsRelyingPartyTrust @p -Confirm:$false | Out-Null
        }
        'update' { Set-AdfsRelyingPartyTrust @p | Out-Null }
        'enable' { Enable-AdfsRelyingPartyTrust @p | Out-Null }
        'disable' { Disable-AdfsRelyingPartyTrust @p | Out-Null }
        'remove' { Remove-AdfsRelyingPartyTrust @p -Confirm:$false | Out-Null }
        default { throw 'Unknown AD FS operation.' }
    }
    [Console]::Out.Write($json.Serialize($result))
}
catch {
    [Console]::Out.Write($json.Serialize(@{failed=$true; message=[string]$_}))
    exit 1
}
"""

_PROPERTIES = (
    ("monitoring_enabled", "MonitoringEnabled"),
    ("auto_update_enabled", "AutoUpdateEnabled"),
    ("token_lifetime", "TokenLifetime"),
    ("notes", "Notes"),
    ("access_control_policy_name", "AccessControlPolicyName"),
    ("signature_algorithm", "SignatureAlgorithm"),
    ("encrypt_claims", "EncryptClaims"),
)
_SIGNATURES = {
    "rsa_sha1": "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    "rsa_sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
}


def run_vendor(operation, parameters):
    """Invoke one fixed AD FS operation with JSON on standard input.

    :param str operation: Inspect, create, update, enable, disable, remove or probe.
    :param dict parameters: Data-only vendor parameter names and values.
    :returns: The vendor observations, without formatting object properties.
    :rtype: dict
    :raises OSError: If the installed engine, snap-in or vendor operation fails.
    """
    root = os.environ.get("SystemRoot", r"C:\Windows")
    system = "Sysnative" if os.environ.get("PROCESSOR_ARCHITEW6432") else "System32"
    executable = os.path.join(
        root, system, "WindowsPowerShell", "v1.0", "powershell.exe"
    )
    encoded = base64.b64encode(_VENDOR_SCRIPT.encode("utf-16-le")).decode("ascii")
    command = [
        executable,
        "-NoProfile",
        "-NonInteractive",
        "-InputFormat",
        "Text",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    ]
    with subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:
        stdout, stderr = process.communicate(
            json.dumps({"operation": operation, "parameters": parameters}).encode(
                "utf-8"
            )
        )
    try:
        response = json.loads(stdout.decode("utf-8-sig"))
    except (ValueError, UnicodeError) as error:
        raise OSError(
            "AD FS management did not return JSON; verify the installed PowerShell "
            "and AD FS management commands: "
            + stderr.decode("utf-8", "replace").strip()
        ) from error
    if not isinstance(response, dict):
        raise OSError("AD FS management returned an invalid response.")
    if response.get("failed") or process.returncode:
        raise OSError(response.get("message") or "AD FS management process failed.")
    return response


def _common(arguments):
    values = dict(arguments)
    values["name"] = as_string(arguments.get("name"), "name")
    if values["name"] is None:
        raise ValueError("missing required arguments: name")
    values["state"] = as_string(arguments.get("state", "present"), "state")
    if values["state"] is not None:
        values["state"] = values["state"].lower()
    if values["state"] not in ("present", "absent"):
        raise ValueError("state must be present or absent.")
    values["_ansible_check_mode"] = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    return values


def trust_parameters(arguments):
    """Apply the released relying-party parameter types and validation rules.

    :param dict arguments: Raw public module inputs.
    :returns: Converted trust inputs and check-mode flag.
    :rtype: dict
    :raises ValueError: If required, exclusive or typed options are invalid.
    """
    values = _common(arguments)
    for name in (
        "metadata_url",
        "metadata_file",
        "wsfed_endpoint",
        "notes",
        "access_control_policy_name",
        "signature_algorithm",
    ):
        values[name] = as_string(arguments.get(name), name)
    for name in ("identifier", "saml_endpoint"):
        values[name] = as_string_list(arguments.get(name), name)
    for name in (
        "enabled",
        "monitoring_enabled",
        "auto_update_enabled",
        "encrypt_claims",
    ):
        raw = arguments.get(name)
        values[name] = None if raw is None else as_bool(raw, name)
    lifetime = arguments.get("token_lifetime")
    if lifetime is not None:
        lifetime = as_int32(lifetime, "token_lifetime")
    values["token_lifetime"] = lifetime
    if values["signature_algorithm"] is not None:
        values["signature_algorithm"] = values["signature_algorithm"].lower()
    if (
        values["signature_algorithm"] is not None
        and values["signature_algorithm"] not in _SIGNATURES
    ):
        raise ValueError("signature_algorithm must be rsa_sha1 or rsa_sha256.")
    specified = [
        name
        for name in ("metadata_url", "metadata_file", "identifier")
        if name in arguments
    ]
    if len(specified) > 1:
        raise ValueError(
            "metadata_url, metadata_file and identifier are mutually exclusive."
        )
    if values["state"] == "present" and not specified:
        raise ValueError(
            "state=present requires metadata_url, metadata_file or identifier."
        )
    return values


def claim_parameters(arguments):
    """Apply the released nested claim-rule options without parsing their language.

    :param dict arguments: Raw public module inputs.
    :returns: Converted set/append requests and check-mode flag.
    :rtype: dict
    :raises ValueError: If a nested option or required rule value is invalid.
    """
    values = _common(arguments)
    for name in ("transform_rules", "authorization_rules"):
        rule = as_dictionary(arguments.get(name), name)
        if rule is not None:
            rule = {key.lower(): value for key, value in rule.items()}
            if any(key not in ("value", "update") for key in rule):
                raise ValueError("Unsupported parameters for " + name + ".")
            if rule.get("value") is None:
                raise ValueError(name + " requires value.")
            rule["value"] = as_string_list(rule["value"], name + ".value")
            rule["update"] = as_string(rule.get("update", "set"), name + ".update")
            if rule["update"] is not None:
                rule["update"] = rule["update"].lower()
            if rule["update"] not in ("set", "append"):
                raise ValueError(name + ".update must be set or append.")
        values[name] = rule
    if values["state"] == "present" and all(
        values[name] is None for name in ("transform_rules", "authorization_rules")
    ):
        raise ValueError(
            "state=present requires transform_rules or authorization_rules."
        )
    return values


def _require(commands, command, parameters):
    if command not in commands:
        raise ValueError(
            "The installed AD FS management interface lacks " + command + "."
        )
    available = set(name.lower() for name in commands[command])
    missing = sorted(name for name in parameters if name.lower() not in available)
    if missing:
        raise ValueError(
            "The installed AD FS " + command + " does not support requested "
            "parameter(s): " + ", ".join(missing) + "."
        )


def _invoke(operation, parameters, message):
    try:
        return run_vendor(operation, parameters)
    except OSError as error:
        raise OSError(message + ": " + str(error)) from error


def _inspect(name, message="Failed to retrieve relying party trust"):
    return _invoke("inspect", {"Name": name}, message + " '" + name + "'")


def _properties(values):
    return {
        vendor: (_SIGNATURES[value] if name == "signature_algorithm" else value)
        for name, vendor in _PROPERTIES
        for value in [values[name]]
        if value is not None
    }


def _equal(left, right):
    # PowerShell's ordinary string comparison is case-insensitive; claim-rule
    # append containment is deliberately handled separately and remains literal.
    if isinstance(left, str) and isinstance(right, str):
        return left.lower() == right.lower()
    return left == right


def _create_trust(values, commands, result):
    name, check = values["name"], values["_ansible_check_mode"]
    parameters = dict(_properties(values), Name=name)
    if values["metadata_url"]:
        parameters["MetadataUrl"] = values["metadata_url"]
    elif values["metadata_file"]:
        parameters["MetadataFile"] = values["metadata_file"]
    else:
        parameters["Identifier"] = values["identifier"]
        if values["wsfed_endpoint"]:
            parameters["WSFedEndpoint"] = values["wsfed_endpoint"]
    if values["enabled"] is not None:
        parameters["Enabled"] = values["enabled"]
    requested = list(parameters) + ["Confirm"]
    if values["saml_endpoint"]:
        requested.append("SamlEndpoint")
        _require(commands, "New-AdfsSamlEndpoint", ["Binding", "Protocol", "Uri"])
        parameters["EndpointUris"] = values["saml_endpoint"]
    _require(commands, "Add-AdfsRelyingPartyTrust", requested)
    if values["metadata_url"]:
        _invoke(
            "probe_metadata",
            {"Uri": values["metadata_url"]},
            "Cannot reach metadata URL '" + values["metadata_url"] + "'",
        )
    elif values["metadata_file"] and not os.path.exists(values["metadata_file"]):
        raise ValueError("Metadata file not found: '" + values["metadata_file"] + "'")
    result["changed"] = True
    if check:
        return None
    _invoke("create", parameters, "Failed to create relying party trust '" + name + "'")
    return _inspect(name, "Failed to retrieve newly created trust")["trust"]


def _update_trust(values, existing, commands, result):
    name, check = values["name"], values["_ansible_check_mode"]
    desired = _properties(values)
    # A missing parameter must not silently accept a request it cannot manage.
    if desired:
        _require(commands, "Set-AdfsRelyingPartyTrust", list(desired) + ["TargetName"])
    update = {
        key: value
        for key, value in desired.items()
        if not _equal(value, existing.get(key))
    }
    enabled = values["enabled"]
    enable_operation = None
    if enabled is not None and enabled != existing["Enabled"]:
        enable_operation = "enable" if enabled else "disable"
        _require(
            commands,
            ("Enable" if enabled else "Disable") + "-AdfsRelyingPartyTrust",
            ["TargetName"],
        )
    if update:
        result["changed"] = True
        if not check:
            _invoke(
                "update",
                dict(update, TargetName=name),
                "Failed to update relying party trust '" + name + "'",
            )
    if enable_operation:
        result["changed"] = True
        if not check:
            _invoke(
                enable_operation,
                {"TargetName": name},
                "Failed to set enabled state for relying party trust '" + name + "'",
            )
    if result["changed"] and not check:
        return _inspect(name, "Failed to retrieve updated trust")["trust"]
    return existing


def manage_trust(values, result):
    """Reconcile one trust using the released creation/update/check-mode behavior.

    :param dict values: Validated trust options.
    :param dict result: Caller-owned envelope, updated before attempted writes.
    :raises OSError: Vendor retrieval, creation, update or removal fails.
    :raises ValueError: A requested option is unavailable on the installed vendor.
    """
    name, check = values["name"], values["_ansible_check_mode"]
    observed = _inspect(name)
    existing, commands = observed["trust"], observed["commands"]
    if values["state"] == "absent":
        if existing:
            _require(
                commands, "Remove-AdfsRelyingPartyTrust", ["TargetName", "Confirm"]
            )
            result["changed"] = True
            if not check:
                _invoke(
                    "remove",
                    {"TargetName": name},
                    "Failed to remove relying party trust '" + name + "'",
                )
        return
    if existing is None:
        existing = _create_trust(values, commands, result)
    else:
        existing = _update_trust(values, existing, commands, result)
    if existing:
        result.update(
            identifier=existing["Identifier"],
            enabled=existing["Enabled"],
            monitoring_enabled=existing["MonitoringEnabled"],
        )


def _normalized_rules(value):
    return re.sub("[" + DOTNET_WHITESPACE + "]+", " ", value).strip(DOTNET_WHITESPACE)


def manage_claim_rules(values, result):
    """Set, append or clear vendor-validated rules on an existing relying party.

    :param dict values: Validated rule requests.
    :param dict result: Caller-owned envelope with result and diff observations.
    :raises OSError: Reading or setting rules through the vendor fails.
    :raises ValueError: The trust or requested management capability is absent.
    """
    name = values["name"]
    observed = _inspect(name)
    existing = observed["trust"]
    if existing is None:
        raise ValueError("Relying party trust '" + name + "' not found.")
    update = {}
    for option, vendor in (
        ("transform_rules", "IssuanceTransformRules"),
        ("authorization_rules", "IssuanceAuthorizationRules"),
    ):
        current = (
            (existing.get(vendor) or "").replace("\r\n", "\n").strip(DOTNET_WHITESPACE)
        )
        request = values[option]
        if values["state"] == "absent":
            desired = ""
        elif request is None:
            result[option] = current
            continue
        else:
            joined = "\n".join(request["value"]).strip(DOTNET_WHITESPACE)
            if request["update"] == "append":
                desired = (
                    current
                    if _normalized_rules(joined) in _normalized_rules(current)
                    else current + "\n" + joined
                )
            else:
                desired = joined
        result["diff"]["before"][option] = current
        result["diff"]["after"][option] = desired
        result[option] = desired
        if not _equal(_normalized_rules(current), _normalized_rules(desired)):
            update[vendor] = desired
    if update:
        _require(
            observed["commands"],
            "Set-AdfsRelyingPartyTrust",
            list(update) + ["TargetName"],
        )
        result["changed"] = True
        if not values["_ansible_check_mode"]:
            _invoke(
                "update",
                dict(update, TargetName=name),
                "Failed to set claim rules on '" + name + "'",
            )
