# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Keep directory credentials out of result values, keys and invocation data."""

from legacy_windows_module import as_bool, as_dictionary  # pylint: disable=import-error

NO_LOG = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
_SECRET_PARAMETERS = (
    "domain_password",
    "password",
    "old_password",
    "domain_admin_password",
    "offline_join_blob",
    "trust_password",
    "safe_mode_password",
    "local_admin_password",
)


def _secret_values(value):
    if isinstance(value, dict):
        values = []
        for item in value.values():
            values.extend(_secret_values(item))
        return values
    if isinstance(value, (list, tuple)):
        values = []
        for item in value:
            values.extend(_secret_values(item))
        return values
    return [] if value is None or value == "" else [str(value)]


def _password_values(arguments):
    secrets = []
    for name in _SECRET_PARAMETERS:
        secrets.extend(_secret_values(arguments.get(name)))
    credentials = arguments.get("domain_credentials") or []
    credentials = [credentials] if isinstance(credentials, dict) else credentials
    if isinstance(credentials, list):
        for entry in credentials:
            if isinstance(entry, str):
                try:
                    entry = as_dictionary(entry, "domain_credentials")
                except ValueError:
                    # Invalid dictionary strings cannot expose their fields;
                    # keep the entire credential entry out of failure output.
                    secrets.append(entry)
                    continue
            if isinstance(entry, dict):
                secrets.extend(_secret_values(entry.get("password")))
    return secrets


def _redact(value, secrets, preserve_keys=False):
    if isinstance(value, dict):
        return {
            (key if preserve_keys else _redact(key, secrets)): _redact(
                item, secrets, preserve_keys=preserve_keys
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, secrets, preserve_keys=preserve_keys) for item in value]
    if isinstance(value, tuple):
        return tuple(
            _redact(item, secrets, preserve_keys=preserve_keys) for item in value
        )
    if not isinstance(value, str):
        # Boolean status fields are not strings or numeric secret values.
        return (
            NO_LOG
            if not isinstance(value, bool)
            and value is not None
            and str(value) in secrets
            else value
        )
    if value == NO_LOG:
        return value
    for secret in secrets:
        value = value.replace(secret, NO_LOG)
    return value


def _redact_diff(value, secrets):
    if isinstance(value, list):
        return [_redact_diff(item, secrets) for item in value]
    if not isinstance(value, dict):
        return _redact(value, secrets)
    output = {}
    for name, snapshot in value.items():
        if name in ("before", "after") and isinstance(snapshot, dict):
            # Snapshot labels are module options; only their raw-attribute
            # dictionary contains directory/user-selected keys.
            redacted = {}
            for key, item in snapshot.items():
                if key == "attributes" and isinstance(item, dict):
                    redacted[key] = {
                        _redact(attribute, secrets): _redact(
                            data, secrets, preserve_keys=True
                        )
                        for attribute, data in item.items()
                    }
                else:
                    redacted[key] = _redact(item, secrets, preserve_keys=True)
            output[name] = redacted
        else:
            # Ansible owns before/after and their optional header labels.
            output[name] = _redact(snapshot, secrets, preserve_keys=True)
    return output


def _redact_objects(value, secrets):
    if not isinstance(value, list):
        return _redact(value, secrets)
    output = []
    for row in value:
        if not isinstance(row, dict):
            output.append(_redact(row, secrets))
            continue
        output.append(
            {
                (
                    name
                    if name
                    in ("DistinguishedName", "Name", "ObjectClass", "ObjectGUID")
                    else _redact(name, secrets)
                ): _redact(item, secrets, preserve_keys=True)
                for name, item in row.items()
            }
        )
    return output


def sanitize_result(result, arguments, normalized_arguments=None):
    """Remove supplied passwords from the complete result and optional invocation.

    Raw arguments preserve secrets even when option validation fails. Normalized
    arguments additionally cover successful string/number coercions. Only the
    caller's public input is included when Ansible requests invocation data.

    Fixed result, diff, snapshot and default object-info labels remain intact
    so passwords matching them cannot alter status, rendering or the public
    interface. Raw attribute keys, extra requested LDAP property names and
    arbitrary invocation data remain subject to key and value redaction.

    :param result: Module-owned envelope, including partial state and optional diff.
    :type result: dict
    :param arguments: Raw arguments read before module-specific validation.
    :type arguments: dict
    :param normalized_arguments: Validated arguments with any coerced passwords.
    :type normalized_arguments: dict or None
    :returns: A copied result with credential data redacted and protocol intact.
    :rtype: dict
    """
    secrets = _password_values(arguments)
    if normalized_arguments is not None:
        secrets.extend(_password_values(normalized_arguments))
    secrets = sorted(set(secrets), key=len, reverse=True)
    output = dict(result)
    try:
        inject_invocation = as_bool(
            arguments.get("_ansible_inject_invocation", False),
            "_ansible_inject_invocation",
        )
    except ValueError as exc:
        output.update({"failed": True, "msg": str(exc)})
        inject_invocation = False
    output = {name: _redact(value, secrets) for name, value in output.items()}
    if "diff" in result:
        output["diff"] = _redact_diff(result["diff"], secrets)
    if "objects" in result:
        output["objects"] = _redact_objects(result["objects"], secrets)
    if inject_invocation:
        output["invocation"] = {
            "module_args": _redact(
                {
                    name: value
                    for name, value in arguments.items()
                    if not name.startswith("_ansible_")
                },
                secrets,
            )
        }
    return output
