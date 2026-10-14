"""Verify complete password redaction independently of directory operations."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib
import json
from types import ModuleType

import pytest

# Ansible supplies the real rendering contract but does not ship typing markers.
from ansible.plugins.callback import CallbackBase  # type: ignore[import-untyped]

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="sanitizer")
def result_sanitizer(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the real target helper through its target-owned dependency closure.

    :param monkeypatch: Scoped helper import path.
    :returns: The native result formatter without running a module.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        ROOT / "legacy_ad/plugins/module_utils/legacy_ad_result.py", "tested_ad_result"
    )


def test_all_password_fields_nested_credentials_keys_and_values_are_redacted(
    sanitizer: ModuleType,
) -> None:
    arguments = {
        "password": "UserSecret1!",
        "old_password": "OldSecret2!",
        "domain_password": "DomainSecret3!",
        "domain_credentials": [
            {
                "name": "other.example.test",
                "username": "admin",
                "password": "ForeignSecret4!",
            }
        ],
    }
    result = {
        "diff": {
            "after": {
                "attributes": {
                    "UserSecret1!": [
                        "OldSecret2!",
                        {"note": "prefix DomainSecret3! suffix"},
                    ]
                }
            }
        },
        "msg": "ForeignSecret4! failure",
    }
    redacted = sanitizer.sanitize_result(result, arguments)
    serialized = json.dumps(redacted)
    for secret in ("UserSecret1!", "OldSecret2!", "DomainSecret3!", "ForeignSecret4!"):
        assert secret not in serialized
    assert redacted["diff"]["after"]["attributes"] == {
        sanitizer.NO_LOG: [
            sanitizer.NO_LOG,
            {"note": "prefix " + sanitizer.NO_LOG + " suffix"},
        ]
    }
    assert result["msg"] == "ForeignSecret4! failure"


def test_invocation_records_only_public_input_and_hides_every_password(
    sanitizer: ModuleType,
) -> None:
    arguments = {
        "name": "Alice",
        "password": "UserSecret1!",
        "domain_password": "DomainSecret3!",
        "domain_credentials": [{"password": "ForeignSecret4!", "username": "admin"}],
        "_ansible_inject_invocation": True,
        "_ansible_check_mode": True,
    }
    result = sanitizer.sanitize_result({"changed": False}, arguments)
    invocation = result["invocation"]["module_args"]
    assert invocation["name"] == "Alice"
    assert invocation["password"] == sanitizer.NO_LOG
    assert invocation["domain_password"] == sanitizer.NO_LOG
    assert invocation["domain_credentials"][0]["password"] == sanitizer.NO_LOG
    assert not any(key.startswith("_ansible_") for key in invocation)


def test_failed_option_coercions_do_not_leak_nested_password_input(
    sanitizer: ModuleType,
) -> None:
    arguments = {
        "password": {"value": "InvalidSecret1!"},
        "domain_credentials": {"password": ["InvalidSecret2!"]},
    }
    result = sanitizer.sanitize_result(
        {"failed": True, "msg": "Cannot convert InvalidSecret1! or InvalidSecret2!"},
        arguments,
    )
    assert "InvalidSecret" not in json.dumps(result)


def test_normalized_locale_secret_and_numeric_result_values_are_redacted(
    sanitizer: ModuleType,
) -> None:
    arguments = {"password": 1.5}
    result = sanitizer.sanitize_result(
        {"raw": 1.5, "stored": "1,5"}, arguments, {"password": "1,5"}
    )
    assert result == {"raw": sanitizer.NO_LOG, "stored": sanitizer.NO_LOG}


def test_empty_missing_passwords_do_not_hide_nonsecret_output(
    sanitizer: ModuleType,
) -> None:
    result = {"changed": False, "values": [None, "", 0, True], "msg": "ordinary result"}
    assert (
        sanitizer.sanitize_result(result, {"password": "", "domain_password": None})
        == result
    )


def test_overlapping_secrets_are_processed_longest_first(sanitizer: ModuleType) -> None:
    result = sanitizer.sanitize_result(
        {"msg": "LongSecretSuffix and LongSecret"},
        {"password": "LongSecret", "domain_password": "LongSecretSuffix"},
    )
    assert result["msg"] == sanitizer.NO_LOG + " and " + sanitizer.NO_LOG


def test_tuple_values_and_scalar_dictionary_keys_are_also_sanitized(
    sanitizer: ModuleType,
) -> None:
    result = sanitizer.sanitize_result(
        {"values": {1234: ("1234", "safe")}}, {"old_password": 1234}
    )
    assert result == {"values": {sanitizer.NO_LOG: (sanitizer.NO_LOG, "safe")}}


@pytest.mark.parametrize(
    "password",
    ["changed", "failed", "msg", "reboot_required", "objects", "object_guid"],
)
def test_password_matching_result_fields_does_not_rename_the_protocol(
    sanitizer: ModuleType, password: str
) -> None:
    result = sanitizer.sanitize_result(
        {
            "changed": True,
            "failed": True,
            "msg": password,
            "reboot_required": True,
            "objects": [{password: password}],
            "object_guid": password,
        },
        {"password": password},
    )
    assert result == {
        "changed": True,
        "failed": True,
        "msg": sanitizer.NO_LOG,
        "reboot_required": True,
        "objects": [{sanitizer.NO_LOG: sanitizer.NO_LOG}],
        "object_guid": sanitizer.NO_LOG,
    }


@pytest.mark.parametrize("password", ["changed", "failed", "module_args"])
def test_protocol_key_password_preserves_failure_exit_status_and_invocation(
    sanitizer: ModuleType, password: str, capsys: pytest.CaptureFixture[str]
) -> None:
    failed_result = sanitizer.sanitize_result(
        {"changed": True, "failed": True, "msg": password},
        {"password": password, "_ansible_inject_invocation": True},
    )

    with pytest.raises(SystemExit) as stopped:
        importlib.import_module("legacy_windows_module").run_module(
            lambda: failed_result
        )
    assert stopped.value.code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["changed"] is True and result["failed"] is True
    assert result["msg"] == sanitizer.NO_LOG
    assert result["invocation"]["module_args"]["password"] == sanitizer.NO_LOG


@pytest.mark.parametrize(
    "password", ["before", "after", "before_header", "after_header"]
)
def test_password_matching_diff_fields_preserves_ansible_rendering(
    sanitizer: ModuleType, password: str
) -> None:
    result = sanitizer.sanitize_result(
        {
            "changed": True,
            "diff": {
                "before": "old value\n",
                "after": "new value\n",
                "before_header": "old file",
                "after_header": "new file",
            },
        },
        {"password": password},
    )
    # The callback's renderer is private; calling it proves actual --diff output.
    # pylint: disable-next=protected-access
    rendered = CallbackBase()._get_diff(result["diff"])
    assert "-old value" in rendered
    assert "+new value" in rendered
    assert "--- before: old file" in rendered
    assert "+++ after: new file" in rendered


@pytest.mark.parametrize("password", ["name", "path", "attributes", "members"])
def test_password_matching_diff_snapshot_fields_preserves_labels_and_hides_data(
    sanitizer: ModuleType, password: str
) -> None:
    snapshot = {
        "name": "Ansible Group",
        "path": "OU=Tests,DC=example,DC=test",
        "attributes": {password: [password]},
        "members": [password],
    }
    result = sanitizer.sanitize_result(
        {"diff": [{"before": None, "after": snapshot}]},
        {"password": password},
    )
    after = result["diff"][0]["after"]
    assert set(after) == {"name", "path", "attributes", "members"}
    assert after["name"] == "Ansible Group"
    assert after["path"] == "OU=Tests,DC=example,DC=test"
    assert after["attributes"] == {sanitizer.NO_LOG: [sanitizer.NO_LOG]}
    assert after["members"] == [sanitizer.NO_LOG]


@pytest.mark.parametrize(
    "password", ["DistinguishedName", "Name", "ObjectClass", "ObjectGUID", "Sid"]
)
def test_object_info_fixed_fields_and_typed_sid_labels_are_preserved(
    sanitizer: ModuleType, password: str
) -> None:
    result = sanitizer.sanitize_result(
        {
            "objects": [
                {
                    "DistinguishedName": "CN=Alice,DC=example,DC=test",
                    "Name": "Alice",
                    "ObjectClass": "user",
                    "ObjectGUID": "5a80fc97-58c5-4ba7-933c-682b8e157c25",
                    "objectSid": {"Sid": "S-1-5-32-544", "Name": password},
                    "description": password,
                }
            ]
        },
        {"domain_password": password},
    )
    row = result["objects"][0]
    sid_property = "object" + sanitizer.NO_LOG if password == "Sid" else "objectSid"
    assert set(row) == {
        "DistinguishedName",
        "Name",
        "ObjectClass",
        "ObjectGUID",
        sid_property,
        "description",
    }
    assert row["ObjectGUID"] == "5a80fc97-58c5-4ba7-933c-682b8e157c25"
    assert row[sid_property] == {"Sid": "S-1-5-32-544", "Name": sanitizer.NO_LOG}
    assert row["description"] == sanitizer.NO_LOG


def test_extra_property_and_arbitrary_invocation_keys_still_hide_credentials(
    sanitizer: ModuleType,
) -> None:
    password = "SecretProperty1!"
    result = sanitizer.sanitize_result(
        {"objects": [{"Name": "Alice", password: [password]}]},
        {
            "domain_password": password,
            "properties": [password],
            password: {password: password},
            "_ansible_inject_invocation": True,
        },
    )
    assert password not in json.dumps(result)
    assert result["objects"][0] == {
        "Name": "Alice",
        sanitizer.NO_LOG: [sanitizer.NO_LOG],
    }
    assert result["invocation"]["module_args"][sanitizer.NO_LOG] == {
        sanitizer.NO_LOG: sanitizer.NO_LOG
    }


def test_raw_attribute_diff_preserves_schema_owned_sid_labels(
    sanitizer: ModuleType,
) -> None:
    result = sanitizer.sanitize_result(
        {
            "diff": {
                "before": None,
                "after": {
                    "attributes": {
                        "objectSid": [{"Sid": "S-1-5-32-544", "Name": "Sid"}]
                    }
                },
            }
        },
        {"password": "Sid"},
    )
    assert result["diff"]["after"]["attributes"] == {
        "object" + sanitizer.NO_LOG: [{"Sid": "S-1-5-32-544", "Name": sanitizer.NO_LOG}]
    }


def test_membership_no_log_password_and_offline_blob_are_sanitized(
    sanitizer: ModuleType,
) -> None:
    result = sanitizer.sanitize_result(
        {"msg": "AdminSecret1!", "blob": "OpaqueJoinBlob2!"},
        {
            "domain_admin_password": "AdminSecret1!",
            "offline_join_blob": "OpaqueJoinBlob2!",
        },
    )
    assert result == {"msg": sanitizer.NO_LOG, "blob": sanitizer.NO_LOG}


@pytest.mark.parametrize("password", ["True", "False"])
def test_boolean_status_is_preserved_when_password_looks_boolean(
    sanitizer: ModuleType, password: str
) -> None:
    result = sanitizer.sanitize_result(
        {"changed": True, "failed": False, "msg": password}, {"password": password}
    )
    assert result == {"changed": True, "failed": False, "msg": sanitizer.NO_LOG}


def test_invalid_invocation_flag_returns_a_redacted_failure_with_partial_state(
    sanitizer: ModuleType,
) -> None:
    result = sanitizer.sanitize_result(
        {"changed": True, "distinguished_name": "CN=Alice,DC=example,DC=test"},
        {"password": "SecretFlag1!", "_ansible_inject_invocation": "SecretFlag1!"},
    )
    assert result["changed"] is True
    assert result["failed"] is True
    assert result["distinguished_name"] == "CN=Alice,DC=example,DC=test"
    assert "SecretFlag1!" not in json.dumps(result)
    assert "_ansible_inject_invocation" in result["msg"]


@pytest.mark.parametrize(
    "credential",
    [
        "username=admin password=StringSecret1! invalid=option",
        '{"username":"admin","password":"StringSecret1!","invalid":"option"}',
    ],
)
def test_dictionary_string_credentials_are_redacted_even_before_validation(
    sanitizer: ModuleType, credential: str
) -> None:
    result = sanitizer.sanitize_result(
        {"failed": True, "msg": "StringSecret1! failed"},
        {"domain_credentials": [credential], "_ansible_inject_invocation": True},
    )
    assert "StringSecret1!" not in json.dumps(result)


def test_unparsable_credential_string_is_not_echoed_in_invocation(
    sanitizer: ModuleType,
) -> None:
    credential = "unparsable credential StringSecret1!"
    result = sanitizer.sanitize_result(
        {"failed": True, "msg": credential},
        {"domain_credentials": [credential], "_ansible_inject_invocation": True},
    )
    assert result["msg"] == sanitizer.NO_LOG
    assert result["invocation"]["module_args"]["domain_credentials"] == [
        sanitizer.NO_LOG
    ]


@pytest.mark.parametrize(
    "name", ["trust_password", "safe_mode_password", "local_admin_password"]
)
def test_trust_and_promotion_no_log_parameters_are_redacted(
    sanitizer: ModuleType, name: str
) -> None:
    result = sanitizer.sanitize_result(
        {"msg": "PromotionSecret1!"},
        {name: "PromotionSecret1!", "_ansible_inject_invocation": True},
    )
    assert result["msg"] == sanitizer.NO_LOG
    assert result["invocation"]["module_args"][name] == sanitizer.NO_LOG
