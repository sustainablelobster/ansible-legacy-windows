"""Exercise credential management through its public JSON entry point."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import copy
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Callable
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

Request = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]
SECRET = "Synthetic-Credential-Only"
PARAMETERS = {
    "name": "owned-target",
    "type": "generic_password",
    "username": "ExampleUser",
    "secret": SECRET,
}


@pytest.fixture(name="native")
def native_state() -> Any:
    """Model readable and authentication-provider-only blobs separately.

    :returns: Mutable credential vault and API call recorder.
    """
    state = SimpleNamespace(vault={}, calls=Mock())

    def _read(name: str, kind: int) -> Any:
        record = copy.deepcopy(state.vault.get((name, kind)))
        if record is not None and kind in (2, 3):
            record["secret"] = b""
        return record

    def _write(record: dict[str, Any], preserve: bool) -> None:
        key = (record["name"], record["type"])
        actual = copy.deepcopy(record)
        actual["secret"] = (
            state.vault[key]["secret"] if preserve else record["secret"] or b""
        )
        for entry in actual["attributes"]:
            if entry["data"] is None:
                raise ValueError(
                    "Object reference not set to an instance of an object."
                )
        state.vault[key] = actual

    state.calls.read.side_effect = _read
    state.calls.write.side_effect = _write
    state.calls.delete.side_effect = lambda name, kind: state.vault.pop((name, kind))
    state.calls.certificate_exists.return_value = True
    return state


@pytest.fixture(name="payload")
def credential_payload(monkeypatch: pytest.MonkeyPatch, native: Any) -> ModuleType:
    """Replace only native credential and collation boundaries.

    :param monkeypatch: Scoped native replacements.
    :param native: Independent vault model.
    :returns: Loaded target module.
    """
    module = load_payload("win_credential", monkeypatch)
    for name in ("read", "write", "delete", "certificate_exists"):
        monkeypatch.setattr(module.credential, name, getattr(native.calls, name))
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right: (
            left is right
            if left is None or right is None
            else left.lower() == right.lower()
        ),
    )
    # pylint: enable=duplicate-code
    return module


@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Request:
    """Invoke the unmodified module entry point with a JSON argument file.

    :param payload: Module with native boundaries replaced.
    :param monkeypatch: Scoped argument vector replacement.
    :param tmp_path: Isolated request directory.
    :param capsys: Captured protocol output.
    :returns: Entry-point request function.
    """
    path = tmp_path / "run_request.json"
    monkeypatch.setattr(sys, "argv", ["win_credential.py", str(path)])

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        path.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run


def test_create_check_real_repeat_and_delete_preserve_diff_contract(
    native: Any, run_request: Request
) -> None:
    args = dict(PARAMETERS, _ansible_diff=True)
    expected: dict[str, Any] = {
        "name": "owned-target",
        "type": "Generic",
        "username": "ExampleUser",
        "persistence": "LocalMachine",
        "alias": None,
        "comment": None,
        "attributes": None,
    }
    assert run_request(dict(args, _ansible_check_mode=True)) == (
        0,
        {"changed": True, "diff": {"before": "", "after": expected}},
    )
    assert native.vault == {}
    native.calls.write.assert_not_called()
    expected["attributes"] = []
    assert run_request(args) == (
        0,
        {"changed": True, "diff": {"before": "", "after": expected}},
    )
    assert native.vault[("owned-target", 1)]["secret"] == SECRET.encode("utf-16-le")
    native.calls.reset_mock()
    assert run_request(args) == (
        0,
        {"changed": False, "diff": {"before": expected, "after": expected}},
    )
    native.calls.write.assert_not_called()
    assert native.calls.read.call_count == 2
    remove = {
        "name": "owned-target",
        "type": "generic_password",
        "state": "absent",
        "_ansible_diff": True,
    }
    assert run_request(dict(remove, _ansible_check_mode=True)) == (
        0,
        {"changed": True, "diff": {"before": expected, "after": ""}},
    )
    assert native.vault
    assert run_request(remove) == (
        0,
        {"changed": True, "diff": {"before": expected, "after": ""}},
    )
    assert run_request(remove) == (
        0,
        {"changed": False, "diff": {"before": "", "after": ""}},
    )


def test_comment_case_changes_but_alias_and_username_case_do_not(
    native: Any, run_request: Request
) -> None:
    assert run_request(dict(PARAMETERS, alias="Alias", comment="Comment"))[0] == 0
    args = dict(PARAMETERS, alias="ALIAS", username="EXAMPLEUSER", comment="Comment")
    assert run_request(args) == (0, {"changed": False})
    assert run_request(dict(args, comment="COMMENT")) == (0, {"changed": True})
    record = native.vault[("owned-target", 1)]
    assert record["alias"] == "Alias" and record["username"] == "ExampleUser"
    assert record["comment"] == "COMMENT"


def test_attribute_encoding_order_duplicate_names_and_omitted_preservation(
    native: Any, run_request: Request
) -> None:
    attributes = [
        {"name": "same", "data": "雪"},
        {"name": "same", "data": "AAE=", "data_format": "base64"},
    ]
    args = dict(PARAMETERS, attributes=attributes, _ansible_diff=True)
    status, checked = run_request(dict(args, _ansible_check_mode=True))
    assert status == 0
    assert checked["diff"]["after"]["attributes"] == [
        dict(attributes[0], data_format="text"),
        attributes[1],
    ]
    status, written = run_request(args)
    assert status == 0
    assert written["diff"]["after"]["attributes"] == [
        {"name": "same", "data": base64.b64encode("雪".encode("utf-8")).decode()},
        {"name": "same", "data": "AAE="},
    ]
    assert run_request(args)[1]["changed"] is False
    assert run_request(PARAMETERS) == (0, {"changed": False})
    assert len(native.vault[("owned-target", 1)]["attributes"]) == 2
    assert (
        run_request(dict(args, attributes=list(reversed(attributes))))[1]["changed"]
        is True
    )
    assert (
        run_request(dict(args, attributes=[]))[1]["diff"]["after"]["attributes"] == []
    )


def test_case_insensitive_base64_comparison_preserves_upstream_quirk(
    native: Any, run_request: Request
) -> None:
    args = dict(
        PARAMETERS,
        secret="AA==",
        secret_format="base64",
        attributes=[{"name": "a", "data": "AA==", "data_format": "base64"}],
    )
    assert run_request(args) == (0, {"changed": True})
    assert run_request(
        dict(
            args,
            secret="aA==",
            attributes=[{"name": "a", "data": "aA==", "data_format": "base64"}],
        )
    ) == (0, {"changed": False})
    assert native.vault[("owned-target", 1)]["secret"] == b"\0"


@pytest.mark.parametrize("value", ["AAAA=", "AAAA=="])
@pytest.mark.parametrize("field", ["secret", "attributes"])
def test_excess_padding_returns_upstream_failure_without_mutation_or_diff(
    native: Any,
    run_request: Request,
    value: str,
    field: str,
) -> None:
    arguments: dict[str, Any] = dict(PARAMETERS, _ansible_diff=True)
    if field == "secret":
        arguments.update(secret=value, secret_format="base64")
    else:
        arguments["attributes"] = [
            {"name": "padding", "data": value, "data_format": "base64"}
        ]
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    status, result = run_request(arguments)
    assert status == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": (
            "Unhandled exception while executing module: Exception calling "
            '"FromBase64String" with "1" argument(s): '
            '"Invalid length for a Base-64 char array or string."'
        ),
        "exception": "(traceback unavailable)",
    }
    # pylint: enable=duplicate-code
    native.calls.write.assert_not_called()
    assert native.vault == {}


@pytest.mark.parametrize(
    "value,expected",
    [
        ("\ud800", "\ufffd"),
        ("\udc00", "\ufffd"),
        ("\ud800A\udc00", "\ufffdA\ufffd"),
        ("\ud83d\ude00", "\U0001f600"),
    ],
)
def test_text_encoding_replaces_unpaired_surrogates_and_preserves_pairs(
    native: Any, run_request: Request, value: str, expected: str
) -> None:
    assert run_request(
        dict(PARAMETERS, secret=value, attributes=[{"name": "text", "data": value}])
    ) == (0, {"changed": True})
    record = native.vault[("owned-target", 1)]
    assert record["secret"] == expected.encode("utf-16-le")
    assert record["attributes"][0]["data"] == expected.encode("utf-8")


@pytest.mark.parametrize("kind", ["generic_password", "domain_password"])
def test_omitted_secret_preserves_blob_when_other_fields_change(
    native: Any, run_request: Request, kind: str
) -> None:
    args = dict(PARAMETERS, type=kind)
    assert run_request(args) == (0, {"changed": True})
    del args["secret"]
    assert run_request(dict(args, comment="changed")) == (0, {"changed": True})
    assert native.calls.write.call_args.args[1] is True
    assert next(iter(native.vault.values()))["secret"] == SECRET.encode("utf-16-le")


def test_domain_always_changes_and_on_create_skips_unreadable_secret(
    run_request: Request,
) -> None:
    args = dict(PARAMETERS, type="domain_password")
    assert run_request(args) == (0, {"changed": True})
    assert run_request(args) == (0, {"changed": True})
    assert run_request(dict(args, update_secret="on_create", secret="Other")) == (
        0,
        {"changed": False},
    )


def test_empty_secret_always_predicts_change_but_omission_does_not(
    run_request: Request,
) -> None:
    args = dict(PARAMETERS, secret="")
    assert run_request(args) == (0, {"changed": True})
    assert run_request(dict(args, _ansible_check_mode=True)) == (0, {"changed": True})
    assert run_request(dict(args, secret=None)) == (0, {"changed": False})


def test_certificate_normalization_check_mode_and_invocation_remain_separate(
    native: Any, run_request: Request
) -> None:
    username = "aa-bb " * 10
    args = dict(
        PARAMETERS,
        type="generic_certificate",
        username=username,
        _ansible_diff=True,
        _ansible_check_mode=True,
        _ansible_inject_invocation=True,
    )
    status, result = run_request(args)
    assert status == 0 and result["changed"] is True
    native.calls.certificate_exists.assert_called_once_with("AABB" * 10)
    assert result["diff"]["after"]["username"] == "AABB" * 10
    assert result["invocation"]["module_args"]["username"] == username
    native.calls.write.assert_not_called()


def test_certificate_failure_precedes_secret_conversion_and_store_access(
    native: Any, run_request: Request
) -> None:
    native.calls.certificate_exists.return_value = False
    status, result = run_request(
        dict(
            PARAMETERS,
            type="domain_certificate",
            username="00",
            secret="!!",
            secret_format="base64",
            state="absent",
        )
    )
    assert status == 1
    assert (
        result["msg"]
        == "Failed to find certificate with the thumbprint 00 in the CurrentUser\\My store"
    )
    native.calls.read.assert_not_called()


def test_null_attribute_data_allows_prediction_but_real_writer_fails(
    native: Any, run_request: Request
) -> None:
    args = dict(PARAMETERS, attributes=[{"name": "empty"}])
    assert run_request(dict(args, _ansible_check_mode=True)) == (0, {"changed": True})
    status, result = run_request(args)
    assert status == 1 and result["changed"] is False
    assert native.vault == {}


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: name, type"),
        (
            {"name": "owned", "type": "generic_password"},
            "state is present but all of the following are missing: username",
        ),
        (
            dict(PARAMETERS, attributes=[{}]),
            "missing required arguments: name found in attributes",
        ),
    ],
)
def test_required_options_fail_before_native_calls(
    native: Any, run_request: Request, arguments: dict[str, Any], message: str
) -> None:
    status, result = run_request(arguments)
    assert status == 1 and result["msg"] == message
    assert native.calls.mock_calls == []


@pytest.mark.parametrize(
    "secret",
    ["failed", "changed", "False", ["Nested-Secret"], {"key": "Nested-Secret"}],
)
def test_secret_redaction_preserves_protocol_and_masks_coerced_invocation(
    native: Any, run_request: Request, secret: Any
) -> None:
    native.calls.read.side_effect = OSError("Credential lookup failed")
    status, result = run_request(
        dict(PARAMETERS, secret=secret, _ansible_inject_invocation=True)
    )
    assert status == 1 and result["failed"] is True and result["changed"] is False
    assert (
        result["invocation"]["module_args"]["secret"]
        == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    )
    assert "Nested-Secret" not in json.dumps(result)


def test_diff_coincidence_is_not_globally_redacted(run_request: Request) -> None:
    status, result = run_request(
        dict(
            PARAMETERS,
            secret="ExampleUser",
            _ansible_diff=True,
            _ansible_check_mode=True,
        )
    )
    assert status == 0 and result["diff"]["after"]["username"] == "ExampleUser"
    assert "secret" not in result["diff"]["after"]
