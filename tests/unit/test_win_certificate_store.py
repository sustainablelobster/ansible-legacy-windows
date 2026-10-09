"""Exercise complete certificate-store public results and partial effects."""

# SPDX-License-Identifier: GPL-3.0-or-later

from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

THUMBPRINT = "1234567890ABCDEF1234567890ABCDEF12345678"
OTHER = "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
PATH = r"C:\owned\certificate.der"


class Collection:
    """Supply retained input/store records without native Windows dependencies."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self.records = records
        self.add = Mock()
        self.remove = Mock()
        self.entered = False
        self.closed = False

    def __enter__(self) -> "Collection":
        self.entered = True
        return self

    def __exit__(self, *_arguments: Any) -> None:
        self.closed = True


@pytest.fixture(name="runner")
def certificate_store_runner(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> Any:
    """Load the real payload behind observable certificate and file substitutes.

    :param monkeypatch: Scoped native and filesystem substitutions.
    :param capsys: Complete JSON-result capture.
    :returns: Public request runner and native boundaries.
    """
    module = load_payload("win_certificate_store", monkeypatch)
    store = Collection([])
    record = {"thumbprint": THUMBPRINT, "has_private_key": False, "context": 41}
    loaded = Collection([record])
    native = SimpleNamespace(
        open_store=Mock(return_value=store),
        read_file=Mock(return_value=loaded),
        matches=Mock(
            side_effect=lambda rows, thumb: [
                row for row in rows if row["thumbprint"].lower() == thumb.lower()
            ]
        ),
        export_certificate=Mock(return_value=b"DER"),
        key_exportable=Mock(return_value=True),
        service_name=Mock(return_value=["OwnedService"]),
        missing_service_stores=Mock(return_value=[]),
        register_service_store=Mock(),
        store_error=Mock(return_value="native store error"),
    )
    for name, function in vars(native).items():
        monkeypatch.setattr(module.certificates, name, function)
    exists = {PATH}
    monkeypatch.setattr(module.os.path, "isfile", lambda path: path in exists)
    monkeypatch.setattr(module.os.path, "isdir", lambda _path: False)
    monkeypatch.setattr(module.os.path, "lexists", lambda path: path in exists)
    remove_file = Mock(side_effect=exists.discard)
    monkeypatch.setattr(module.os, "remove", remove_file)

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        monkeypatch.setattr(module, "read_arguments", lambda *_arguments: arguments)
        return invoke_payload(module, capsys)

    return SimpleNamespace(
        run=_run,
        module=module,
        native=native,
        store=store,
        loaded=loaded,
        record=record,
        files=exists,
        remove_file=remove_file,
    )


@pytest.mark.parametrize("suffix", [".pfx", ".p12"])
def test_legacy_matching_pfx_export_does_not_rewrite_destination(
    runner: Any,
    suffix: str,
) -> None:
    path = r"C:\owned\export" + suffix
    runner.files.add(path)
    runner.record["has_private_key"] = True
    runner.native.read_file.side_effect = [NotImplementedError(), runner.loaded]
    code, result = runner.run(
        {
            "state": "exported",
            "path": path,
            "thumbprint": THUMBPRINT,
            "file_type": "pkcs12",
        }
    )
    assert code == 0 and result == {"changed": False, "thumbprints": [THUMBPRINT]}
    assert runner.native.read_file.call_args_list[0].args == (
        path,
        None,
        False,
        "default",
    )
    assert runner.native.read_file.call_args_list[0].kwargs == {"persist": False}
    runner.remove_file.assert_not_called()
    runner.native.export_certificate.assert_not_called()
    assert runner.loaded.closed


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "state is present but all of the following are missing: path"),
        (
            {"state": "absent"},
            "state is absent but any of the following are missing: path, thumbprint",
        ),
        (
            {"state": "exported"},
            "state is exported but all of the following are missing: path, thumbprint",
        ),
        (
            {"state": "exported", "path": PATH},
            "state is exported but all of the following are missing: thumbprint",
        ),
    ],
)
def test_missing_arguments_fail_before_result_initialization(
    runner: Any,
    arguments: dict[str, Any],
    message: str,
) -> None:
    assert runner.run(arguments) == (
        1,
        {"changed": False, "failed": True, "msg": message},
    )
    runner.native.open_store.assert_not_called()


@pytest.mark.parametrize(
    "name,choices",
    [
        ("state", "absent, exported, present"),
        ("store_type", "service, system"),
        ("key_storage", "default, machine, user"),
        ("file_type", "der, pem, pkcs12"),
    ],
)
def test_choice_validation_preserves_public_diagnostic(
    runner: Any,
    name: str,
    choices: str,
) -> None:
    assert runner.run({"path": PATH, name: "invalid"})[1] == {
        "changed": False,
        "failed": True,
        "msg": f"value of {name} must be one of: {choices}. Got no match for: invalid",
    }


def test_null_required_path_reaches_store_before_file_binding_failure(
    runner: Any,
) -> None:
    status, result = runner.run({"path": None})
    assert status == 1 and result["thumbprints"] == []
    assert "all of the following are missing" not in result["msg"]
    runner.native.open_store.assert_called_once()
    assert runner.store.closed


@pytest.mark.parametrize("check", [False, True])
def test_import_and_check_keep_native_file_reads_even_when_store_is_unchanged(
    runner: Any,
    check: bool,
) -> None:
    runner.store.records = [runner.record]
    assert runner.run({"path": PATH, "_ansible_check_mode": check}) == (
        0,
        {"changed": False, "thumbprints": [THUMBPRINT]},
    )
    runner.native.read_file.assert_called_once_with(PATH, None, True, "default")
    runner.store.add.assert_not_called()
    assert runner.loaded.closed and runner.store.closed


@pytest.mark.parametrize("check", [False, True])
def test_import_missing_and_key_upgrade_predict_exact_change(
    runner: Any, check: bool
) -> None:
    runner.record["has_private_key"] = True
    runner.store.records = [dict(runner.record, has_private_key=False)]
    assert runner.run(
        {
            "path": PATH,
            "key_storage": "machine",
            "key_exportable": False,
            "_ansible_check_mode": check,
        }
    ) == (0, {"changed": True, "thumbprints": [THUMBPRINT]})
    runner.native.read_file.assert_called_once_with(PATH, None, False, "machine")
    assert runner.store.add.call_count == (0 if check else 1)


def test_multi_certificate_import_keeps_order_and_partial_success(runner: Any) -> None:
    runner.loaded.records.append(dict(runner.record, thumbprint=OTHER))
    runner.store.add.side_effect = [None, OSError(5, "denied\r\n")]
    status, result = runner.run({"path": PATH})
    assert status == 1 and result["changed"] is True
    assert result["thumbprints"] == [THUMBPRINT, OTHER]
    assert result["msg"].startswith(
        "Unable to import certificate with thumbprint '" + OTHER
    )
    assert runner.loaded.closed and runner.store.closed


def test_path_precedence_for_removal_ignores_contradictory_thumbprint(
    runner: Any,
) -> None:
    runner.store.records = [runner.record]
    assert runner.run({"state": "absent", "path": PATH, "thumbprint": OTHER}) == (
        0,
        {"changed": True, "thumbprints": [THUMBPRINT]},
    )
    runner.store.remove.assert_called_once_with(runner.record)


@pytest.mark.parametrize("selector", ["path", "thumbprint"])
@pytest.mark.parametrize("check", [False, True])
def test_explicit_null_removal_selector_has_no_selected_certificates(
    runner: Any,
    selector: str,
    check: bool,
) -> None:
    assert runner.run(
        {"state": "absent", selector: None, "_ansible_check_mode": check}
    ) == (0, {"changed": False, "thumbprints": []})
    runner.native.read_file.assert_not_called()
    runner.native.matches.assert_not_called()
    runner.store.remove.assert_not_called()
    assert runner.store.closed


@pytest.mark.parametrize("check", [False, True])
def test_removal_appends_literal_selector_even_when_absent(
    runner: Any, check: bool
) -> None:
    requested = THUMBPRINT.lower()
    assert runner.run(
        {"state": "absent", "thumbprint": requested, "_ansible_check_mode": check}
    ) == (0, {"changed": False, "thumbprints": [requested]})
    runner.store.remove.assert_not_called()


def test_missing_store_failure_precedes_missing_input_file(runner: Any) -> None:
    runner.files.clear()
    runner.native.open_store.side_effect = OSError(2, "missing")
    assert runner.run({"path": PATH, "store_name": "Missing"})[1] == {
        "changed": False,
        "thumbprints": [],
        "failed": True,
        "msg": "unable to find store 'Missing': (native store error)",
        "exception": "(traceback unavailable)",
    }
    runner.native.read_file.assert_not_called()


def test_missing_file_keeps_initialized_thumbprints_without_exception(
    runner: Any,
) -> None:
    runner.files.clear()
    assert runner.run({"path": PATH})[1] == {
        "changed": False,
        "thumbprints": [],
        "failed": True,
        "msg": "File at '" + PATH + "' either does not exist or is not a file",
    }


def test_certificate_authority_alias_and_case_choices(runner: Any) -> None:
    assert (
        runner.run(
            {"path": PATH, "state": "PRESENT", "store_name": "certificateauthority"}
        )[0]
        == 0
    )
    runner.native.open_store.assert_called_once_with(
        "CA", "LocalMachine", "system", False
    )


@pytest.mark.parametrize("check", [False, True])
def test_service_registrations_happen_before_open_and_keep_partial_effects(
    runner: Any,
    check: bool,
) -> None:
    runner.native.missing_service_stores.return_value = ["My", "Root"]
    runner.native.open_store.side_effect = OSError(2, "missing")
    status, result = runner.run(
        {
            "path": PATH,
            "store_type": "service",
            "store_location": "ownedservice",
            "_ansible_check_mode": check,
        }
    )
    assert status == 1 and result["changed"] is True and result["thumbprints"] == []
    assert runner.native.register_service_store.call_count == (0 if check else 2)
    runner.native.open_store.assert_called_once_with(
        "My", "OwnedService", "service", False
    )


def test_export_directory_failure_appends_thumbprint_before_failure(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner.module.os.path, "isdir", lambda _path: True)
    result = runner.run({"state": "exported", "path": PATH, "thumbprint": THUMBPRINT})[
        1
    ]
    assert result == {
        "changed": False,
        "thumbprints": [THUMBPRINT],
        "failed": True,
        "msg": "Cannot export cert to path '" + PATH + "' as it is a directory",
    }


def test_missing_export_parent_reports_plain_source_io_exception(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = r"C:\owned\missing\certificate.der"
    runner.store.records = [runner.record]
    monkeypatch.setattr(runner.module.os.path, "abspath", lambda _path: path)
    monkeypatch.setattr(
        runner.module,
        "open",
        Mock(side_effect=FileNotFoundError(2, "No such file")),
        raising=False,
    )
    code, result = runner.run(
        {"state": "exported", "path": path, "thumbprint": THUMBPRINT}
    )
    assert code == 1 and result == {
        "changed": False,
        "thumbprints": [THUMBPRINT],
        "failed": True,
        "exception": "(traceback unavailable)",
        "msg": "Failed to write cert to file due to IO Exception: "
        "Could not find a part of the path '" + path + "'.",
    }


def test_export_idempotence_reads_input_before_checking_store_selection(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner.module, "_file_type", lambda _parameters: "der")
    assert runner.run(
        {"state": "exported", "path": PATH, "thumbprint": THUMBPRINT}
    ) == (0, {"changed": False, "thumbprints": [THUMBPRINT]})
    runner.native.export_certificate.assert_not_called()
    runner.remove_file.assert_not_called()
    assert not runner.store.records


@pytest.mark.parametrize("check", [False, True])
def test_export_deletes_destination_before_serialization_failure_even_in_check_mode(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
    check: bool,
) -> None:
    runner.store.records = [runner.record]
    monkeypatch.setattr(runner.module, "_file_type", lambda _parameters: "pem")
    runner.native.export_certificate.side_effect = OSError(
        0x8009000B, "not exportable\r\n"
    )
    status, result = runner.run(
        {
            "state": "exported",
            "path": PATH,
            "thumbprint": THUMBPRINT,
            "_ansible_check_mode": check,
        }
    )
    assert (
        status == 1
        and result["changed"] is True
        and result["thumbprints"] == [THUMBPRINT]
    )
    assert PATH not in runner.files and runner.store.closed
    runner.remove_file.assert_called_once_with(PATH)
    assert "Failed to export certificate as bytes" in result["msg"]


@pytest.mark.parametrize("private", [False, True])
def test_pkcs12_creation_check_preserves_source_return_fields_without_write(
    runner: Any,
    private: bool,
) -> None:
    runner.record["has_private_key"] = private
    runner.store.records = [runner.record]
    runner.files.clear()
    expected = {"changed": True, "thumbprints": [THUMBPRINT], "key_exported": False}
    if private:
        expected["key_exportable"] = True
    assert runner.run(
        {
            "state": "exported",
            "path": PATH,
            "thumbprint": THUMBPRINT,
            "file_type": "pkcs12",
            "_ansible_check_mode": True,
        }
    ) == (0, expected)
    runner.remove_file.assert_not_called()


def test_password_redaction_covers_validation_and_native_failures(runner: Any) -> None:
    assert runner.run({"state": "secret", "path": PATH, "password": "secret"})[1][
        "msg"
    ].endswith("********")
    runner.native.read_file.side_effect = OSError(5, "secret in message")
    result = runner.run({"path": PATH, "password": "secret"})[1]
    assert "secret" not in str(result) and "********" in result["msg"]
