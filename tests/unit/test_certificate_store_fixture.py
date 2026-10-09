"""Exercise certificate fixture journals, ownership and recovery boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Fixture definitions are loaded without executing native target operations.
# pylint: disable=exec-used

import ast
import contextlib
import copy
import ctypes
import json
import struct
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock, call

import pytest

# The pinned development environment supplies PyYAML without typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


def _document(name: str) -> Any:
    return yaml.safe_load(
        (ROOT / "tests/integration" / name).read_text(encoding="utf-8")
    )


@pytest.fixture(name="fixture")
def certificate_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    """Load only fixture definitions behind controlled Windows boundaries.

    :param tmp_path: Owned journal and input directory.
    :param monkeypatch: Scoped platform and registry substitutions.
    :returns: Native fixture namespace without any target operation.
    """
    registry = ModuleType("winreg")
    monkeypatch.setattr(registry, "HKEY_CURRENT_USER", 1, raising=False)
    monkeypatch.setattr(registry, "HKEY_LOCAL_MACHINE", 2, raising=False)
    monkeypatch.setitem(sys.modules, "winreg", registry)
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "setup"])
    monkeypatch.setattr(
        sys, "getwindowsversion", lambda: SimpleNamespace(major=10), raising=False
    )
    source = _document("vars/certificate_store_fixture.yml")[
        "certificate_store_fixture"
    ]
    namespace: dict[str, Any] = {"__name__": "fixture"}
    exec(compile(source, "certificate_store_fixture.py", "exec"), namespace)
    namespace["native"] = Mock(return_value=Mock(return_value=41))
    namespace["registry_tree"] = Mock(return_value=None)
    before = {
        "registry": {
            "user": None,
            "machine": None,
            "service": None,
            "service_root": None,
        },
        "keys": {"capi": {}, "cng": {}},
        "service_exists": False,
    }
    namespace["original_state"] = Mock(return_value=before)
    namespace["key_catalogue"] = Mock(return_value=before["keys"])
    namespace["memory_export"] = Mock(return_value=b"owned PKCS7")
    namespace["file_certificates"] = Mock(return_value=[])
    namespace["register"] = Mock()
    namespace["service_change"] = Mock()
    namespace["service_exists"] = Mock(return_value=False)
    namespace["empty_owned_store"] = Mock()
    namespace["delete_registry"] = Mock()
    namespace["delete_key"] = Mock()

    def _generate(record: dict[str, Any], role: str) -> None:
        assert _journal(namespace)["before"] == before
        record["generated"][role].update(
            created=True, certificate={"thumbprint": role, "der": "0102"}
        )
        record["public_identities"].append(role + "-public")
        record["context"]["thumbprints"][role] = role
        namespace["save"](record)

    namespace["generate"] = Mock(side_effect=_generate)
    return namespace


def _journal(fixture: dict[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(Path(fixture["journal"]).read_text("utf-8")))


def _owned_key(identity: str, container: str = "imported-owned-key") -> dict[str, Any]:
    return {
        "identity": {
            "kind": "capi",
            "container": container,
            "scope": 0,
            "provider": "Owned provider",
            "provider_type": 1,
        },
        "keys": {"1": {"rsa_identity": identity, "public": "0102"}},
    }


def test_full_baseline_is_flushed_before_first_native_mutation(
    fixture: dict[str, Any],
) -> None:
    observed: list[str] = []

    def _register(*_arguments: Any) -> None:
        record = _journal(fixture)
        assert record["before"] == fixture["original_state"].return_value
        assert len(record["generated"]) == 2
        observed.append("store")

    fixture["register"].side_effect = _register
    result = fixture["setup"]()
    record = _journal(fixture)
    assert result["journaled"] and result["before"] == record["before"]
    assert observed == ["store", "store"]
    assert fixture["generate"].call_count == 2
    assert record["context"]["thumbprints"] == {
        "primary": "primary",
        "secondary": "secondary",
    }
    assert "password" not in result["context"]


def test_existing_journal_is_never_overwritten(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    original = Path(fixture["journal"]).read_bytes()
    with pytest.raises(ValueError, match="must not be overwritten"):
        fixture["setup"]()
    assert Path(fixture["journal"]).read_bytes() == original


@pytest.mark.parametrize("operation", ["dump", "fsync", "replace"])
def test_interrupted_update_retains_previous_valid_journal(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    fixture["setup"]()
    path = Path(fixture["journal"])
    original = path.read_bytes()
    record = _journal(fixture)
    record["pending"] = "not authorized until flushed"

    def _interrupt(*arguments: Any, **_keywords: Any) -> None:
        if operation == "dump":
            arguments[1].write("{")
        raise OSError("Interrupted journal replacement")

    with monkeypatch.context() as patch:
        library = fixture["json"] if operation == "dump" else fixture["os"]
        patch.setattr(library, operation, _interrupt)
        with pytest.raises(OSError, match="Interrupted journal"):
            fixture["save"](record)
    assert path.read_bytes() == original
    assert "pending" not in _journal(fixture)
    assert not list(path.parent.glob(".certificate-store-recovery-*"))


def test_failed_setup_keeps_usable_journal(fixture: dict[str, Any]) -> None:
    fixture["generate"].side_effect = OSError("Certificate creation failed")
    with pytest.raises(OSError, match="Certificate creation failed"):
        fixture["setup"]()
    record = _journal(fixture)
    assert record["before"] == fixture["original_state"].return_value
    fixture["register"].assert_not_called()
    fixture["service_change"].assert_not_called()
    assert fixture["cleanup"]()["restored"]


def test_new_matching_key_is_recorded_before_cleanup(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    row = _owned_key("primary-public")
    current = {"capi": {"new": row}, "cng": {}}
    fixture["discover_keys"](record, current)
    assert _journal(fixture)["imported_keys"] == {"new": row["identity"]}


def test_unreadable_capi_alias_requires_matching_owned_container(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    readable = _owned_key("primary-public")
    alias: dict[str, Any] = {
        "identity": dict(readable["identity"], provider="Unreadable CSP"),
        "error": 0x8009000A,
    }
    current = {"capi": {"alias": alias, "readable": readable}, "cng": {}}
    fixture["discover_keys"](record, current)
    assert _journal(fixture)["imported_keys"] == {
        name: row["identity"] for name, row in current["capi"].items()
    }


@pytest.mark.parametrize("different", ["container", "scope", "kind"])
def test_unreadable_alias_cannot_adopt_another_container_scope_or_kind(
    fixture: dict[str, Any],
    different: str,
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    original = Path(fixture["journal"]).read_bytes()
    readable = _owned_key("primary-public")
    alias: dict[str, Any] = {
        "identity": dict(readable["identity"], provider="Unreadable CSP"),
        "error": 0x8009000A,
    }
    alias["identity"][different] = {
        "container": "unowned",
        "scope": 0x20,
        "kind": "cng",
    }[different]
    current = {"capi": {"readable": readable}, "cng": {}}
    current["cng" if different == "kind" else "capi"]["alias"] = alias
    with pytest.raises(ValueError, match="cannot be adopted"):
        fixture["discover_keys"](record, current)
    assert Path(fixture["journal"]).read_bytes() == original
    fixture["delete_key"].assert_not_called()


def test_unrelated_new_key_is_never_adopted_or_deleted(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    original = Path(fixture["journal"]).read_bytes()
    with pytest.raises(ValueError, match="cannot be adopted"):
        fixture["discover_keys"](
            record, {"capi": {"unrelated": _owned_key("unrelated")}, "cng": {}}
        )
    assert Path(fixture["journal"]).read_bytes() == original
    fixture["delete_key"].assert_not_called()


def test_initial_keys_are_not_adopted_even_with_a_matching_public_key(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    row = _owned_key("primary-public")
    record["before"]["keys"]["capi"]["existing"] = row
    fixture["discover_keys"](record, {"capi": {"existing": row}, "cng": {}})
    assert _journal(fixture)["imported_keys"] == {}


def test_declared_fresh_container_is_recoverable_before_certificate_creation(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    container = record["generated"]["primary"]["container"]
    row = _owned_key("not-yet-recorded-public", container)
    fixture["discover_keys"](record, {"capi": {"new": row}, "cng": {}})
    assert _journal(fixture)["imported_keys"]["new"] == row["identity"]


def test_generated_capi_name_cannot_adopt_an_unrelated_cng_key(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    original = Path(fixture["journal"]).read_bytes()
    generated = record["generated"]["primary"]
    row = _owned_key("unrelated", generated["container"])
    row["identity"].update(kind="cng", scope=generated["scope"])

    with pytest.raises(ValueError, match="cannot be adopted"):
        fixture["discover_keys"](record, {"capi": {}, "cng": {"unowned": row}})

    assert Path(fixture["journal"]).read_bytes() == original
    fixture["delete_key"].assert_not_called()


def test_recovery_failure_keeps_journal_and_owned_resources_for_retry(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    fixture["delete_key"].side_effect = OSError("Key deletion failed")
    with pytest.raises(OSError, match="Key deletion failed"):
        fixture["cleanup"]()
    assert Path(fixture["journal"]).is_file()
    assert _journal(fixture)["before"] == fixture["original_state"].return_value
    fixture["delete_key"].side_effect = None
    assert fixture["cleanup"]()["restored"]


def test_recovery_requires_complete_recorded_state_equality(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    changed = copy.deepcopy(fixture["original_state"].return_value)
    changed["keys"]["capi"]["unrestored"] = {"error": 5}
    fixture["original_state"].return_value = changed
    with pytest.raises(ValueError, match="original certificate state differs"):
        fixture["cleanup"]()
    assert Path(fixture["journal"]).is_file()


def test_unknown_certificate_stops_before_store_deletion(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    namespace = fixture
    record = _journal(namespace)
    function = namespace["empty_owned_store"]
    assert isinstance(function, Mock)
    source = _document("vars/certificate_store_fixture.yml")[
        "certificate_store_fixture"
    ]
    definition = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "empty_owned_store"
    )
    exec(
        compile(ast.Module(body=[definition], type_ignores=[]), "owned", "exec"),
        namespace,
    )
    namespace["store"] = Mock(return_value=contextlib.nullcontext(41))
    namespace["certificates"] = Mock(
        return_value=[{"thumbprint": "unrelated", "der": "different"}]
    )
    native = namespace["native"]
    native.reset_mock()
    with pytest.raises(ValueError, match="unjournaled certificate"):
        namespace["empty_owned_store"](record, "Owned", 0x10000)
    namespace["store"].assert_called_once_with("Owned", 0x10000, physical=True)
    native.assert_not_called()


def test_cleanup_uses_only_physical_store_not_inherited_service_view(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture["setup"]()
    source = _document("vars/certificate_store_fixture.yml")[
        "certificate_store_fixture"
    ]
    definition = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "empty_owned_store"
    )
    exec(
        compile(ast.Module(body=[definition], type_ignores=[]), "owned", "exec"),
        fixture,
    )
    logical = [{"thumbprint": "unrelated", "der": "machine certificate"}]
    opened: list[tuple[str, bool]] = []

    def _store(name: str, scope: int, physical: bool = False) -> Any:
        assert scope == 0x50000
        opened.append((name, physical))
        return contextlib.nullcontext(42 if physical else 41)

    monkeypatch.setitem(fixture, "store", _store)
    monkeypatch.setitem(
        fixture, "certificates", lambda handle: [] if handle == 42 else logical
    )
    delete = Mock()
    monkeypatch.setitem(
        fixture,
        "native",
        lambda _library, name, *_signature: (
            delete
            if name == "CertDeleteCertificateFromStore"
            else Mock(return_value=True)
        ),
    )
    fixture["empty_owned_store"](_journal(fixture), "Owned\\Root", 0x50000)
    assert opened == [("Owned\\Root", True)]
    # No certificate delete is invoked for the inherited, unrelated row.
    delete.assert_not_called()


def test_capi_and_cng_public_blobs_have_the_same_rsa_identity(
    fixture: dict[str, Any],
) -> None:
    modulus = bytes(range(1, 129))
    capi = struct.pack("<BBHIIII", 6, 2, 0, 0xA400, 0x31415352, 1024, 65537)
    capi += modulus[::-1]
    cng = struct.pack("<IIIIII", 0x31415352, 1024, 3, 128, 0, 0)
    cng += b"\1\0\1" + modulus
    assert fixture["rsa_identity"](capi, "capi") == fixture["rsa_identity"](cng, "cng")
    assert fixture["rsa_identity"](b"malformed", "cng") is None


def _walk(node: Any) -> Any:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def test_owned_assertion_items_are_strings_or_booleans() -> None:
    for name in ("win_certificate_store.yml", "tasks/win_certificate_store_case.yml"):
        for node in _walk(_document(name)):
            if "ansible.builtin.assert" in node:
                assert all(
                    isinstance(item, (str, bool))
                    for item in node["ansible.builtin.assert"]["that"]
                )


def test_capture_precedes_assertions_and_public_fields_are_not_excluded() -> None:
    tasks = _document("tasks/win_certificate_store_case.yml")[1]["block"]
    saved = next(
        index
        for index, task in enumerate(tasks)
        if task["name"] == "Save raw observations before asserting behavior"
    )
    asserted = next(
        index for index, task in enumerate(tasks) if "ansible.builtin.assert" in task
    )
    assert saved < asserted
    source = (
        ROOT / "tests/integration/tasks/win_certificate_store_case.yml"
    ).read_text()
    assert "dict2items" not in source and "rejectattr" not in source
    assert "certificate_store_result" in source


def test_ordinary_fixture_is_python34_and_has_no_powershell_dependency() -> None:
    source = _document("vars/certificate_store_fixture.yml")[
        "certificate_store_fixture"
    ]
    ast.parse(source, feature_version=(3, 4))
    assert "powershell" not in source.lower() and "subprocess" not in source
    assert "os.fsync" in source and "os.replace" in source
    assert ctypes.sizeof(ctypes.c_uint32) == 4


def test_complete_case_list_is_unique_and_covers_both_store_locations() -> None:
    document = _document("vars/certificate_store.yml")
    cases = (
        document["certificate_store_binding_cases"]
        + document["certificate_store_lifecycle_cases"]
    )
    assert len(cases) == 50
    assert len({case["name"] for case in cases}) == len(cases)
    assert any(
        case.get("params", {}).get("store_location") == "LocalMachine" for case in cases
    )
    assert any(case.get("params", {}).get("store_type") == "service" for case in cases)


def test_user_and_machine_store_names_are_distinct(
    fixture: dict[str, Any],
) -> None:
    context = fixture["setup"]()["context"]
    assert context["store"] != context["machine_store"]
    assert fixture["register"].call_args_list == [
        ((context["store"], 0x10000),),
        ((context["machine_store"], 0x20000),),
    ]


def test_failed_export_destination_uses_valid_owned_der(
    fixture: dict[str, Any],
    tmp_path: Path,
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    source = tmp_path / "secondary.der"
    source.write_bytes(b"owned valid DER fixture")
    record["context"]["files"]["secondary_der"] = str(source)
    fixture["save"](record)
    result = fixture["prepare_destination"]()
    assert Path(result["path"]).read_bytes() == source.read_bytes()
    assert result["recorded"]


def test_original_replay_preserves_only_the_generated_key_scope_and_kind(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    generated = record["generated"]["primary"]
    protected = {
        name: generated[name]
        for name in ("kind", "provider", "provider_type", "container", "scope")
    }
    machine = dict(protected, scope=0x20)
    cng = dict(protected, kind="cng")
    record["imported_keys"] = {"generated": protected, "machine": machine, "cng": cng}
    fixture["save"](record)
    assert fixture["prepare_original"]() == record["context"]
    assert fixture["delete_key"].call_count == 2
    fixture["delete_key"].assert_has_calls([call(machine), call(cng)], any_order=True)


def test_default_play_preserves_full_count_and_literal_comparison_gates() -> None:
    source = (ROOT / "tests/integration/win_certificate_store.yml").read_text()
    assert "default(certificate_store_cases)" in source
    assert "loop: '{{ certificate_store_cases }}'" in source
    assert "native | length == certificate_store_cases | length" in source
    assert "original | length == certificate_store_cases | length" in source
    assert "native | map(attribute='result') | list ==" in source
    assert "original | map(attribute='result') | list" in source
