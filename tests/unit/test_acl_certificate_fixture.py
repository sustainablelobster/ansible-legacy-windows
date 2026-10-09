"""Verify ownership and recovery in the independent certificate fixture."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import copy
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# The pinned Nix environment supplies PyYAML without its optional typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def certificate_fixture() -> Any:
    """Load only cleanup, without executing native imports or setup.

    :returns: Cleanup function with observable provider and journal operations.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/acl_certificate_fixture.yml").read_text()
    )["acl_certificate_fixture"]
    cleanup = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "cleanup"
    )
    api = SimpleNamespace(saved=[])

    def _require(value: Any) -> None:
        if not value:
            raise OSError("native operation failed")

    def _missing_key(_entry: Any) -> None:
        error = OSError("key does not exist")
        setattr(error, "winerror", -2146893802)
        raise error

    namespace = {
        "key_descriptor": Mock(),
        "find": Mock(side_effect=[71, None]),
        "encoded_certificate": Mock(return_value="original DER"),
        "free_certificate": Mock(return_value=True),
        "delete_certificate": Mock(return_value=True),
        "remove_key": Mock(),
        "key_context": _missing_key,
        "save": lambda state: api.saved.append(copy.deepcopy(state)),
        "require": _require,
    }
    # Execute only cleanup so these checks cannot import DLLs or create keys.
    # pylint: disable-next=exec-used
    exec(
        compile(ast.Module(body=[cleanup], type_ignores=[]), "<cleanup>", "exec"),
        namespace,
    )
    api.calls, api.cleanup = namespace, namespace["cleanup"]
    return api


def _entry(**changes: Any) -> dict[str, Any]:
    result = {
        "key_created": True,
        "certificate_added": True,
        "original_descriptor": "original ACL",
        "thumbprint": "owned hash",
        "der": "original DER",
    }
    result.update(changes)
    return result


def test_cleanup_skips_objects_not_owned_by_fixture(fixture: Any) -> None:
    fixture.cleanup(
        10, {"entries": [_entry(key_created=False, certificate_added=False)]}
    )
    for name in ("key_descriptor", "find", "delete_certificate", "remove_key"):
        fixture.calls[name].assert_not_called()
    assert fixture.saved == []


def test_cleanup_checks_certificate_identity_before_deletion(fixture: Any) -> None:
    fixture.calls["encoded_certificate"].return_value = "different DER"
    with pytest.raises(AssertionError):
        fixture.cleanup(10, {"entries": [_entry()]})
    fixture.calls["free_certificate"].assert_called_once_with(71)
    fixture.calls["delete_certificate"].assert_not_called()
    fixture.calls["remove_key"].assert_not_called()
    assert fixture.saved == []


def test_failed_native_delete_does_not_double_free_certificate(fixture: Any) -> None:
    fixture.calls["delete_certificate"].return_value = False
    state = {"entries": [_entry()]}
    with pytest.raises(OSError, match="native operation failed"):
        fixture.cleanup(10, state)
    fixture.calls["free_certificate"].assert_not_called()
    fixture.calls["remove_key"].assert_not_called()
    assert state["entries"][0]["certificate_added"] is True


def test_key_delete_failure_retains_key_ownership_and_records_removed_certificate(
    fixture: Any,
) -> None:
    fixture.calls["remove_key"].side_effect = OSError("key deletion failed")
    state = {"entries": [_entry()]}
    with pytest.raises(OSError, match="key deletion failed"):
        fixture.cleanup(10, state)
    assert fixture.saved[-1]["entries"][0]["certificate_added"] is False
    assert fixture.saved[-1]["entries"][0]["key_created"] is True
    fixture.calls["key_descriptor"].assert_called_once_with(
        state["entries"][0], restore=True
    )


def test_successful_cleanup_records_both_deletions_and_verifies_absence(
    fixture: Any,
) -> None:
    state = {"entries": [_entry()]}
    fixture.cleanup(10, state)
    assert fixture.calls["find"].call_count == 2
    assert fixture.saved[-1]["entries"][0]["certificate_added"] is False
    assert fixture.saved[-1]["entries"][0]["key_created"] is False
