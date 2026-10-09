"""Exercise DNS record input binding without contacting a Windows provider."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def public_runner(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> Any:
    """Run the public JSON entry point with a native provider substitute.

    :param monkeypatch: Scoped argument and native boundary substitutes.
    :param capsys: Captured module response.
    :param tmp_path: Isolated request files.
    :returns: Request runner and recorded native calls.
    """
    payload = load_payload("win_dns_record", monkeypatch)
    manage = Mock(return_value={"changed": False})
    monkeypatch.setattr(payload.dns, "manage", manage)

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        request = tmp_path / "arguments.json"
        request.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["win_dns_record.py", str(request)])
        return invoke_payload(payload, capsys)

    return SimpleNamespace(run=_run, manage=manage)


def test_defaults_preserve_released_sparse_result(runner: Any) -> None:
    assert runner.run(
        {"name": "database", "type": "A", "zone": "owned.test", "value": "192.0.2.1"}
    ) == (0, {"changed": False})
    runner.manage.assert_called_once_with(
        {
            "name": "database",
            "type": "A",
            "zone": "owned.test",
            "zone_scope": None,
            "computer_name": None,
            "state": "present",
            "ttl": 3600,
            "port": None,
            "priority": None,
            "weight": None,
            "aging": False,
            "allow_update_any": False,
            "value": ["192.0.2.1"],
        },
        False,
        False,
    )


@pytest.mark.parametrize("field,value", [("type", "a"), ("state", "PRESENT")])
def test_choice_case_reaches_provider_unchanged(
    runner: Any, field: str, value: str
) -> None:
    arguments = {
        "name": "database",
        "type": "A",
        "zone": "owned.test",
        "value": "192.0.2.1",
        field: value,
    }
    assert runner.run(arguments)[0] == 0
    assert runner.manage.call_args.args[0][field] == value


def test_values_alias_overrides_canonical_like_basic(runner: Any) -> None:
    assert (
        runner.run(
            {
                "name": "database",
                "type": "A",
                "zone": "owned.test",
                "value": "192.0.2.1",
                "values": ["192.0.2.2", "192.0.2.2"],
            }
        )[0]
        == 0
    )
    assert runner.manage.call_args.args[0]["value"] == ["192.0.2.2", "192.0.2.2"]


@pytest.mark.parametrize("kind", ["SRV", "srv"])
def test_required_if_preserves_basic_case_sensitive_condition(
    runner: Any, kind: str
) -> None:
    code, result = runner.run(
        {"name": "service", "type": kind, "zone": "owned.test", "value": "host.test"}
    )
    if kind == "SRV":
        assert (
            code == 1
            and result["msg"]
            == "type is SRV but all of the following are missing: port, priority, weight"
        )
        runner.manage.assert_not_called()
    else:
        assert code == 0 and runner.manage.call_args.args[0]["port"] is None


@pytest.mark.parametrize(
    "arguments,message",
    [
        (
            {"name": "database", "type": "A", "zone": "owned.test"},
            "Parameter 'values' must be non-empty when state='present'",
        ),
        (
            {
                "name": "database",
                "type": "A",
                "zone": "owned.test",
                "state": "absent",
                "value": "192.0.2.1",
            },
            "Parameter 'values' must be undefined or empty when state='absent'",
        ),
        (
            {
                "name": "database",
                "type": "A",
                "zone": "owned.test",
                "value": "192.0.2.1",
                "ttl": 0,
            },
            "Parameter 'ttl' must be between 1 and 31557600",
        ),
        (
            {
                "name": "database",
                "type": "A",
                "zone": "owned.test",
                "value": "192.0.2.1",
                "ttl": 31557601,
            },
            "Parameter 'ttl' must be between 1 and 31557600",
        ),
    ],
)
def test_pre_execution_failures_do_not_open_provider(
    runner: Any, arguments: dict[str, Any], message: str
) -> None:
    assert runner.run(arguments) == (
        1,
        {"changed": False, "failed": True, "msg": message},
    )
    runner.manage.assert_not_called()


@pytest.mark.parametrize("field", ["ttl", "port", "priority", "weight"])
@pytest.mark.parametrize(
    "value,kind,detail",
    [
        (True, "Boolean", "Input string was not in a correct format."),
        (1.5, "Decimal", "Input string was not in a correct format."),
        (1.0, "Decimal", "Input string was not in a correct format."),
        (1e30, "Double", "Input string was not in a correct format."),
        (2**31, "Int64", "Value was either too large or too small for an Int32."),
        (
            -(2**31) - 1,
            "Int64",
            "Value was either too large or too small for an Int32.",
        ),
        (2**63, "Decimal", "Value was either too large or too small for an Int32."),
        ([], "Object[]", "Input string was not in a correct format."),
        (
            {},
            "Collections.Hashtable",
            "Input string was not in a correct format.",
        ),
        ("12\u00a0", "String", "Input string was not in a correct format."),
        ("\u00a012", "String", "Input string was not in a correct format."),
        ("12\u202f", "String", "Input string was not in a correct format."),
        ("\u0661\u0662", "String", "Input string was not in a correct format."),
        ("1\x002", "String", "Input string was not in a correct format."),
        ("", "String", "Input string was not in a correct format."),
    ],
)
def test_integer_failures_preserve_complete_basic_response(
    runner: Any, field: str, value: object, kind: str, detail: str
) -> None:
    assert runner.run(
        {
            "name": "database",
            "type": "A",
            "zone": "owned.test",
            "value": "192.0.2.1",
            field: value,
        }
    ) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": f"argument for {field} is of type System.{kind} "
            f"and we were unable to convert to int: {detail}",
        },
    )
    runner.manage.assert_not_called()


@pytest.mark.parametrize("field", ["ttl", "port", "priority", "weight"])
@pytest.mark.parametrize("value", ["12\x00", " +12 \x00\x00", "\t12\r\n", 12])
def test_integer_ascii_whitespace_and_trailing_nulls_bind_before_provider(
    runner: Any, field: str, value: object
) -> None:
    assert (
        runner.run(
            {
                "name": "database",
                "type": "A",
                "zone": "owned.test",
                "value": "192.0.2.1",
                field: value,
            }
        )[0]
        == 0
    )
    assert runner.manage.call_args.args[0][field] == 12
