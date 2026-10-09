"""Check independently observed licensing values and sensitive fixture logging."""

# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import ctypes
import re
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

from tests.unit.payload_support import ROOT

OBSERVATION = ROOT / "tests/integration/vars/product_observation.yml"
PLAY = ROOT / "tests/integration/win_product_facts.yml"
REQUIRED = ["PartialProductKey", "Name", "LicenseStatus"]
CHANNEL_WARNING = (
    "ansible_os_license_channel is unavailable: SoftwareLicensingProduct "
    "does not provide ProductKeyChannel."
)


@pytest.fixture(name="expectation")
def license_expectation() -> (
    Callable[[dict[str, Any]], tuple[dict[str, Any], list[str]]]
):
    """Load the portable expectations without running native observations.

    :returns: The maintained fixture's licensing expectation function.
    """
    code = yaml.safe_load(OBSERVATION.read_text(encoding="utf-8"))[
        "product_observation_code"
    ]
    function = next(
        node
        for node in ast.parse(code).body
        if isinstance(node, ast.FunctionDef) and node.name == "expected_licenses"
    )
    namespace: dict[str, Any] = {}
    # Execute the maintained portable function without loading Windows APIs.
    # pylint: disable-next=exec-used
    exec(
        compile(ast.Module(body=[function], type_ignores=[]), str(OBSERVATION), "exec"),
        namespace,
    )
    return cast(
        Callable[[dict[str, Any]], tuple[dict[str, Any], list[str]]],
        namespace["expected_licenses"],
    )


def _provider(rows: list[dict[str, Any]], channel: bool = True) -> dict[str, Any]:
    return {
        "available": True,
        "properties": REQUIRED + (["ProductKeyChannel"] if channel else []),
        "windows_licenses": rows,
    }


def test_absent_class_returns_nulls_and_exact_named_warnings(
    expectation: Callable[[dict[str, Any]], tuple[dict[str, Any], list[str]]],
) -> None:
    facts, warnings = expectation(
        {"available": False, "properties": [], "windows_licenses": []}
    )
    assert facts == {
        "ansible_os_license_edition": None,
        "ansible_os_license_channel": None,
        "ansible_os_license_status": None,
    }
    assert warnings == [
        "ansible_os_license_" + field + " is unavailable: this Windows "
        "version does not provide SoftwareLicensingProduct."
        for field in ("edition", "channel", "status")
    ]


@pytest.mark.parametrize("count", [0, 1, 2])
def test_missing_channel_retains_available_fields_and_exact_warning(
    expectation: Callable[[dict[str, Any]], tuple[dict[str, Any], list[str]]],
    count: int,
) -> None:
    rows = [
        {"Name": "Windows " + str(index), "LicenseStatus": index + 1}
        for index in range(count)
    ]
    facts, warnings = expectation(_provider(rows, channel=False))
    assert facts == {
        "ansible_os_license_edition": (
            None
            if count == 0
            else "Windows 0" if count == 1 else ["Windows 0", "Windows 1"]
        ),
        "ansible_os_license_channel": None if count < 2 else [None, None],
        "ansible_os_license_status": (
            None
            if count == 0
            else "Licensed" if count == 1 else ["Licensed", "OOBGrace"]
        ),
    }
    assert warnings == [CHANNEL_WARNING]


def test_empty_available_provider_returns_nulls_without_fabricated_warnings(
    expectation: Callable[[dict[str, Any]], tuple[dict[str, Any], list[str]]],
) -> None:
    facts, warnings = expectation(_provider([]))
    assert all(value is None for value in facts.values())
    assert warnings == []


@pytest.mark.parametrize(
    "number,name",
    enumerate(
        [
            "Unlicensed",
            "Licensed",
            "OOBGrace",
            "OOTGrace",
            "NonGenuineGrace",
            "Notification",
            "ExtendedGrace",
        ]
    ),
)
def test_complete_schema_preserves_scalar_values_and_status_names(
    expectation: Callable[[dict[str, Any]], tuple[dict[str, Any], list[str]]],
    number: int,
    name: str,
) -> None:
    facts, warnings = expectation(
        _provider(
            [
                {
                    "Name": "Windows edition",
                    "ProductKeyChannel": "Retail",
                    "LicenseStatus": number,
                }
            ]
        )
    )
    assert facts == {
        "ansible_os_license_edition": "Windows edition",
        "ansible_os_license_channel": "Retail",
        "ansible_os_license_status": name,
    }
    assert warnings == []


@pytest.mark.parametrize("status", [None, -1, 7, "2"])
def test_null_or_unknown_status_does_not_imply_missing_schema(
    expectation: Callable[[dict[str, Any]], tuple[dict[str, Any], list[str]]],
    status: object,
) -> None:
    facts, warnings = expectation(
        _provider(
            [
                {
                    "Name": "Windows edition",
                    "ProductKeyChannel": None,
                    "LicenseStatus": status,
                }
            ]
        )
    )
    assert facts["ansible_os_license_channel"] is None
    assert facts["ansible_os_license_status"] is None
    assert warnings == []


def test_multiple_licenses_preserve_order_duplicates_and_null_members(
    expectation: Callable[[dict[str, Any]], tuple[dict[str, Any], list[str]]],
) -> None:
    facts, warnings = expectation(
        _provider(
            [
                {"Name": "Windows B", "ProductKeyChannel": None, "LicenseStatus": 7},
                {
                    "Name": "Windows A",
                    "ProductKeyChannel": "Retail",
                    "LicenseStatus": 1,
                },
                {
                    "Name": "Windows A",
                    "ProductKeyChannel": "Retail",
                    "LicenseStatus": 1,
                },
            ]
        )
    )
    assert facts == {
        "ansible_os_license_edition": ["Windows B", "Windows A", "Windows A"],
        "ansible_os_license_channel": [None, "Retail", "Retail"],
        "ansible_os_license_status": [None, "Licensed", "Licensed"],
    }
    assert warnings == []


@pytest.mark.parametrize("missing", REQUIRED)
def test_absent_required_property_fails_instead_of_claiming_optional_unavailability(
    expectation: Callable[[dict[str, Any]], tuple[dict[str, Any], list[str]]],
    missing: str,
) -> None:
    observed = _provider([])
    observed["properties"].remove(missing)
    with pytest.raises(AssertionError, match="required property"):
        expectation(observed)


def _tasks(items: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for item in items:
        yield item
        for section in ("block", "rescue", "always"):
            yield from _tasks(item.get(section, []))


@pytest.mark.parametrize(
    "expected,actual,accepted",
    [
        (None, None, True),
        ("Retail", "Retail", True),
        ([None, "Retail"], [None, "Retail"], True),
        (None, "Retail", False),
        ("Retail", "Volume:MAK", False),
        ([None, "Retail"], ["Retail", None], False),
        ([None, None], None, False),
    ],
)
@pytest.mark.parametrize("field", ["edition", "channel", "status"])
def test_fixture_compares_each_license_value_exactly(
    expected: object, actual: object, accepted: bool, field: str
) -> None:
    play = yaml.safe_load(PLAY.read_text(encoding="utf-8"))[0]
    assertions = next(
        item["ansible.builtin.assert"]["that"]
        for item in _tasks(play["tasks"])
        if item["name"]
        == "Verify stable facts against independent product observations"
    )
    fact = "ansible_os_license_" + field
    expression = next(
        value for value in assertions if "observed.license_facts." + fact in value
    )
    evaluate = Environment().compile_expression(expression)
    assert (
        evaluate(
            item={"ansible_facts": {fact: actual}},
            observed={"license_facts": {fact: expected}},
        )
        is accepted
    )


@pytest.mark.parametrize(
    "warnings,accepted",
    [
        ([CHANNEL_WARNING], True),
        ([], False),
        (["ansible_os_license_channel unavailable"], False),
        ([CHANNEL_WARNING, "unexpected warning"], False),
    ],
)
def test_fixture_requires_exact_warnings_and_protects_sensitive_results(
    warnings: list[str], accepted: bool
) -> None:
    play = yaml.safe_load(PLAY.read_text(encoding="utf-8"))[0]
    tasks = list(_tasks(play["tasks"]))
    for item in tasks:
        if any(
            key in item
            for key in ("block", "ansible.builtin.raw", "ansible.builtin.fail")
        ):
            continue
        assert item["no_log"] is True
    assertions = next(
        item["ansible.builtin.assert"]["that"]
        for item in tasks
        if item["name"]
        == "Verify stable facts against independent product observations"
    )
    expression = next(
        value for value in assertions if "observed.license_warnings" in value
    )
    evaluate = Environment().compile_expression(expression)
    assert (
        evaluate(
            item={"warnings": warnings},
            observed={"license_warnings": [CHANNEL_WARNING]},
        )
        is accepted
    )


def test_native_observer_compiles_without_importing_collection_code() -> None:
    code = yaml.safe_load(OBSERVATION.read_text(encoding="utf-8"))[
        "product_observation_code"
    ]
    tree = ast.parse(code)
    compile(tree, str(OBSERVATION), "exec")
    imports = [
        name.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for name in node.names
    ]
    assert not any("legacy_windows" in name for name in imports)


@pytest.mark.parametrize(
    "result,message",
    [
        (0x40004, "Licensing enumeration timed out"),
        (0x80070005, "IEnumWbemClassObject.Next failed (HRESULT 0x80070005)"),
        (0x80070426, "IEnumWbemClassObject.Next failed (HRESULT 0x80070426)"),
    ],
)
def test_observer_enumeration_fails_boundedly_and_releases_returned_objects(
    result: int, message: str
) -> None:
    code = yaml.safe_load(OBSERVATION.read_text(encoding="utf-8"))[
        "product_observation_code"
    ]
    observer = next(
        node
        for node in ast.parse(code).body
        if isinstance(node, ast.FunctionDef) and node.name == "licensing_provider"
    )
    checked = next(
        node
        for node in observer.body
        if isinstance(node, ast.FunctionDef) and node.name == "checked"
    )
    enumeration = next(
        node for node in ast.walk(observer) if isinstance(node, ast.While)
    )
    released: list[int | None] = []

    def _advance(
        _enumeration: Any, timeout: int, count: int, instance: Any, returned: Any
    ) -> int:
        assert timeout == 5000 and count == 1
        ctypes.cast(instance, ctypes.POINTER(ctypes.c_void_p))[0] = 104
        ctypes.cast(returned, ctypes.POINTER(ctypes.c_uint32))[0] = 0
        return ctypes.c_int32(result).value

    namespace = {
        "ctypes": ctypes,
        "ExitStack": ExitStack,
        "pointer": ctypes.c_void_p,
        "signed": ctypes.c_int32,
        "unsigned": ctypes.c_uint32,
        "enumeration": ctypes.c_void_p(103),
        "method": lambda *_arguments: _advance,
        "release": lambda instance: released.append(instance.value),
    }
    # Run the maintained enumeration loop with a single native response, avoiding
    # a duplicate timeout algorithm or a Windows connection in routine tests.
    with pytest.raises(OSError, match=re.escape(message)):
        # pylint: disable-next=exec-used
        exec(
            compile(
                ast.Module(body=[checked, enumeration], type_ignores=[]),
                str(OBSERVATION),
                "exec",
            ),
            namespace,
        )
    assert released == [104]
