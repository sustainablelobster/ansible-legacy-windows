"""Test structured URI bodies by content rather than runtime-specific order."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These developer-runtime tests do not establish Windows execution.
# pylint: disable=protected-access

import copy
import json
from types import ModuleType
from typing import Any, cast

import pytest

from tests.unit.payload_support import load_payload


@pytest.fixture(name="helper")
def uri_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the URI payload with its actual helper closure.

    :param monkeypatch: Scoped module import and locale substitutions.
    :returns: The URI helper used by the public payload.
    """
    return cast(ModuleType, load_payload("win_uri", monkeypatch).uri)


@pytest.mark.parametrize(
    "value",
    [
        {},
        [],
        {"Name": "upper", "name": "lower"},
        {"é": "composed", "e\u0301": "decomposed"},
        {"unicode": "中😀", "markup": "<>&'"},
        {
            "outer": {"Name": 1, "name": 2},
            "items": [{"first": False, "second": None}, [3, 2, 1], "literal"],
        },
        [{"key": True}, None, False, 7, "中😀"],
    ],
)
def test_structured_json_round_trip_preserves_all_content_without_mutation(
    helper: ModuleType, value: Any
) -> None:
    original = copy.deepcopy(value)
    result = helper._body(value)
    assert isinstance(result, bytes)
    assert json.loads(result.decode("utf-8")) == original
    assert value == original


@pytest.mark.parametrize(
    "text",
    ['{"Name":1, "name":2}', " [3, 2, 1]\n", "<>&'中😀", ""],
)
def test_raw_text_body_preserves_exact_requested_representation(
    helper: ModuleType, text: str
) -> None:
    assert helper._body(text) == text.encode("utf-8")


def test_absent_body_does_not_create_an_upload(helper: ModuleType) -> None:
    assert helper._body(None) is None
