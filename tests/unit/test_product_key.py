"""Check product-key decoding with synthetic data, never guest license keys."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
from types import ModuleType

import pytest

from tests.unit.payload_support import ROOT, load_module

REFERENCE = json.loads(
    (ROOT / "tests/fixtures/product_key_reference.json").read_text(encoding="utf-8")
)


@pytest.fixture(name="helper")
def product_key_helper() -> ModuleType:
    """Load the target's dependency-free product-key decoder.

    :returns: Decoder imported with the development interpreter.
    """
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_product_key.py",
        "tested_product_key",
    )


def _registry_bytes(value: int) -> bytes:
    return bytes(52) + value.to_bytes(15, "little")


@pytest.mark.parametrize("case", REFERENCE["cases"], ids=lambda case: case["id"])
def test_matches_pinned_upstream_synthetic_decoder(
    helper: ModuleType, case: dict[str, str]
) -> None:
    data = bytes.fromhex(case["hex"])
    if "error" in case:
        assert case["error_type"] == "System.IndexOutOfRangeException"
        with pytest.raises(ValueError) as raised:
            helper.decode_product_key(data)
        assert str(raised.value) == case["error"]
    else:
        assert helper.decode_product_key(data) == case["value"]


@pytest.mark.parametrize("position", range(24))
def test_unconditional_n_insertion_at_each_leading_digit(
    helper: ModuleType, position: int
) -> None:
    data = _registry_bytes(position * 24**24)
    key = "B" * position + "N" + "B" * (24 - position)
    expected = "-".join(key[offset : offset + 5] for offset in range(0, 25, 5))
    assert helper.decode_product_key(data) == expected


def test_only_low_25_base24_digits_are_retained(helper: ModuleType) -> None:
    assert helper.decode_product_key(_registry_bytes(24**25 + 1)) == (
        "NBBBB-BBBBB-BBBBB-BBBBB-BBBBC"
    )


def test_each_base24_character_is_preserved(helper: ModuleType) -> None:
    value = sum(digit * 24 ** (23 - digit) for digit in range(24))
    assert helper.decode_product_key(_registry_bytes(value)) == (
        "NBCDF-GHJKM-PQRTV-WXY23-46789"
    )


def test_registry_header_trailer_and_byte66_bit3_do_not_change_key(
    helper: ModuleType,
) -> None:
    data = bytearray(_registry_bytes(1))
    data[:52] = bytes(range(52))
    data[66] |= 8
    data.extend(bytes(range(200)))
    assert helper.decode_product_key(data) == "NBBBB-BBBBB-BBBBB-BBBBB-BBBBC"


def test_does_not_mutate_registry_bytes_and_repeated_decode_is_identical(
    helper: ModuleType,
) -> None:
    data = bytearray(range(200))
    before = bytes(data)
    first = helper.decode_product_key(data)
    assert helper.decode_product_key(data) == first
    assert bytes(data) == before


@pytest.mark.parametrize("length", [0, 1, 52, 65, 66])
def test_short_registry_values_fail_like_upstream(
    helper: ModuleType, length: int
) -> None:
    with pytest.raises(ValueError, match="Index was outside the bounds of the array"):
        helper.decode_product_key(bytes(length))


@pytest.mark.parametrize("value", [-1, 256])
def test_invalid_byte_sequence_is_not_silently_truncated(
    helper: ModuleType, value: int
) -> None:
    data = [0] * 67
    data[52] = value
    with pytest.raises(ValueError, match="byte must be in range"):
        helper.decode_product_key(data)


def test_recovery_after_malformed_value(helper: ModuleType) -> None:
    with pytest.raises(ValueError):
        helper.decode_product_key(b"short")
    assert helper.decode_product_key(bytes(67)) == "NBBBB-BBBBB-BBBBB-BBBBB-BBBBB"
