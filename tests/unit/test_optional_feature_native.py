"""Exercise fixed DISM arguments, return codes, state parsing and scratch cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes do not establish Windows support.
# pylint: disable=protected-access

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="native")
def optional_feature_native(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Load the helper with observable shipped-tool and process boundaries.

    :param monkeypatch: Scoped platform and subprocess replacements.
    :param tmp_path: Private native scratch substitute.
    :returns: Helper, native process and executable-presence controls.
    """
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_optional_feature.py",
        "tested_optional_feature_native",
    )
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    exists = Mock(side_effect=lambda name: "System32" in name)
    monkeypatch.setattr(helper.os.path, "isfile", exists)
    temporary = MagicMock()
    temporary.__enter__.return_value = str(tmp_path / "scratch")
    constructor = Mock(return_value=temporary)
    monkeypatch.setattr(helper.tempfile, "TemporaryDirectory", constructor)
    process = MagicMock()
    process.__enter__.return_value = process
    process.returncode = 0
    process.communicate.return_value = (b"State : Disabled\r\n", None)
    popen = Mock(return_value=process)
    monkeypatch.setattr(helper.subprocess, "Popen", popen)
    monkeypatch.setattr(helper, "_decode", lambda value: value.decode("utf-8").strip())
    return SimpleNamespace(
        helper=helper,
        exists=exists,
        temporary=temporary,
        constructor=constructor,
        process=process,
        popen=popen,
        scratch=str(tmp_path / "scratch"),
    )


def _arguments(native: Any) -> list[str]:
    return cast(list[str], native.popen.call_args.args[0])


def test_native_tool_uses_fixed_online_english_private_log_and_scratch(
    native: Any,
) -> None:
    with native.helper.OptionalFeatures() as features:
        assert features.state("TelnetClient") == "Disabled"
    arguments = _arguments(native)
    assert arguments[1:] == [
        "/Online",
        "/English",
        "/LogPath:" + str(Path(native.scratch) / "dism.log"),
        "/ScratchDir:" + native.scratch,
        "/Get-FeatureInfo",
        "/FeatureName:TelnetClient",
    ]
    assert "System32" in arguments[0]
    native.constructor.assert_called_once_with(
        prefix="legacy-windows-optional-feature-"
    )
    native.temporary.__exit__.assert_called_once_with(None, None, None)
    native.popen.assert_called_once_with(
        arguments,
        stdout=native.helper.subprocess.PIPE,
        stderr=native.helper.subprocess.STDOUT,
    )


def test_wow64_prefers_native_system_tool_alias(native: Any) -> None:
    native.exists.side_effect = lambda name: "Sysnative" in name
    with native.helper.OptionalFeatures() as features:
        features.state("TelnetClient")
    assert "Sysnative" in _arguments(native)[0]


def test_missing_tool_fails_before_any_scratch_or_process(native: Any) -> None:
    native.exists.side_effect = None
    native.exists.return_value = False
    with pytest.raises(
        OSError, match="does not support the Enable-WindowsOptionalFeature"
    ):
        native.helper.OptionalFeatures()
    native.constructor.assert_not_called()
    native.popen.assert_not_called()


@pytest.mark.parametrize("status", [0x800F080C, -2146498548])
def test_only_measured_unknown_feature_status_returns_none(
    native: Any, status: int
) -> None:
    native.process.returncode = status
    execute = Mock(side_effect=[(status, "unknown"), (0, "Feature Name : ActualOther")])
    with native.helper.OptionalFeatures() as features:
        features._execute = execute
        assert features.state("missing") is None


def test_case_sensitive_catalogue_resolution_reaches_real_read_and_batch(
    native: Any,
) -> None:
    execute = Mock(
        side_effect=[
            (0x800F080C, "unknown spelling"),
            (0, "Feature Name : TelnetClient\nState : Disabled\n"),
            (0, "State : Disabled\n"),
            (0, "enabled"),
            (0, "disabled"),
        ]
    )
    with native.helper.OptionalFeatures() as features:
        features._execute = execute
        assert features.state("telnetclient") == "Disabled"
        assert features.enable(["telnetclient", "telnetclient"], False, None) is False
        assert features.disable(["telnetclient"]) is False
    assert [call.args[0] for call in execute.call_args_list] == [
        ["/Get-FeatureInfo", "/FeatureName:telnetclient"],
        ["/Get-Features", "/Format:List"],
        ["/Get-FeatureInfo", "/FeatureName:TelnetClient"],
        [
            "/Enable-Feature",
            "/FeatureName:TelnetClient",
            "/FeatureName:TelnetClient",
            "/NoRestart",
        ],
        ["/Disable-Feature", "/FeatureName:TelnetClient", "/NoRestart"],
    ]


@pytest.mark.parametrize(
    "catalogue", ["no catalogue", "Feature Name : Alpha\nFeature Name : alpha\n"]
)
def test_missing_or_ambiguous_catalogue_never_guesses_a_servicing_name(
    native: Any,
    catalogue: str,
) -> None:
    with native.helper.OptionalFeatures() as features:
        features._execute = Mock(side_effect=[(0x800F080C, "unknown"), (0, catalogue)])
        with pytest.raises(OSError, match="catalogue|ambiguous"):
            features.state("ALPHA")
        assert features._execute.call_count == 2


@pytest.mark.parametrize(
    "parent,source,switch", [(True, None, "All"), (False, "literal", "Source")]
)
def test_genuinely_absent_enable_switches_fail_before_any_native_write(
    native: Any,
    parent: bool,
    source: str | None,
    switch: str,
) -> None:
    with native.helper.OptionalFeatures() as features:
        execute = Mock(return_value=(0, "/Enable-Feature /FeatureName:<name>"))
        features._execute = execute
        with pytest.raises(ValueError, match="/" + switch):
            features.enable(["Alpha"], parent, source)
        execute.assert_called_once_with(["/Enable-Feature", "/?"])


def test_supported_enable_switch_help_is_read_once_for_preview_and_write(
    native: Any,
) -> None:
    with native.helper.OptionalFeatures() as features:
        execute = Mock(side_effect=[(0, "[/All] [/Source:<path>]"), (0, "enabled")])
        features._execute = execute
        features.validate_enable(True, "literal")
        assert features.enable(["Alpha"], True, "literal") is False
        assert execute.call_count == 2


@pytest.mark.parametrize("status", [5, 87, 0x800F0906])
def test_other_read_failures_retain_native_error_and_do_not_change(
    native: Any, status: int
) -> None:
    native.process.returncode = status
    native.process.communicate.return_value = (b"Native read failure", None)
    with native.helper.OptionalFeatures() as features:
        with pytest.raises(OSError, match="DISM failed .*Native read failure"):
            features.state("TelnetClient")
    assert len(_arguments(native)) == 7


@pytest.mark.parametrize(
    "output", [b"", b"State :\n", b"State : Enabled\nState : Disabled\n"]
)
def test_no_unique_native_state_fails_without_guessing(
    native: Any, output: bytes
) -> None:
    native.process.communicate.return_value = (output, None)
    with native.helper.OptionalFeatures() as features:
        with pytest.raises(OSError, match="no unique state"):
            features.state("TelnetClient")


@pytest.mark.parametrize(
    "state",
    ["Enabled", "Disabled with Payload Removed", "Enable Pending", "Disable Pending"],
)
def test_native_state_text_is_preserved_for_public_prefix_matching(
    native: Any, state: str
) -> None:
    native.process.communicate.return_value = (f"State : {state}\r\n".encode(), None)
    with native.helper.OptionalFeatures() as features:
        assert features.state("TelnetClient") == state


@pytest.mark.parametrize("parents", [False, True])
def test_enable_batches_names_in_order_with_exact_parent_source_and_norestart(
    native: Any, parents: bool
) -> None:
    source = r"\\server\share with spaces\sxs"
    native.process.communicate.return_value = (b"[/All] [/Source:<path>]", None)
    with native.helper.OptionalFeatures() as features:
        assert features.enable(["Beta", "Alpha", "Beta"], parents, source) is False
    arguments = _arguments(native)[5:]
    expected = [
        "/Enable-Feature",
        "/FeatureName:Beta",
        "/FeatureName:Alpha",
        "/FeatureName:Beta",
    ]
    if parents:
        expected.append("/All")
    assert arguments == expected + ["/Source:" + source, "/NoRestart"]
    assert "/LimitAccess" not in _arguments(native)


def test_disable_never_removes_payload_or_uses_source_and_parents(native: Any) -> None:
    with native.helper.OptionalFeatures() as features:
        assert features.disable(["Beta", "Alpha"]) is False
    assert _arguments(native)[5:] == [
        "/Disable-Feature",
        "/FeatureName:Beta",
        "/FeatureName:Alpha",
        "/NoRestart",
    ]
    assert not any(
        arg.startswith(("/Source:", "/All", "/Remove")) for arg in _arguments(native)
    )


@pytest.mark.parametrize("status,required", [(0, False), (3010, True)])
def test_only_success_reboot_status_sets_reboot_required(
    native: Any, status: int, required: bool
) -> None:
    native.process.returncode = status
    with native.helper.OptionalFeatures() as features:
        assert features.disable(["Alpha"]) is required


def test_failed_batch_does_not_retry_or_rollback_and_always_cleans_scratch(
    native: Any,
) -> None:
    native.process.returncode = 50
    native.process.communicate.return_value = (
        b"Batch failed after partial writes",
        None,
    )
    with pytest.raises(OSError, match="Batch failed after partial writes"):
        with native.helper.OptionalFeatures() as features:
            features.enable(["Alpha", "Beta"], True, None)
    native.popen.assert_called_once()
    assert native.temporary.__exit__.call_args.args[0] is OSError
