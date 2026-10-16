"""Exercise native speech ordering, literal text, files and nonmutating preview."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Payload calls isolate the native audio boundary without replacing validation.
# pylint: disable=protected-access

import ctypes
import sys
import wave
from contextlib import ExitStack
from pathlib import Path
from types import ModuleType
from typing import Any, Callable
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def speech_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the speech frontend with recorded audio boundary substitutes.

    :param monkeypatch: Scoped helper imports and output substitutions.
    :returns: Loaded speech frontend.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_say.py", "tested_say"
    )
    monkeypatch.setattr(module, "render", Mock(return_value=("Fixture Voice", None)))
    monkeypatch.setattr(module, "play_wave", Mock())
    return module


def test_literal_unicode_speech_and_voice_selection(payload: ModuleType) -> None:
    result = payload._say(
        {"msg": "Café 雪 <literal>", "voice": "Fixture Voice", "speech_speed": 4}
    )
    assert result == {
        "changed": False,
        "message_text": "Café 雪 <literal>",
        "voice": "Fixture Voice",
    }
    payload.render.assert_called_once_with(
        "Café 雪 <literal>", "Fixture Voice", 4, False
    )


def test_missing_voice_warns_and_returns_actual_default(payload: ModuleType) -> None:
    warning = "Could not load voice 'Missing', using system default voice."
    payload.render.return_value = "Fixture Voice", warning
    result = payload._say({"msg": "test", "voice": "Missing"})
    assert result["voice"] == "Fixture Voice"
    assert result["voice_info"] == warning and result["warnings"] == [warning]


def test_unicode_message_file_uses_powershell_line_normalization(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "message.txt"
    source.write_text("Café 雪\nsecond", encoding="utf-16")
    result = payload._say({"msg_file": str(source)})
    assert result["message_text"] == "Café 雪\r\nsecond\r\n"
    payload.render.assert_called_once_with("Café 雪\r\nsecond\r\n", None, 0, False)


def test_playback_order_and_sound_only(payload: ModuleType, tmp_path: Path) -> None:
    start, end = tmp_path / "start.wav", tmp_path / "end.wav"
    start.touch()
    end.touch()
    parent = Mock()
    parent.attach_mock(payload.play_wave, "wave")
    parent.attach_mock(payload.render, "speech")
    result = payload._say(
        {"start_sound_path": str(start), "msg": "test", "end_sound_path": str(end)}
    )
    assert result["changed"] is False
    assert [item[0] for item in parent.mock_calls] == ["wave", "speech", "wave"]
    payload.render.reset_mock()
    assert payload._say({"start_sound_path": str(start)}) == {
        "changed": False,
        "message_text": "",
    }
    payload.render.assert_not_called()


def test_preview_selects_voice_without_producing_audio(
    payload: ModuleType, tmp_path: Path
) -> None:
    sound = tmp_path / "sound.wav"
    sound.touch()
    result = payload._say(
        {
            "msg": "test",
            "start_sound_path": str(sound),
            "end_sound_path": str(sound),
            "_ansible_check_mode": True,
        }
    )
    assert result["changed"] is False
    payload.render.assert_called_once_with("test", None, 0, True)
    payload.play_wave.assert_not_called()


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"msg": "one", "msg_file": "two"},
        {"msg": "x", "speech_speed": 11},
        {"msg": "x", "speech_speed": -11},
        {"msg": "x", "speech_speed": "bad"},
        {"msg_file": "missing-fixture.txt"},
        {"start_sound_path": "missing-fixture.wav"},
    ],
)
def test_invalid_requests_do_not_produce_audio(
    payload: ModuleType, options: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        payload._say(options)
    payload.render.assert_not_called()
    payload.play_wave.assert_not_called()


def test_native_audio_failure_is_not_reported_as_success(payload: ModuleType) -> None:
    payload.render.side_effect = OSError("audio output unavailable")
    with pytest.raises(OSError, match="audio output unavailable"):
        payload._say({"msg": "test"})


@pytest.mark.usefixtures("payload")
@pytest.mark.parametrize("synthesis_fails", [False, True])
def test_native_synthesis_closes_and_removes_owned_wave_on_all_paths(
    monkeypatch: pytest.MonkeyPatch, synthesis_fails: bool
) -> None:
    native = sys.modules["legacy_community_windows_speech"]
    assert ctypes.sizeof(native._WaveFormat) == 18
    operations: list[int] = []
    files: list[Path] = []

    def _method(
        _pointer: object, slot: int, _result: object, _arguments: object
    ) -> Callable[..., int]:
        def _call(*arguments: Any) -> int:
            operations.append(slot)
            if slot == 17:
                files.append(Path(arguments[1]))
                settings = ctypes.cast(
                    arguments[4], ctypes.POINTER(native._WaveFormat)
                ).contents
                assert (
                    settings.channels,
                    settings.samples_per_second,
                    settings.bits_per_sample,
                ) == (1, 22050, 16)
                files[0].touch()
            elif slot == 20:
                assert arguments[1:3] == ("<literal>", 16)
                if synthesis_fails:
                    raise OSError("controlled synthesis failure")
                with wave.Wave_write(str(files[0])) as output:
                    output.setparams((1, 2, 22050, 0, "NONE", "not compressed"))
                    output.writeframes(b"\x10\x00" * 40)
            return 0

        return _call

    def _play(path: str) -> None:
        assert operations == [17, 13, 20, 18]
        with wave.open(path, "rb") as output:
            assert output.getnframes() == 40
            assert output.readframes(40) != bytes(80)

    playback = Mock(side_effect=_play)
    monkeypatch.setattr(native, "_create", lambda *_arguments: ctypes.c_void_p(2))
    monkeypatch.setattr(native, "_method", _method)
    monkeypatch.setattr(native, "play_wave", playback)
    with ExitStack() as cleanup:
        if synthesis_fails:
            with pytest.raises(OSError, match="controlled synthesis failure"):
                native._speak(None, cleanup, ctypes.c_void_p(1), "<literal>")
            playback.assert_not_called()
        else:
            native._speak(None, cleanup, ctypes.c_void_p(1), "<literal>")
            playback.assert_called_once_with(str(files[0]))
    assert operations == [17, 13, 20, 18]
    assert files and not files[0].exists()
