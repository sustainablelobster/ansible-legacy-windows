# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Speak through SAPI's native ISpVoice interface and play WAV files."""

import ctypes
import os
import tempfile
import uuid
from contextlib import ExitStack

# SAPI uses the standard COM ABI and the same Windows-owned allocations as WMI.
from legacy_windows_wmi import (  # pylint: disable=import-error
    _check,
    _Guid,
    _libraries,
    _method,
    _release,
)

_POINTER = ctypes.c_void_p
_LONG = ctypes.c_int32
_ULONG = ctypes.c_uint32


# Windows' mmreg.h packs WAVEFORMATEX at byte alignment, including cbSize.
class _WaveFormat(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _pack_ = 1
    _fields_ = [
        ("format", ctypes.c_uint16),
        ("channels", ctypes.c_uint16),
        ("samples_per_second", _ULONG),
        ("bytes_per_second", _ULONG),
        ("block_alignment", ctypes.c_uint16),
        ("bits_per_sample", ctypes.c_uint16),
        ("extra_size", ctypes.c_uint16),
    ]


def _guid(value):
    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


def _create(ole, cleanup, class_id, interface_id):
    pointer = _POINTER()
    cleanup.callback(_release, pointer)
    # CoCreateInstance's fixed ABI stays with the SAPI reference owner rather
    # than introducing a dependency on another feature's object factory.
    # pylint: disable=duplicate-code
    _check(
        ole.CoCreateInstance(
            ctypes.byref(_guid(class_id)),
            None,
            1,
            ctypes.byref(_guid(interface_id)),
            ctypes.byref(pointer),
        ),
        "CoCreateInstance(SAPI)",
    )
    # pylint: enable=duplicate-code
    return pointer


def _name(ole, token):
    with ExitStack() as cleanup:
        attributes = _POINTER()
        cleanup.callback(_release, attributes)
        _check(
            _method(token, 9, _LONG, [ctypes.c_wchar_p, ctypes.POINTER(_POINTER)])(
                token, "Attributes", ctypes.byref(attributes)
            ),
            "ISpObjectToken.OpenKey(Attributes)",
        )
        text = _POINTER()
        cleanup.callback(ole.CoTaskMemFree, text)
        _check(
            _method(attributes, 6, _LONG, [ctypes.c_wchar_p, ctypes.POINTER(_POINTER)])(
                attributes, "Name", ctypes.byref(text)
            ),
            "ISpDataKey.GetStringValue(Name)",
        )
        return ctypes.wstring_at(text) if text else ""


def _voices(ole, cleanup):
    category = _create(
        ole,
        cleanup,
        "a910187f-0c7a-45ac-92cc-59edafb77b53",
        "2d3d3845-39af-4850-bbf9-40b49780011d",
    )
    _check(
        _method(category, 15, _LONG, [ctypes.c_wchar_p, _LONG])(
            category, r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech\Voices", 0
        ),
        "ISpObjectTokenCategory.SetId(Voices)",
    )
    tokens = _POINTER()
    cleanup.callback(_release, tokens)
    _check(
        _method(
            category,
            18,
            _LONG,
            [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(_POINTER)],
        )(category, None, None, ctypes.byref(tokens)),
        "ISpObjectTokenCategory.EnumTokens",
    )
    count = _ULONG()
    _check(
        _method(tokens, 8, _LONG, [ctypes.POINTER(_ULONG)])(
            tokens, ctypes.byref(count)
        ),
        "IEnumSpObjectTokens.GetCount",
    )
    result = {}
    for index in range(count.value):
        token = _POINTER()
        cleanup.callback(_release, token)
        _check(
            _method(tokens, 7, _LONG, [_ULONG, ctypes.POINTER(_POINTER)])(
                tokens, index, ctypes.byref(token)
            ),
            "IEnumSpObjectTokens.Item",
        )
        result[_name(ole, token)] = token
    return result


def _speak(ole, cleanup, voice, text):
    stream = _create(
        ole,
        cleanup,
        "715d9c59-4442-11d2-9605-00c04f8ee628",
        "12e3cca9-7518-44c5-a5e7-ba5a79cb929e",
    )
    with tempfile.TemporaryDirectory(prefix="ansible-speech-") as directory:
        path = os.path.join(directory, "speech.wav")
        _check(
            _method(
                stream,
                17,
                _LONG,
                [
                    ctypes.c_wchar_p,
                    _LONG,
                    ctypes.POINTER(_Guid),
                    ctypes.POINTER(_WaveFormat),
                    ctypes.c_uint64,
                ],
            )(
                stream,
                path,
                3,
                ctypes.byref(_guid("c31adbae-527f-4ff5-a230-f62bb61ff70c")),
                ctypes.byref(_WaveFormat(1, 1, 22050, 44100, 2, 16, 0)),
                0,
            ),
            "ISpStream.BindToFile",
        )
        try:
            # Direct SAPI device output rejects remote non-console sessions.
            # Native synthesis to WAV plus WinMM playback uses the same audio
            # device without requiring a different Ansible execution session.
            _check(
                _method(voice, 13, _LONG, [_POINTER, _LONG])(voice, stream, 0),
                "ISpVoice.SetOutput",
            )
            # SPF_IS_NOT_XML preserves angle brackets and other text literally.
            _check(
                _method(voice, 20, _LONG, [ctypes.c_wchar_p, _ULONG, _POINTER])(
                    voice, text, 16, None
                ),
                "ISpVoice.Speak",
            )
        finally:
            _check(_method(stream, 18, _LONG, [])(stream), "ISpStream.Close")
        play_wave(path)


def render(text, requested_voice, speed, check_mode):
    """Select an installed voice and synchronously speak unless previewing.

    :param str text: Literal text to synthesize, never interpreted as SAPI XML.
    :param requested_voice: Installed voice name or None for the default.
    :type requested_voice: str or None
    :param int speed: Speaking rate from -10 through 10.
    :param bool check_mode: Read voice metadata without producing audio.
    :returns: Selected voice name and an optional unavailable-voice warning.
    :rtype: tuple
    :raises OSError: SAPI, a voice, or the audio device rejects the operation.
    """
    ole, _automation = _libraries()
    ole.CoTaskMemFree.argtypes = [_POINTER]
    ole.CoTaskMemFree.restype = None
    with ExitStack() as cleanup:
        initialized = ole.CoInitializeEx(None, 2)
        if initialized & 0xFFFFFFFF != 0x80010106:
            _check(initialized, "CoInitializeEx(SAPI)")
            cleanup.callback(ole.CoUninitialize)
        voice = _create(
            ole,
            cleanup,
            "96749377-3391-11d2-9ee3-00c04f797396",
            "6c44df74-72b9-4992-a1ec-ef996e0422d4",
        )
        warning = None
        if requested_voice:
            selected = next(
                (
                    token
                    for name, token in _voices(ole, cleanup).items()
                    if name.lower() == requested_voice.lower()
                ),
                None,
            )
            if selected is None:
                warning = (
                    "Could not load voice '{0}', using system default voice.".format(
                        requested_voice
                    )
                )
            else:
                _check(
                    _method(voice, 18, _LONG, [_POINTER])(voice, selected),
                    "ISpVoice.SetVoice",
                )
        selected = _POINTER()
        cleanup.callback(_release, selected)
        _check(
            _method(voice, 19, _LONG, [ctypes.POINTER(_POINTER)])(
                voice, ctypes.byref(selected)
            ),
            "ISpVoice.GetVoice",
        )
        name = _name(ole, selected)
        _check(_method(voice, 28, _LONG, [_LONG])(voice, speed), "ISpVoice.SetRate")
        if not check_mode:
            _speak(ole, cleanup, voice, text)
        return name, warning


def play_wave(path):
    """Play one WAV synchronously without falling back to a system sound.

    :param str path: Existing WAV file path.
    :raises OSError: Windows cannot load or play the specified sound.
    """
    multimedia = ctypes.WinDLL("winmm")
    multimedia.PlaySoundW.argtypes = [ctypes.c_wchar_p, _POINTER, _ULONG]
    multimedia.PlaySoundW.restype = _LONG
    # SND_FILENAME | SND_NODEFAULT; synchronous playback is the default.
    if not multimedia.PlaySoundW(path, None, 0x20002):
        raise OSError("Windows could not play WAV file: " + path)
