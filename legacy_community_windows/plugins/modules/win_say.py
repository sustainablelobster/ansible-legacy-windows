#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2016, Jon Hawkesworth (@jhawkesworth)
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Speak literal text and play WAV files through native Windows facilities."""

# WANT_JSON

import locale
import os

from legacy_community_windows_speech import (  # pylint: disable=import-error
    play_wave,
    render,
)
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)
from legacy_windows_text import decode_bytes  # pylint: disable=import-error

DOCUMENTATION = r"""
---
module: win_say
short_description: Speak text and optionally play WAV sounds
description:
  - Uses the installed Windows Speech API to speak messages synchronously.
  - Audio output requires a working device and the Windows Audio service.
options:
  msg:
    description: Text to speak, mutually exclusive with O(msg_file).
    type: str
  msg_file:
    description: Path to a text file to speak, mutually exclusive with O(msg).
    type: path
  voice:
    description: Installed voice name. Unavailable names warn and use the default.
    type: str
  speech_speed:
    description: Speaking rate from -10 (slowest) through 10 (fastest).
    type: int
    default: 0
  start_sound_path:
    description: WAV file to play before speaking.
    type: path
  end_sound_path:
    description: WAV file to play after speaking.
    type: path
notes:
  - At least one message or sound option is required.
  - Check mode validates files and selects the voice without producing audio.
  - Like the released module, successful playback does not report C(changed).
  - Voices must be registered with the installed SAPI engine for the target
    Python interpreter's architecture.
author:
  - Jon Hawkesworth (@jhawkesworth)
"""

EXAMPLES = r"""
- name: Warn of an impending deployment
  sustainablelobster.legacy_community_windows.win_say:
    msg: Deployment begins in five minutes.

- name: Speak a report with an alert sound
  sustainablelobster.legacy_community_windows.win_say:
    msg_file: C:\Reports\status.txt
    start_sound_path: C:\Windows\Media\ding.wav
"""

RETURN = r"""
message_text:
  description: Text the module attempted to speak.
  returned: success
  type: str
voice:
  description: Selected installed voice name.
  returned: when speaking text
  type: str
voice_info:
  description: Warning when the requested voice could not be selected.
  returned: when requested voice is unavailable
  type: str
"""

_PARAMETERS = (
    "msg",
    "msg_file",
    "voice",
    "speech_speed",
    "start_sound_path",
    "end_sound_path",
)


def _parameters(arguments):
    options = {name: as_string(arguments.get(name), name) for name in ("msg", "voice")}
    for name in ("msg_file", "start_sound_path", "end_sound_path"):
        options[name] = as_path(arguments.get(name), name)
    if options["msg"] is not None and options["msg_file"] is not None:
        raise ValueError("msg and msg_file are mutually exclusive")
    if all(
        options[name] is None
        for name in _PARAMETERS
        if name not in ("voice", "speech_speed")
    ):
        raise ValueError(
            "one of msg, msg_file, start_sound_path or end_sound_path is required"
        )
    raw = arguments.get("speech_speed", 0)
    try:
        speed = int(round(raw)) if isinstance(raw, float) else int(raw)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(
            "speech_speed must be an integer from -10 through 10"
        ) from error
    if not -10 <= speed <= 10:
        raise ValueError("speech_speed must be an integer from -10 through 10")
    options["speech_speed"] = speed
    return options


def _say(arguments):
    options = _parameters(arguments)
    check = as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode")
    words = options["msg"]
    for name in ("msg_file", "start_sound_path", "end_sound_path"):
        if options[name] and not os.path.isfile(options[name]):
            raise ValueError(
                "{0} could not be found or opened: {1}".format(name, options[name])
            )
    if options["msg_file"]:
        with open(options["msg_file"], "rb") as source:
            text = decode_bytes(source.read(), locale.getpreferredencoding(False))
        words = "".join(line + "\r\n" for line in text.splitlines())
    result = {"changed": False, "message_text": words or ""}
    if options["start_sound_path"] and not check:
        play_wave(options["start_sound_path"])
    if words:
        name, warning = render(words, options["voice"], options["speech_speed"], check)
        result["voice"] = name
        if warning:
            result.update(voice_info=warning, warnings=[warning])
    if options["end_sound_path"] and not check:
        play_wave(options["end_sound_path"])
    return result


def main():
    """Read a WANT_JSON request and return the native speech result."""
    run_module(
        lambda: _say(
            read_arguments(
                _PARAMETERS,
                "sustainablelobster.legacy_community_windows.win_say",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
