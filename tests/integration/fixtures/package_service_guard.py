# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own stopped services and a harmless installer counter for package guards."""

import json
import os
import shutil
import subprocess
import sys
import time
import uuid

# Windows supplies the fixture's independent registry observer.
import winreg  # pylint: disable=import-error


def _sc(*arguments):
    with subprocess.Popen(
        [os.path.join(os.environ["SystemRoot"], "System32", "sc.exe")]
        + list(arguments),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        try:
            output, error = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
    return {
        "rc": process.returncode,
        "stdout": output.decode("mbcs", "replace"),
        "stderr": error.decode("mbcs", "replace"),
    }


def _require_sc(*arguments):
    result = _sc(*arguments)
    if result["rc"]:
        raise OSError("sc.exe {0}: {1}".format(arguments, result))
    return result


def _configuration(name):
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\" + name,
        ) as key:
            return {
                field: winreg.QueryValueEx(key, field)[0]
                for field in ("ImagePath", "DisplayName", "Start", "Type")
            }
    except FileNotFoundError:
        return None


def _write_state(root, state):
    with open(
        os.path.join(root, "service-guard-state.json"), "w", encoding="utf-8"
    ) as stream:
        json.dump(state, stream, sort_keys=True)


def _read_state(root):
    with open(
        os.path.join(root, "service-guard-state.json"), encoding="utf-8"
    ) as stream:
        return json.load(stream)


def _count(root):
    path = os.path.join(root, "installer-count.txt")
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as stream:
        return int(stream.read())


def _observe(root, state):
    return {
        "count": _count(root),
        "services": {name: _configuration(name) for name in state["names"]},
        "query": {name: _sc("query", name) for name in state["names"]},
    }


def _setup(root):
    prefix = "LegacyPackageGuard" + uuid.uuid4().hex
    names = [prefix + suffix for suffix in ("A", "B", "[L]", "Denied")]
    image = '"{0}"'.format(sys.executable)
    installer = os.path.join(root, "counter installer.exe")
    state = {
        "prefix": prefix,
        "names": names,
        "image": image,
        "sddl": None,
        "installer": installer,
        "python_home": sys.prefix,
    }
    assert all(_configuration(name) is None for name in names)
    _write_state(root, state)
    # Package providers may grant SYSTEM read access to their source. Copy the
    # executable so the test never changes the installed interpreter's ACL.
    shutil.copy2(sys.executable, installer)
    for filename in ("python34.dll", "MSVCR100.dll"):
        source = next(
            os.path.join(directory, filename)
            for directory in (
                os.path.dirname(sys.executable),
                os.path.join(os.environ["SystemRoot"], "System32"),
            )
            if os.path.isfile(os.path.join(directory, filename))
        )
        shutil.copy2(source, os.path.join(root, filename))
    for name in names:
        _require_sc(
            "create",
            name,
            "binPath=",
            image,
            "start=",
            "demand",
            "DisplayName=",
            "Display " + name,
        )
    assert all(_sc("query", name)["rc"] == 0 for name in names)
    return dict(state, observation=_observe(root, state))


def _deny(root, state):
    name = state["names"][-1]
    shown = _require_sc("sdshow", name)
    state["sddl"] = next(
        line.strip()
        for line in shown["stdout"].splitlines()
        if line.strip().startswith(("D:", "O:", "G:", "S:"))
    )
    # Only this uniquely owned service changes. Preserve its original DACL
    # before denying SERVICE_QUERY_STATUS; administrators retain WRITE_DAC.
    _write_state(root, state)
    _require_sc(
        "sdset",
        name,
        "D:(D;;LC;;;WD)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)",
    )
    observation = _observe(root, state)
    # XP's sc.exe can report a failed OpenService without a nonzero exit code.
    assert "FAILED 5" in observation["query"][name]["stdout"], observation
    return observation


def _restore(root, state):
    if state["sddl"] is not None:
        _require_sc("sdset", state["names"][-1], state["sddl"])
        state["sddl"] = None
        _write_state(root, state)
    return _observe(root, state)


def _cleanup(root, state):
    _restore(root, state)
    for name in state["names"]:
        configuration = _configuration(name)
        if configuration is None:
            continue
        assert configuration["ImagePath"] == state["image"], name
        assert configuration["DisplayName"] == "Display " + name, name
        _require_sc("delete", name)
    deadline = time.time() + 10
    while any(_configuration(name) is not None for name in state["names"]):
        if time.time() >= deadline:
            raise OSError("Owned services remain after deletion")
        time.sleep(0.1)
    observation = _observe(root, state)
    assert all(value is None for value in observation["services"].values())
    return dict(observation, restored=True)


def main():
    """Run one explicitly selected fixture phase and emit its observation."""
    assert sys.version_info[:3] == (3, 4, 4)
    root, phase = sys.argv[1:]
    if phase == "install":
        count = _count(root) + 1
        with open(
            os.path.join(root, "installer-count.txt"), "w", encoding="utf-8"
        ) as stream:
            stream.write(str(count))
        result = {"count": count}
    elif phase == "setup":
        result = _setup(root)
    else:
        state = _read_state(root)
        operations = {
            "observe": _observe,
            "deny": _deny,
            "restore": _restore,
            "cleanup": _cleanup,
        }
        result = operations[phase](root, state)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
