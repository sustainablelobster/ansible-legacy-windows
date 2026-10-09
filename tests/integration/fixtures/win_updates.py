# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe WUA search state without accepting EULAs or servicing updates."""

import json
import sys
import time
import types

# The playbook supplies immutable native helper bytes through the established
# win_command stdin interface; no helper is installed globally on the host.
for _name in ("legacy_windows_wmi", "legacy_windows_updates_native"):
    _module = types.ModuleType(_name)
    sys.modules[_name] = _module
    # These immutable helper bytes deliberately form the executable fixture.
    # pylint: disable=exec-used
    exec(
        compile(globals()["HELPER_SOURCES"][_name], _name + ".py", "exec"),
        _module.__dict__,
    )
    # pylint: enable=exec-used

# This module is injected above rather than installed as a target dependency.
from legacy_windows_updates_native import (  # pylint: disable=import-error,wrong-import-position
    UpdateAgent,
)


def observe(online, criteria="IsInstalled = 0"):
    """Capture update identity and mutable servicing flags before public writes.

    :param bool online: Whether the preparation search may contact its configured catalog.
    :param str criteria: Explicit native observation query, not public-module behavior.
    :returns: Complete pending-update identity/EULA/download flags and search status.
    :rtype: dict
    :raises OSError: Native WUA access or search fails.
    """
    if sys.version_info[:3] != (3, 4, 4):
        raise OSError("The Windows Updates fixture requires actual Python 3.4.4.")
    began = time.monotonic()
    with UpdateAgent() as agent:
        required = agent.reboot_required()
        session = agent.create_session()
        searcher = session.call("CreateUpdateSearcher")
        if not online:
            # These per-object preparation flags never approximate public
            # default behavior; they only inspect the currently cached catalog.
            searcher.put("Online", False)
            searcher.put("CanAutomaticallyUpgradeService", False)
        result = agent.operation(
            searcher,
            "Search",
            criteria,
            lambda: time.monotonic() - began >= 120,
            None,
        )
        rows = []
        for update in result.get("Updates").items():
            identity = update.get("Identity")
            rows.append(
                {
                    "id": identity.get("UpdateID"),
                    "revision": identity.get("RevisionNumber"),
                    "title": update.get("Title"),
                    "eula_accepted": update.get("EulaAccepted"),
                    "downloaded": update.get("IsDownloaded"),
                    "installed": update.get("IsInstalled"),
                    "uninstallable": update.get("IsUninstallable"),
                    "reboot_behaviour": update.get("InstallationBehavior").get(
                        "RebootBehavior"
                    ),
                    "kb": update.get("KBArticleIDs").items(),
                }
            )
        return {
            "python": list(sys.version_info[:3]),
            "online": online,
            "reboot_required": required,
            "result_code": result.get("ResultCode"),
            "updates": rows,
            "elapsed": time.monotonic() - began,
        }


if __name__ == "__main__":
    print(
        json.dumps(
            observe(
                sys.argv[1] == "online",
                sys.argv[2] if len(sys.argv) > 2 else "IsInstalled = 0",
            )
        )
    )
