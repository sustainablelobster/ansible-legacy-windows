"""Observe one genuine noninstalling WUA search and its owned diagnostics."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
import os
import sys
import time


def _load(source, name, **values):
    namespace = dict(values, __name__=name)
    # Literal maintained observers are supplied through win_command stdin;
    # they are not globally installed or substituted for the WUA provider.
    exec(compile(source, name + ".py", "exec"), namespace)  # pylint: disable=exec-used
    return namespace


def _catalogue():
    provider = _load(
        globals()["PROVIDER_SOURCE"],
        "owned_search_provider",
        HELPER_SOURCES=globals()["HELPER_SOURCES"],
    )
    began = time.monotonic()
    with provider["UpdateAgent"]() as agent:
        session = agent.create_session()
        searcher = session.call("CreateUpdateSearcher")
        # This read-only cached observation is not the public online request.
        # Select the same real catalogue, without any policy/trust-store change.
        searcher.put("ServerSelection", 2)
        searcher.put("Online", False)
        searcher.put("CanAutomaticallyUpgradeService", False)
        # The cached-catalog oracle is separate from the online module operation.
        # pylint: disable=duplicate-code
        result = agent.operation(
            searcher,
            "Search",
            "IsInstalled = 0",
            lambda: time.monotonic() - began >= 120,
            None,
        )
        updates = []
        for update in result.get("Updates").items():
            identity = update.get("Identity")
            updates.append(
                {
                    "id": identity.get("UpdateID"),
                    "revision": identity.get("RevisionNumber"),
                    "title": update.get("Title"),
                    "eula_accepted": update.get("EulaAccepted"),
                    "downloaded": update.get("IsDownloaded"),
                    "installed": update.get("IsInstalled"),
                }
            )
        # pylint: enable=duplicate-code
        return {
            "python": list(sys.version_info[:3]),
            "online": False,
            "server_selection": 2,
            "criteria": "IsInstalled = 0",
            "result_code": result.get("ResultCode"),
            "updates": updates,
            "elapsed": time.monotonic() - began,
        }


def _diagnostics(workspace):
    files = {}
    for name in ("native.log", "original.log"):
        path = os.path.join(workspace, name)
        if os.path.isfile(path):
            with open(path, "rb") as stream:
                body = stream.read()
            files[name] = {
                "body_base64": base64.b64encode(body).decode("ascii"),
                "text": body.decode("utf-8-sig"),
            }
        else:
            files[name] = None
    protected = _load(globals()["SETUP_SOURCE"], "owned_search_file")["_file"](
        os.path.join(workspace, "protected.bin")
    )
    return {
        "workspace": workspace,
        "logs": files,
        "protected": protected,
        "entries": sorted(os.listdir(workspace)),
    }


def main():
    """Run a bounded observer without accepting EULAs or servicing updates.

    :raises ValueError: The requested operation is unknown.
    :raises OSError: An actual provider, cache or owned-process observation fails.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    workspace, operation = sys.argv[1:3]
    runas = _load(
        globals()["RUNAS_SOURCE"],
        "owned_search_runas",
        WMI_SOURCE=globals()["WMI_SOURCE"],
        BASE_SOURCE=globals()["BASE_SOURCE"],
        MONITOR_SOURCE=globals()["MONITOR_SOURCE"],
    )
    if operation == "observe":
        result = runas["_observe"]()
    elif operation == "cache":
        result = _load(globals()["CACHE_SOURCE"], "owned_search_cache")["observe"]()
    elif operation == "catalogue":
        result = _catalogue()
    elif operation == "prepare":
        assert os.path.basename(workspace).startswith("legacy-windows-updates-runas-")
        assert not os.listdir(workspace)
        with open(os.path.join(workspace, "protected.bin"), "xb") as stream:
            stream.write(b"search protected sibling\x00\xff")
        result = _load(globals()["SETUP_SOURCE"], "owned_search_file")["_file"](
            os.path.join(workspace, "protected.bin")
        )
    elif operation in ("start", "stop"):
        result = runas["_" + operation](workspace)
    elif operation == "diagnostics":
        result = _diagnostics(workspace)
    else:
        raise ValueError("Unknown successful-search observation operation.")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
