# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read binding states in a separate process for a restoring module demo."""

import json
import sys

from legacy_community_windows_net_adapter_feature_native import (  # pylint: disable=import-error
    NetworkBindings,
)


def main():
    """Print named adapters and installed nonessential binding-path states.

    :raises ValueError: No reversible nonessential component is installed.
    """
    assert sys.version_info[:3] >= (3, 4, 4)
    with NetworkBindings(False) as bindings:
        adapters = bindings.adapters()
        # A client binding does not remove the NDIS QoS filter from the adapter
        # carrying SSH. Native QoS removal can drop even an async launch reply.
        for component in ("ms_msclient", "ms_pacer", "ms_psched"):
            try:
                paths = bindings.paths(component, adapters)
            except ValueError:
                continue
            if any(paths.values()):
                break
        else:
            raise ValueError("No installed nonessential binding fixture was found")
        result = {
            "python": list(sys.version_info[:3]),
            "component_id": component,
            "bindings": [
                {"interface": name, "states": [path["enabled"] for path in paths[name]]}
                for name in sorted(adapters)
            ],
        }
    print(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    main()
