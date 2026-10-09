# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare measured DNS fixture transitions and unordered provider metadata."""

import json


def _comparable_components(components):
    if components is None:
        return None
    result = {}
    for name, component in components.items():
        item = dict(component)
        # Only these private metadata arrays have reshuffled after servicing.
        # Preserve raw captures and every actual role/CLI state literally.
        if item.get("SubFeatures") is not None:
            item["SubFeatures"] = sorted(item["SubFeatures"])
        if item.get("OptionalCompanions") is not None:
            item["OptionalCompanions"] = sorted(
                item["OptionalCompanions"],
                key=lambda value: json.dumps(value, sort_keys=True),
            )
        result[name] = item
    return result


def _class_catalogue(namespace):
    if namespace is None:
        return None
    result = dict(namespace)
    classes = {row["__CLASS"]: row for row in namespace["classes"]}
    assert len(classes) == len(namespace["classes"])
    result["classes"] = classes
    return result


def _cache_countdown(before, after, role_owned):
    if before == after:
        return []
    assert role_owned and before is not None and after is not None
    key = "MicrosoftDNS_ResourceRecord"
    assert {name: value for name, value in before.items() if name != key} == {
        name: value for name, value in after.items() if name != key
    }
    retained_before, retained_after, changes = [], [], []
    for original, current in zip(before[key], after[key]):
        if original == current:
            retained_before.append(original)
            retained_after.append(current)
            continue
        assert (
            original["__CLASS"] == "MicrosoftDNS_AType"
            and original["ContainerName"] in ("..Cache", "..RootHints")
            and original["OwnerName"] == "localhost." + original["ContainerName"]
            and original["IPAddress"] == "127.0.0.1"
            and original["RecordData"] == "127.0.0.1"
            and 0 <= current["TTL"] < original["TTL"]
        )
        assert {name: value for name, value in original.items() if name != "TTL"} == {
            name: value for name, value in current.items() if name != "TTL"
        }
        changes.append({"before": original, "after": current})
    assert len(before[key]) == len(after[key])
    assert retained_before == retained_after
    assert {change["before"]["ContainerName"] for change in changes} == {
        "..Cache",
        "..RootHints",
    }
    assert len(changes) == 2
    assert (
        len({change["before"]["TTL"] - change["after"]["TTL"] for change in changes})
        == 1
    )
    return changes


def _role_initialization(before, after, role_owned):
    if before == after:
        return None
    assert role_owned and len(before) == len(after) == 1
    original, current = before[0], after[0]
    assert original["BootMethod"] == 0 and current["BootMethod"] == 3
    assert {
        name: value for name, value in original.items() if name != "BootMethod"
    } == {name: value for name, value in current.items() if name != "BootMethod"}
    return {"before": original, "after": current}
