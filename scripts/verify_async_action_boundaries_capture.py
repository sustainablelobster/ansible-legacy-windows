"""Verify paired pre-transfer async failures and exact owned recovery offline."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
from pathlib import Path
from typing import Any, cast


def _observation(document: dict[str, Any], name: str) -> dict[str, Any]:
    result = document[name]
    # JSON booleans must not masquerade as an integer process exit code.
    # pylint: disable-next=unidiomatic-typecheck
    assert type(result["rc"]) is int and result["rc"] == 0, name
    observed = cast(dict[str, Any], json.loads(result["stdout"]))
    assert observed["python"] == [3, 4, 4], name
    return observed


def verify_capture(document: dict[str, Any]) -> int:
    """Compare four literal public pairs and original protected state.

    :param document: Unmodified playbook capture of both action sides and recovery.
    :returns: Four verified public pairs.
    :raises AssertionError: If arguments, results, types or recovery differ.
    """
    count = 0
    for name in ("win_copy", "win_template"):
        native = document["native_" + name]["results"]
        original = document["original_" + name]["results"]
        assert len(native) == len(original) == 2
        for poll, first, second in zip((0, 1), native, original):
            assert type(first["boundary_poll"]) is type(second["boundary_poll"]) is int
            assert first["boundary_poll"] == second["boundary_poll"] == poll
            for value in (first, second):
                assert value["failed"] is True and value["changed"] is False
                assert "ansible_job_id" not in value
                assert "does not support async." in value["msg"]
            # Only the requested collection namespace and standard diagnostics
            # differ; retain every actual public field/type without coercion.
            left = {
                key: value
                for key, value in first.items()
                if key not in ("invocation", "exception")
            }
            right = {
                key: value
                for key, value in second.items()
                if key not in ("invocation", "exception")
            }
            right["msg"] = right["msg"].replace(
                "ansible.windows." + name, "sustainablelobster.legacy_windows." + name
            )
            assert json.dumps(left, sort_keys=True) == json.dumps(
                right, sort_keys=True
            ), (name, poll, left, right)
            count += 1
    before = _observation(document, "before")
    protected = _observation(document, "protected")
    after = _observation(document, "after")
    final = _observation(document, "final")
    assert before["root"] is None
    assert (
        protected["root"]
        == after["root"]
        == final["root"]
        == document["workspace"]["path"]
    )
    assert protected == after
    assert protected["root_exists"] is True
    assert set(protected["files"]) == {"sentinel.txt"}
    assert protected["directories"] == []
    assert before["staging"] == protected["staging"] == final["staging"]
    assert before["root_exists"] is final["root_exists"] is False
    assert final["files"] == {} and final["directories"] == []
    assert document["workspace_absent"] is True
    return count


def main() -> None:
    """Validate one retained capture without contacting a Windows host."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    arguments = parser.parse_args()
    count = verify_capture(json.loads(arguments.capture.read_text(encoding="utf-8")))
    print(
        f"PASS: {count} pre-transfer async pairs, protected bytes/metadata and staging recovery"
    )


if __name__ == "__main__":
    main()
