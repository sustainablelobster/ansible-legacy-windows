"""Check the public smoke's interpreter floor without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import json
from types import SimpleNamespace

import pytest
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

from tests.unit.payload_support import ROOT


@pytest.mark.parametrize(
    "version,accepted",
    [
        ((3, 4, 3), False),
        ((3, 4, 4), True),
        ((3, 4, 10), True),
        ((3, 5, 0), True),
        ((3, 13, 15), True),
    ],
)
def test_release_smoke_accepts_the_minimum_and_newer_python(
    version: tuple[int, int, int], accepted: bool
) -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/release_smoke.yml").read_text(encoding="utf-8")
    )[0]
    runtime = next(
        task for task in play["tasks"] if task.get("register") == "smoke_runtime"
    )
    script = runtime["sustainablelobster.legacy_windows.win_command"]["argv"][-1]
    assertion = next(
        node for node in ast.parse(script).body if isinstance(node, ast.Assert)
    )
    code = compile(
        ast.Module(body=[assertion], type_ignores=[]), "smoke-version", "exec"
    )
    namespace = {"sys": SimpleNamespace(version_info=version)}
    # Run the maintained Assert node rather than duplicate its predicate here.
    if accepted:
        exec(code, namespace)  # pylint: disable=exec-used
    else:
        with pytest.raises(AssertionError):
            exec(code, namespace)  # pylint: disable=exec-used

    assertions = next(
        task["ansible.builtin.assert"]["that"]
        for task in play["tasks"]
        if "ansible.builtin.assert" in task
    )
    expression = next(item for item in assertions if "smoke_runtime.stdout" in item)
    environment = Environment()
    environment.filters["from_json"] = json.loads
    evaluate = environment.compile_expression(expression)
    assert evaluate(smoke_runtime={"stdout": json.dumps(list(version))}) is accepted
