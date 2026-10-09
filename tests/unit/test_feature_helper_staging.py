"""Import the maintained embedded fixture helper closures without Windows calls."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

# PyYAML is provided by the pinned developer environment without typing stubs.
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

from tests.unit.payload_support import ROOT


@pytest.mark.parametrize(
    "filename,program",
    [
        ("feature_fixture.yml", "feature_program"),
        ("feature_info_fixture.yml", "feature_info_program"),
        ("dns_zone_fixture.yml", "dns_zone_fixture_program"),
    ],
)
def test_embedded_feature_loaders_stage_every_imported_sibling(
    filename: str, program: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Compile real helper sources while omitting only native fixture execution.

    :param filename: Maintained fixture variables containing the helper loader.
    :param program: Loader's program variable.
    :param monkeypatch: Scoped module staging that cannot leak to another test.
    """
    integration = ROOT / "tests/integration"
    document = yaml.safe_load((integration / "vars" / filename).read_text())

    def _lookup(kind: str, path: str) -> str:
        assert kind == "file"
        selected = Path(path).resolve()
        if selected == integration / "fixtures/win_dns_zone.py":
            return ""  # Its native setup is outside this loader regression test.
        return selected.read_text(encoding="utf-8")

    environment = Environment()
    environment.filters["to_json"] = json.dumps
    values: dict[str, Any] = {"playbook_dir": str(integration), "lookup": _lookup}
    for name, source in document.items():
        if name.endswith("_source"):
            values[name] = environment.from_string(source).render(values)
    values.update(feature_fixture="", feature_info_fixture="")
    source = environment.from_string(document[program]).render(values)
    with monkeypatch.context() as staging:
        for name in (
            "legacy_windows_regex",
            "legacy_windows_find_match",
            "legacy_windows_wmi",
            "legacy_windows_feature_legacy",
            "legacy_windows_feature_info",
            "legacy_windows_feature_manage",
            "legacy_windows_dns_classic",
            "legacy_windows_dns_zone",
            "win_dns_zone_state",
        ):
            # Track each map entry before the loader replaces it, including
            # newly staged modules that must not leak into another test.
            staging.setitem(sys.modules, name, ModuleType(name))
        namespace: dict[str, Any] = {}
        exec(compile(source, filename, "exec"), namespace)  # pylint: disable=exec-used
        legacy = sys.modules["legacy_windows_feature_legacy"]
        assert legacy.ServerManager
        information = (
            namespace.get("native_feature")
            or sys.modules["legacy_windows_feature_info"]
        )
        assert information.legacy is legacy
