"""Keep integration inputs and controller outputs independent of the checkout."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from pathlib import Path
from typing import Any, cast

import pytest

# The pinned development environment supplies PyYAML and Ansible without stubs.
import yaml  # type: ignore[import-untyped]
from ansible.errors import AnsibleError  # type: ignore[import-untyped]
from ansible.plugins.loader import init_plugin_loader  # type: ignore[import-untyped]
from ansible.template import (  # type: ignore[import-untyped]
    Templar,
    trust_as_template,
)
from ansible.utils.collection_loader import (  # type: ignore[import-untyped]
    AnsibleCollectionConfig,
)

from tests.unit.payload_support import ROOT

_INTEGRATION = ROOT / "tests/integration"
_OUTPUTS = [
    ("native_async.yml", "evidence_dir"),
    ("win_eventlog.yml", "eventlog_evidence_dir"),
    ("win_http_trust.yml", "http_trust_evidence_dir"),
    ("win_https.yml", "https_evidence_dir"),
]
_INPUTS = [
    ("dsc3.yml", "dsc3_archive", "DSC-3.1.2-x86_64-pc-windows-msvc.zip"),
    (
        "hotfix.yml",
        "hotfix_inapplicable_controller_source",
        "hotfix-inapplicable-windows8-x64.msu",
    ),
    (
        "package_children_fixture.yml",
        "package_children_controller_x86",
        "package-children-x86",
    ),
]


def _play(filename: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        yaml.safe_load((_INTEGRATION / filename).read_text(encoding="utf-8"))[0],
    )


def _render(expression: str, variables: dict[str, Any]) -> Any:
    if AnsibleCollectionConfig.collection_finder is None:
        init_plugin_loader()
    trusted = {
        key: trust_as_template(value) if isinstance(value, str) else value
        for key, value in variables.items()
    }
    return Templar(variables=trusted).template(trust_as_template(expression))


def test_integration_sources_do_not_depend_on_session_scratch_paths() -> None:
    checkout_scratch = re.compile(r"\.\./\.\./tmp[/\\][^/'\"\\]+")
    offending = [
        str(path.relative_to(ROOT))
        for path in sorted(_INTEGRATION.rglob("*.yml"))
        if checkout_scratch.search(path.read_text(encoding="utf-8"))
    ]
    assert offending == []


@pytest.mark.parametrize("filename,override", _OUTPUTS)
@pytest.mark.parametrize("environment", [None, "", "controller temporary storage"])
def test_output_defaults_follow_controller_temporary_storage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    filename: str,
    override: str,
    environment: str | None,
) -> None:
    if environment is None:
        monkeypatch.delenv("TMPDIR", raising=False)
    else:
        monkeypatch.setenv("TMPDIR", str(tmp_path / environment) if environment else "")
    expected = str(tmp_path / environment) if environment else "/tmp"
    play = _play(filename)
    task = next(task for task in play["tasks"] if "ansible.builtin.tempfile" in task)
    variables = dict(play.get("vars", {}), playbook_dir="/unrelated/checkout")
    assert _render(task["ansible.builtin.tempfile"]["path"], variables) == expected
    variables[override] = str(tmp_path / "caller-selected output")
    assert (
        _render(task["ansible.builtin.tempfile"]["path"], variables)
        == variables[override]
    )


@pytest.mark.parametrize(
    "filename,override",
    [
        ("win_eventlog.yml", "eventlog_evidence_dir"),
        ("win_https.yml", "https_evidence_dir"),
        ("win_optional_feature.yml", "evidence_dir"),
        ("win_dhcp_lease_legacy.yml", "evidence_dir"),
    ],
)
@pytest.mark.parametrize("selection", [None, "/tmp", "/tmp/", "temporary", "custom"])
def test_directory_preparation_never_chmods_shared_temporary_storage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    filename: str,
    override: str,
    selection: str | None,
) -> None:
    controller_temp = str(tmp_path / "controller temporary storage")
    monkeypatch.setenv("TMPDIR", controller_temp)
    play = _play(filename)
    task = next(task for task in play["tasks"] if "ansible.builtin.file" in task)
    variables = dict(play.get("vars", {}))
    if selection is not None:
        variables[override] = {
            "temporary": controller_temp + "/",
            "custom": str(tmp_path / "private captures"),
        }.get(selection, selection)
    conditions = task["when"]
    if isinstance(conditions, str):
        conditions = [conditions]
    should_prepare = all(
        _render("{{ " + condition + " }}", variables) for condition in conditions
    )
    assert should_prepare is (selection == "custom")


@pytest.mark.parametrize("filename,variable,basename", _INPUTS)
def test_external_fixture_paths_use_explicit_or_environment_directories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    filename: str,
    variable: str,
    basename: str,
) -> None:
    variables = yaml.safe_load(
        (_INTEGRATION / "vars" / filename).read_text(encoding="utf-8")
    )
    monkeypatch.delenv("LEGACY_WINDOWS_TEST_ARTIFACTS", raising=False)
    with pytest.raises(AnsibleError, match="Set integration_artifact_dir"):
        _render(variables[variable], variables)
    environment = tmp_path / "external fixtures"
    monkeypatch.setenv("LEGACY_WINDOWS_TEST_ARTIFACTS", str(environment))
    assert _render(variables[variable], variables) == str(environment / basename)
    explicit = tmp_path / "caller fixtures"
    variables["integration_artifact_dir"] = str(explicit)
    assert _render(variables[variable], variables) == str(explicit / basename)
    variables[variable] = str(tmp_path / "individual fixture")
    assert _render(variables[variable], variables) == variables[variable]
