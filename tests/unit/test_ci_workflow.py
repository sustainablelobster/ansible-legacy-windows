"""Keep hosted CI checks and release promotion separate from Windows evidence."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

# The pinned developer environment provides PyYAML without typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


def _workflow() -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    return document


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = job["steps"]
    return steps


def _run_package_step(
    workspace: Path, **values: str
) -> subprocess.CompletedProcess[str]:
    step = next(
        item
        for item in _steps(_workflow()["jobs"]["package"])
        if item.get("id") == "package"
    )
    environment = dict(
        os.environ,
        PATH=str(workspace) + os.pathsep + os.environ["PATH"],
        **values,
    )
    return subprocess.run(
        ["bash", "-euo", "pipefail"],
        input=step["run"],
        cwd=workspace,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_ci_runs_checks_on_prs_branches_tags_and_manual_dispatch() -> None:
    events = _workflow()["on"]
    assert set(events) == {"pull_request", "push", "workflow_dispatch"}
    assert events["pull_request"] is None  # Includes pull requests from forks.
    assert events["push"] == {"branches": ["main", "v1"], "tags": ["v*"]}
    assert events["workflow_dispatch"] is None


def test_ansible_lint_exclusion_applies_only_to_workflow_yaml() -> None:
    hooks = yaml.safe_load(
        (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    )
    ansible_lint = next(
        hook
        for repository in hooks["repos"]
        for hook in repository["hooks"]
        if hook["id"] == "ansible-lint"
    )
    excluded = re.compile(ansible_lint["exclude"])
    assert excluded.search(".github/workflows/ci.yml")
    assert excluded.search(".github/workflows/release.yaml")
    assert not excluded.search(".github/ansible.yml")
    assert not excluded.search("tests/integration/release_smoke.yml")


def test_quality_jobs_are_parallel_and_use_the_locked_linux_toolchain() -> None:
    jobs = _workflow()["jobs"]
    assert set(jobs) == {"lint", "unit", "package", "publish"}
    for name in ("lint", "unit", "package"):
        job = jobs[name]
        assert "needs" not in job
        assert job["runs-on"] == "ubuntu-24.04"
        runs = "\n".join(step.get("run", "") for step in _steps(job))
        assert "develop --no-write-lock-file path:. --command" in runs
    lint = "\n".join(step.get("run", "") for step in _steps(jobs["lint"]))
    unit = "\n".join(step.get("run", "") for step in _steps(jobs["unit"]))
    assert "just lint" in lint
    assert "git diff --exit-code" in lint
    assert "pytest -ra --junitxml=tmp/codex/ci/pytest.xml" in unit
    assert "tests/integration" not in unit


def test_publication_requires_an_origin_tag_push_and_all_checks() -> None:
    publish = _workflow()["jobs"]["publish"]
    assert set(publish["needs"]) == {"lint", "unit", "package"}
    conditions = [" ".join(item.split()) for item in publish["if"].split("&&")]
    assert conditions == [
        "github.repository == 'sustainablelobster/ansible-legacy-windows'",
        "github.event_name == 'push'",
        "startsWith(github.ref, 'refs/tags/v')",
        "needs.lint.result == 'success'",
        "needs.unit.result == 'success'",
        "needs.package.result == 'success'",
    ]
    assert publish["concurrency"]["cancel-in-progress"] is False
    assert _workflow()["concurrency"]["cancel-in-progress"] == (
        "${{ !startsWith(github.ref, 'refs/tags/') }}"
    )


def test_only_the_publisher_has_write_permissions_or_a_publish_token() -> None:
    workflow = _workflow()
    assert workflow["permissions"] == {"contents": "read"}
    for name, job in workflow["jobs"].items():
        assert job.get("permissions", workflow["permissions"]) == {
            "contents": "write" if name == "publish" else "read"
        }
        for step in _steps(job):
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False
            environment = step.get("env", {})
            if "GH_TOKEN" in environment:
                assert name == "publish"
                assert "ci_release.py publish" in step["run"]
                assert environment["GH_TOKEN"] == "${{ github.token }}"
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "secrets." not in source
    assert "self-hosted" not in source
    assert "pull_request_target" not in source


def test_actions_are_immutable_and_only_trusted_lint_runs_save_caches() -> None:
    for name, job in _workflow()["jobs"].items():
        caches = []
        for step in _steps(job):
            if "uses" not in step:
                continue
            assert re.fullmatch(r"[A-Za-z0-9_./-]+@[0-9a-f]{40}", step["uses"])
            if step["uses"].startswith("nix-community/cache-nix-action@"):
                caches.append(step)
        if name == "publish":
            assert not caches
            continue
        assert len(caches) == 1
        inputs = caches[0]["with"]
        assert "flake.lock" in inputs["primary-key"]
        assert "flake.nix" in inputs["primary-key"]
        assert ".pre-commit-config.yaml" in inputs["primary-key"]
        assert inputs["paths"] == "${{ env.PRE_COMMIT_HOME }}"
        if name == "lint":
            save = " ".join(inputs["save"].split())
            assert "github.event_name == 'push'" in save
            assert "'sustainablelobster/ansible-legacy-windows'" in save
            assert "github.ref == 'refs/heads/main'" in save
            assert "github.ref == 'refs/heads/v1'" in save
        else:
            assert inputs["save"] is False


def test_artifact_promotion_uses_this_runs_package_and_its_recorded_digest() -> None:
    jobs = _workflow()["jobs"]
    uploads = [
        step
        for name in ("unit", "package")
        for step in _steps(jobs[name])
        if step.get("uses", "").startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 2
    assert uploads[0]["with"]["path"] == "tmp/codex/ci/pytest.xml"
    assert uploads[1]["with"]["path"].splitlines() == [
        "tmp/codex/ci/package/${{ steps.package.outputs.filename }}",
        "tmp/codex/ci/package/SHA256SUMS",
        "tmp/codex/ci/package/release-notes.txt",
        "tmp/codex/ci/package/release-manifest.json",
    ]
    for upload in uploads:
        assert upload["with"]["if-no-files-found"] == "error"
        assert upload["with"]["retention-days"] == 30
        assert "${{ github.run_attempt }}" in upload["with"]["name"]
    assert jobs["package"]["outputs"]["artifact-id"] == (
        "${{ steps.upload.outputs.artifact-id }}"
    )
    publisher_steps = _steps(jobs["publish"])
    download = next(
        step
        for step in publisher_steps
        if step.get("uses", "").startswith("actions/download-artifact@")
    )
    assert download["with"] == {
        "artifact-ids": "${{ needs.package.outputs.artifact-id }}",
        "path": "tmp/codex/ci/package",
        "merge-multiple": True,
        "digest-mismatch": "error",
    }
    publish = next(step for step in publisher_steps if "run" in step)
    assert publish["env"]["EXPECTED_SHA256"] == ("${{ needs.package.outputs.sha256 }}")
    assert '--sha256 "$EXPECTED_SHA256"' in publish["run"]
    assert "just build" not in publish["run"]


@pytest.mark.parametrize("count", [0, 2])
def test_package_step_rejects_missing_or_ambiguous_archives(
    tmp_path: Path, count: int
) -> None:
    (tmp_path / "dist").mkdir()
    for index in range(count):
        (
            tmp_path / "dist" / f"sustainablelobster-legacy_windows-{index}.tar.gz"
        ).touch()
    command = tmp_path / "nix"
    command.write_text(
        "#!/bin/bash\n"
        "while [[ $1 != --command ]]; do shift; done\n"
        "shift\n"
        "[[ $1 == just && $2 == build ]] || exit 99\n",
        encoding="utf-8",
    )
    command.chmod(0o700)
    result = _run_package_step(tmp_path)
    assert result.returncode == 1
    assert "Expected exactly one collection archive." in result.stderr


@pytest.mark.parametrize(
    "event,ref_type,ref_name,tag_arguments",
    [
        ("push", "branch", "main", []),
        ("push", "tag", "v1.0.0", ["--tag", "v1.0.0"]),
        ("workflow_dispatch", "tag", "v1.0.0", []),
        ("pull_request", "branch", "example", []),
        (
            "push",
            "tag",
            "v1.0.0; touch escaped",
            ["--tag", "v1.0.0; touch escaped"],
        ),
    ],
)
def test_package_step_checks_the_same_archive_before_preparing_a_release(
    tmp_path: Path,
    event: str,
    ref_type: str,
    ref_name: str,
    tag_arguments: list[str],
) -> None:
    (tmp_path / "dist").mkdir()
    archive = "dist/sustainablelobster-legacy_windows-1.0.0.tar.gz"
    (tmp_path / archive).touch()
    command_log = tmp_path / "commands.jsonl"
    command = tmp_path / "nix"
    # Record the real workflow's commands without building or publishing.
    command.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "args = sys.argv[sys.argv.index('--command') + 1:]\n"
        "with open(os.environ['CI_COMMAND_LOG'], 'a') as output:\n"
        "    output.write(json.dumps(args) + '\\n')\n",
        encoding="utf-8",
    )
    command.chmod(0o700)
    result = _run_package_step(
        tmp_path,
        CI_COMMAND_LOG=str(command_log),
        GITHUB_EVENT_NAME=event,
        GITHUB_REF_TYPE=ref_type,
        GITHUB_REF_NAME=ref_name,
    )
    assert result.returncode == 0, result.stderr
    assert [json.loads(line) for line in command_log.read_text().splitlines()] == [
        ["just", "build"],
        ["python", "scripts/check_collection.py", "--artifact", archive],
        [
            "python",
            "scripts/ci_release.py",
            "package",
            "--artifact",
            archive,
            "--output-dir",
            "tmp/codex/ci/package",
            *tag_arguments,
        ],
    ]
    assert not (tmp_path / "escaped").exists()
