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
        CI_OUTPUT_DIR=str(workspace.parent / (workspace.name + "-ci-output")),
        GITHUB_OUTPUT=str(workspace / "github-output"),
    )
    environment.update(values)
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
    assert events["push"] == {
        "branches": ["main", "v1"],
        "tags": ["legacy_windows/v*", "legacy_ad/v*", "legacy_community_windows/v*"],
    }
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
    assert 'pytest -ra --junitxml="$CI_OUTPUT_DIR/pytest.xml"' in unit
    assert "tests/integration" not in unit


def test_ci_workflow_keeps_runner_files_outside_the_checkout() -> None:
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert not re.search(r"\btmp[/\\]", source)
    assert "PRE_COMMIT_HOME" not in _workflow().get("env", {})


@pytest.mark.parametrize("job_name", ["lint", "unit", "package", "publish"])
def test_work_directories_are_prepared_before_nix_and_cache_restore(
    job_name: str,
) -> None:
    steps = _steps(_workflow()["jobs"][job_name])
    preparation = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "Prepare runner-owned work directories"
    )
    checkout = next(
        index
        for index, step in enumerate(steps)
        if step.get("uses", "").startswith("actions/checkout@")
    )
    assert preparation == checkout + 1
    actions = ["cachix/install-nix-action@"]
    if job_name != "publish":
        actions.append("nix-community/cache-nix-action@")
    for action in actions:
        restore = next(
            index
            for index, step in enumerate(steps)
            if step.get("uses", "").startswith(action)
        )
        assert preparation < restore


@pytest.mark.parametrize("job_name", ["lint", "unit", "package", "publish"])
def test_work_directory_preparation_is_writable_and_preserves_existing_files(
    tmp_path: Path, job_name: str
) -> None:
    preparation = next(
        step
        for step in _steps(_workflow()["jobs"][job_name])
        if step.get("name") == "Prepare runner-owned work directories"
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner_temp = tmp_path / "runner temporary storage"
    runner_temp.mkdir()
    github_env = tmp_path / "github-env"
    github_env.write_text("EXISTING_ENV=preserved\n", encoding="utf-8")
    directories = [
        runner_temp,
        runner_temp / "pre-commit",
        runner_temp / "legacy-windows-ci",
    ]
    exported_environment = (
        f"PRE_COMMIT_HOME={runner_temp / 'pre-commit'}\n"
        f"CI_OUTPUT_DIR={runner_temp / 'legacy-windows-ci'}\n"
    )
    existing_files: list[Path] = []
    for attempt in range(2):
        result = subprocess.run(
            ["bash", "-euo", "pipefail"],
            input=preparation["run"],
            cwd=workspace,
            env=dict(
                os.environ, RUNNER_TEMP=str(runner_temp), GITHUB_ENV=str(github_env)
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert not list(workspace.iterdir())
        assert github_env.read_text(encoding="utf-8") == (
            "EXISTING_ENV=preserved\n" + exported_environment * (attempt + 1)
        )
        for directory in directories:
            assert directory.is_dir()
            assert directory.stat().st_uid == os.geteuid()
            assert directory.stat().st_mode & 0o300 == 0o300
        if attempt == 0:
            existing_files = [directory / "existing-file" for directory in directories]
            for existing_file in existing_files:
                existing_file.write_text("runner-owned content", encoding="utf-8")
        else:
            for existing_file in existing_files:
                assert (
                    existing_file.read_text(encoding="utf-8") == "runner-owned content"
                )


@pytest.mark.parametrize("report_exists", [False, True])
def test_test_report_detection_finds_reports_outside_the_checkout(
    tmp_path: Path, report_exists: bool
) -> None:
    steps = _steps(_workflow()["jobs"]["unit"])
    report_step = next(step for step in steps if step.get("id") == "report")
    assert " ".join(report_step["if"].split()) == "${{ !cancelled() }}"
    test_step = next(
        step
        for step in steps
        if step.get("name") == "Run all unit and controller tests"
    )
    assert steps.index(test_step) < steps.index(report_step)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output_directory = tmp_path / "runner temporary storage" / "legacy-windows-ci"
    output_directory.mkdir(parents=True)
    if report_exists:
        (output_directory / "pytest.xml").write_text("<testsuites />", encoding="utf-8")
    github_output = tmp_path / "github-output"
    github_output.touch()
    result = subprocess.run(
        ["bash", "-euo", "pipefail"],
        input=report_step["run"],
        cwd=workspace,
        env=dict(
            os.environ,
            CI_OUTPUT_DIR=str(output_directory),
            GITHUB_OUTPUT=str(github_output),
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert github_output.read_text(encoding="utf-8") == (
        "available=true\n" if report_exists else ""
    )
    assert not list(workspace.iterdir())


def test_publication_requires_an_origin_tag_push_and_all_checks() -> None:
    publish = _workflow()["jobs"]["publish"]
    assert set(publish["needs"]) == {"lint", "unit", "package"}
    conditions = [" ".join(item.split()) for item in publish["if"].split("&&")]
    assert conditions == [
        "github.repository == 'sustainablelobster/ansible-legacy-windows'",
        "github.event_name == 'push'",
        "(startsWith(github.ref, 'refs/tags/legacy_windows/v') "
        "|| startsWith(github.ref, 'refs/tags/legacy_ad/v') "
        "|| startsWith(github.ref, 'refs/tags/legacy_community_windows/v'))",
        "needs.lint.result == 'success'",
        "needs.unit.result == 'success'",
        "needs.package.result == 'success'",
    ]
    assert publish["concurrency"]["cancel-in-progress"] is False
    assert publish["concurrency"]["queue"] == "max"
    assert "${{ github.sha }}" in publish["concurrency"]["group"]
    assert "github.ref" not in publish["concurrency"]["group"]
    assert _workflow()["concurrency"]["cancel-in-progress"] == (
        "${{ !startsWith(github.ref, 'refs/tags/') }}"
    )


@pytest.mark.parametrize("queue", ["single", "max", "invalid"])
@pytest.mark.parametrize("cancel", [False, True])
def test_locked_workflow_linter_validates_queue_modes_without_ignoring_syntax(
    queue: str, cancel: bool
) -> None:
    workflow = {
        "on": "push",
        "jobs": {
            "release": {
                "runs-on": "ubuntu-24.04",
                "concurrency": {
                    "group": "release",
                    "queue": queue,
                    "cancel-in-progress": cancel,
                },
                "steps": [{"run": "echo release"}],
            }
        },
    }
    result = subprocess.run(
        ["actionlint", "-"],
        input=yaml.safe_dump(workflow),
        capture_output=True,
        text=True,
        check=False,
    )
    accepted = queue in ("single", "max") and not (queue == "max" and cancel)
    assert (result.returncode == 0) == accepted, result.stdout + result.stderr


def test_only_the_publisher_has_write_permissions_or_a_publish_token() -> None:
    workflow = _workflow()
    assert workflow["permissions"] == {"contents": "read"}
    assert "env" not in workflow
    galaxy_steps = []
    for name, job in workflow["jobs"].items():
        assert "env" not in job
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
            if "GALAXY_API_KEY" in environment:
                assert name == "publish"
                assert environment["GALAXY_API_KEY"] == (
                    "${{ secrets.GALAXY_API_KEY }}"
                )
                assert "ci_release.py publish-tagged" in step["run"]
                galaxy_steps.append(step)
    assert len(galaxy_steps) == 1
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert re.findall(r"secrets\.[A-Za-z_]+", source) == ["secrets.GALAXY_API_KEY"]
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
    assert len(uploads) == 4
    assert uploads[0]["with"]["path"] == "${{ env.CI_OUTPUT_DIR }}/pytest.xml"
    assert " ".join(uploads[0]["if"].split()) == (
        "${{ !cancelled() && steps.report.outputs.available == 'true' }}"
    )
    for upload, collection, step in zip(
        uploads[1:],
        ("legacy_windows", "legacy_ad", "legacy_community_windows"),
        ("windows", "ad", "community"),
        strict=True,
    ):
        prefix = (
            "${{ env.PACKAGE_DIR }}/"
            if collection == "legacy_community_windows"
            else "${{ env.CI_OUTPUT_DIR }}/" + collection + "/"
        )
        if collection == "legacy_community_windows":
            assert upload["env"]["PACKAGE_DIR"] == (
                "${{ env.CI_OUTPUT_DIR }}/legacy_community_windows"
            )
        assert upload["with"]["path"].splitlines() == [
            prefix + "${{ env.RELEASE_FILENAME }}",
            prefix + "SHA256SUMS",
            prefix + "release-notes.txt",
            prefix + "release-manifest.json",
        ]
        assert upload["env"]["RELEASE_FILENAME"] == (
            "${{ steps." + step + ".outputs.filename }}"
        )
    for upload in uploads:
        assert upload["with"]["if-no-files-found"] == "error"
        assert upload["with"]["retention-days"] == 30
        assert "${{ github.run_attempt }}" in upload["with"]["name"]
    assert jobs["package"]["outputs"] == {
        "windows-sha256": "${{ steps.windows.outputs.sha256 }}",
        "ad-sha256": "${{ steps.ad.outputs.sha256 }}",
        "community-sha256": "${{ steps.community.outputs.sha256 }}",
        "windows-artifact-id": "${{ steps.upload-windows.outputs.artifact-id }}",
        "ad-artifact-id": "${{ steps.upload-ad.outputs.artifact-id }}",
        "community-artifact-id": "${{ steps.upload-community.outputs.artifact-id }}",
    }
    publisher_steps = _steps(jobs["publish"])
    downloads = [
        step
        for step in publisher_steps
        if step.get("uses", "").startswith("actions/download-artifact@")
    ]
    assert len(downloads) == 3
    for download, collection, output in zip(
        downloads,
        ("legacy_windows", "legacy_ad", "legacy_community_windows"),
        ("windows", "ad", "community"),
        strict=True,
    ):
        assert download["with"] == {
            "artifact-ids": "${{ needs.package.outputs." + output + "-artifact-id }}",
            "path": "${{ env.CI_OUTPUT_DIR }}/" + collection,
            "merge-multiple": True,
            "digest-mismatch": "error",
        }
    publish = next(
        step for step in publisher_steps if "GH_TOKEN" in step.get("env", {})
    )
    assert publish["env"]["WINDOWS_SHA256"] == (
        "${{ needs.package.outputs.windows-sha256 }}"
    )
    assert publish["env"]["AD_SHA256"] == ("${{ needs.package.outputs.ad-sha256 }}")
    assert publish["env"]["COMMUNITY_SHA256"] == (
        "${{ needs.package.outputs.community-sha256 }}"
    )
    assert "GITHUB_REF_NAME" not in publish["env"]
    assert "GITHUB_SHA" not in publish["env"]
    assert not any(step.get("id") == "selected" for step in publisher_steps)
    assert "just build" not in publish["run"]


@pytest.mark.parametrize("token", ["", " \t\n", "private-test-token"])
def test_publish_step_requires_secret_and_passes_all_exact_candidates(
    tmp_path: Path, token: str
) -> None:
    step = next(
        item
        for item in _steps(_workflow()["jobs"]["publish"])
        if "GALAXY_API_KEY" in item.get("env", {})
    )
    command_log = tmp_path / "commands.jsonl"
    nix = tmp_path / "nix"
    nix.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "args = sys.argv[sys.argv.index('--command') + 1:]\n"
        "with open(os.environ['CI_COMMAND_LOG'], 'a') as output:\n"
        "    output.write(json.dumps(args) + '\\n')\n",
        encoding="utf-8",
    )
    nix.chmod(0o700)
    output_directory = tmp_path / "runner temporary storage"
    windows_digest = "a" * 64
    ad_digest = "b" * 64
    community_digest = "c" * 64
    result = subprocess.run(
        ["bash", "-euo", "pipefail"],
        input=step["run"],
        cwd=tmp_path,
        env=dict(
            os.environ,
            PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
            CI_COMMAND_LOG=str(command_log),
            CI_OUTPUT_DIR=str(output_directory),
            WINDOWS_SHA256=windows_digest,
            AD_SHA256=ad_digest,
            COMMUNITY_SHA256=community_digest,
            GALAXY_API_KEY=token,
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    if not token.strip():
        assert result.returncode != 0
        assert "GALAXY_API_KEY repository secret" in result.stderr
        assert not command_log.exists()
        return
    assert result.returncode == 0, result.stderr
    assert [json.loads(line) for line in command_log.read_text().splitlines()] == [
        [
            "python",
            "scripts/ci_release.py",
            "publish-tagged",
            "--windows-package-dir",
            str(output_directory / "legacy_windows"),
            "--windows-sha256",
            windows_digest,
            "--ad-package-dir",
            str(output_directory / "legacy_ad"),
            "--ad-sha256",
            ad_digest,
            "--community-package-dir",
            str(output_directory / "legacy_community_windows"),
            "--community-sha256",
            community_digest,
        ]
    ]
    assert token not in command_log.read_text() + result.stdout + result.stderr


@pytest.mark.parametrize(
    "collection", ["legacy_windows", "legacy_ad", "legacy_community_windows"]
)
@pytest.mark.parametrize("count", [0, 2])
def test_package_step_rejects_missing_or_ambiguous_archives(
    tmp_path: Path, collection: str, count: int
) -> None:
    (tmp_path / "dist").mkdir()
    for other in ("legacy_windows", "legacy_ad", "legacy_community_windows"):
        if other != collection:
            (tmp_path / "dist" / f"sustainablelobster-{other}-1.0.0.tar.gz").touch()
    for index in range(count):
        (tmp_path / "dist" / f"sustainablelobster-{collection}-{index}.tar.gz").touch()
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
    assert "Expected exactly one archive for each collection." in result.stderr


def test_package_step_checks_the_same_archive_before_preparing_a_release(
    tmp_path: Path,
) -> None:
    (tmp_path / "dist").mkdir()
    archive = "dist/sustainablelobster-legacy_windows-1.0.0.tar.gz"
    (tmp_path / archive).touch()
    ad_archive = "dist/sustainablelobster-legacy_ad-1.0.0.tar.gz"
    (tmp_path / ad_archive).touch()
    community_archive = "dist/sustainablelobster-legacy_community_windows-1.0.0.tar.gz"
    (tmp_path / community_archive).touch()
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
    output_directory = tmp_path.parent / (tmp_path.name + "-ci-output")
    result = _run_package_step(
        tmp_path,
        CI_OUTPUT_DIR=str(output_directory),
        CI_COMMAND_LOG=str(command_log),
    )
    assert result.returncode == 0, result.stderr
    assert [json.loads(line) for line in command_log.read_text().splitlines()] == [
        ["just", "build"],
        [
            "python",
            "scripts/check_collection.py",
            "--artifact",
            archive,
            "--artifact",
            ad_archive,
            "--artifact",
            community_archive,
        ],
    ]
    assert (tmp_path / "github-output").read_text() == (
        f"windows-archive={archive}\nad-archive={ad_archive}\n"
        f"community-archive={community_archive}\n"
    )


@pytest.mark.parametrize(
    "collection,step_id",
    [
        ("legacy_windows", "windows"),
        ("legacy_ad", "ad"),
        ("legacy_community_windows", "community"),
    ],
)
@pytest.mark.parametrize(
    "context",
    [
        ("push", "branch", "main"),
        ("push", "tag", "legacy_windows/v1.0.0"),
        ("push", "tag", "v1.0.0"),
        ("push", "tag", "legacy_ad/v1.0.0"),
        ("push", "tag", "legacy_community_windows/v1.0.0"),
        ("workflow_dispatch", "tag", "legacy_windows/v1.0.0"),
        ("pull_request", "branch", "example"),
        ("push", "tag", "legacy_windows/v1.0.0; touch escaped"),
    ],
)
def test_each_candidate_preparation_receives_only_its_own_tag(
    tmp_path: Path,
    collection: str,
    step_id: str,
    context: tuple[str, str, str],
) -> None:
    event, ref_type, ref_name = context
    step = next(
        item
        for item in _steps(_workflow()["jobs"]["package"])
        if item.get("id") == step_id
    )
    command_log = tmp_path / "commands.jsonl"
    nix = tmp_path / "nix"
    nix.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "args = sys.argv[sys.argv.index('--command') + 1:]\n"
        "with open(os.environ['CI_COMMAND_LOG'], 'a') as output:\n"
        "    output.write(json.dumps(args) + '\\n')\n",
        encoding="utf-8",
    )
    nix.chmod(0o700)
    archive = f"dist/sustainablelobster-{collection}-1.0.0.tar.gz"
    output_directory = tmp_path / "runner temporary storage"
    result = subprocess.run(
        ["bash", "-euo", "pipefail"],
        input=step["run"],
        cwd=tmp_path,
        env=dict(
            os.environ,
            PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
            CI_COMMAND_LOG=str(command_log),
            CI_OUTPUT_DIR=str(output_directory),
            ARCHIVE=archive,
            GITHUB_EVENT_NAME=event,
            GITHUB_REF_TYPE=ref_type,
            GITHUB_REF_NAME=ref_name,
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    prefix = collection + "/v"
    tag_args = (
        ["--tag", ref_name]
        if event == "push" and ref_type == "tag" and ref_name.startswith(prefix)
        else []
    )
    assert [json.loads(line) for line in command_log.read_text().splitlines()] == [
        [
            "python",
            "scripts/ci_release.py",
            "package",
            "--collection",
            collection,
            "--artifact",
            archive,
            "--output-dir",
            str(output_directory / collection),
            *tag_args,
        ]
    ]
    assert not (tmp_path / "escaped").exists()
