"""Protect the real-servicing fixture's input checks and owned cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# PyYAML is provided by the pinned developer environment without typing stubs.
import yaml  # type: ignore[import-untyped]
from jinja2.nativetypes import NativeEnvironment

SOURCE = (
    Path(__file__).resolve().parents[2]
    / "tests/integration/fixtures/hotfix_lifecycle.py"
)


def test_prerequisite_repeat_cannot_erase_its_installation_restart() -> None:
    play = yaml.safe_load(
        SOURCE.parent.parent.joinpath("win_hotfix_legacy.yml").read_text(
            encoding="utf-8"
        )
    )[0]
    tasks = next(task["block"] for task in play["tasks"] if "block" in task)
    restart = next(
        task
        for task in tasks
        if "hotfix_legacy_prerequisite_restart" == task.get("register")
    )
    # Jinja's template stub says str even for this native-value environment.
    template: Any = NativeEnvironment().from_string("{{ " + restart["when"] + " }}")
    assert (
        template.render(
            hotfix_legacy_prerequisite_install={"reboot_required": True},
            hotfix_legacy_prerequisite_repeat={"reboot_required": False},
        )
        is True
    )
    assert (
        template.render(
            hotfix_legacy_prerequisite_install={"reboot_required": False},
            hotfix_legacy_prerequisite_repeat={"reboot_required": False},
        )
        is False
    )


def test_repeat_cannot_erase_an_actual_pending_servicing_restart() -> None:
    tasks = yaml.safe_load(
        SOURCE.parent.parent.joinpath("tasks/win_hotfix_lifecycle_case.yml").read_text(
            encoding="utf-8"
        )
    )
    facts = [
        task["ansible.builtin.set_fact"]
        for task in tasks
        if "ansible.builtin.set_fact" in task
    ]
    expression = next(
        fact["hotfix_lifecycle_restart_required"]
        for fact in facts
        if "hotfix_lifecycle_restart_required" in fact
    )
    # Jinja's template stub says str even for this native-value environment.
    template: Any = NativeEnvironment().from_string(expression)
    assert (
        template.render(
            hotfix_lifecycle_restart_required=False,
            hotfix_lifecycle_result={"reboot_required": True},
        )
        is True
    )
    assert (
        template.render(
            hotfix_lifecycle_restart_required=True,
            hotfix_lifecycle_result={"reboot_required": False},
        )
        is True
    )
    assert (
        template.render(
            hotfix_lifecycle_restart_required=False,
            hotfix_lifecycle_result={"reboot_required": False},
        )
        is False
    )
    restart = tasks[-1]
    assert "hotfix_lifecycle_restart_required" in restart["when"]
    assert (
        restart["block"][-1]["ansible.builtin.set_fact"][
            "hotfix_lifecycle_restart_required"
        ]
        is False
    )


@pytest.fixture(name="fixture")
def lifecycle_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load target fixture functions without Windows or lab connections.

    :param tmp_path: Temporary owned test files.
    :param monkeypatch: Scoped native imports and target prerequisites.
    :returns: Fixture namespace and native input-inspection stand-ins.
    """
    modules: dict[str, Any] = {}
    for name in ("winreg", "legacy_windows_hotfix", "legacy_windows_package_signature"):
        modules[name] = ModuleType(name)
        monkeypatch.setitem(__import__("sys").modules, name, modules[name])
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    text = SOURCE.read_text(encoding="utf-8").replace(
        "assert sys.version_info[:3] == (3, 4, 4)\n", ""
    )
    namespace: dict[str, Any] = {"__name__": "hotfix_lifecycle_fixture"}
    exec(compile(text, str(SOURCE), "exec"), namespace)  # pylint: disable=exec-used
    directory = tmp_path / "expanded"
    directory.mkdir()
    source = directory / "package.cab"
    source.write_bytes(b"official")
    mum = tmp_path / "servicing/Packages/package.mum"
    mum.parent.mkdir(parents=True)
    mum.write_text(
        '<assembly><package identifier="KB42"/></assembly>', encoding="utf-8"
    )
    expansion = Mock()
    expansion.__enter__ = Mock(return_value=str(directory))
    expansion.__exit__ = Mock(return_value=False)
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    modules["legacy_windows_hotfix"].ExpandedMsu = Mock(return_value=expansion)
    modules["legacy_windows_hotfix"].HotfixSession = Mock(return_value=session)
    metadata = [
        {"name": "package", "kb": "KB42", "state": "Installed", "path": str(source)}
    ]
    modules["legacy_windows_hotfix"].metadata_from_file = Mock(return_value=metadata)
    modules["legacy_windows_package_signature"].status = Mock(return_value="Valid")
    namespace["_file_record"] = lambda _path: {
        "sha256": "official",
        "attributes": 32,
        "mtime": 42.5,
    }
    namespace["_observe"] = lambda _identifier: {"complete": "provider baseline"}

    def expanded_catalog(_source: str, folder: str, pattern: str) -> None:
        Path(folder).mkdir()
        if pattern == "*.cat":
            Path(folder, "update.cat").write_bytes(b"signed")
        else:
            assert pattern == "update.mum"
            Path(folder, "update.mum").write_text(
                '<assembly><package identifier="KB42"/></assembly>', encoding="utf-8"
            )

    namespace["_expand_selected"] = expanded_catalog
    return SimpleNamespace(
        namespace=namespace,
        modules=modules,
        metadata=metadata,
        expansion=expansion,
        mum=mum,
        root=tmp_path,
    )


def test_catalog_signature_and_exact_input_are_verified_before_servicing(
    fixture: Any,
) -> None:
    result = fixture.namespace["_inspect_source"](
        "download.msu", "package", "KB42", "official"
    )
    assert result["metadata"][0]["path"] == "package.cab"
    assert result["catalogs"][0]["signature"] == "Valid"
    assert result["state"] == {"complete": "provider baseline"}
    fixture.expansion.__exit__.assert_called_once()


def test_genuinely_absent_package_uses_its_actual_cab_manifest(fixture: Any) -> None:
    fixture.mum.unlink()
    result = fixture.namespace["_inspect_source"](
        "download.msu", "package", "KB42", "official"
    )
    assert result["installed_mum"] is None
    assert result["source_mum"]["sha256"] == "official"
    assert result["declarations"] == [{"identifier": "KB42"}]
    fixture.expansion.__exit__.assert_called_once()


@pytest.mark.parametrize("field,value", [("name", "other"), ("kb", "KB999")])
def test_wrong_package_identity_is_rejected_without_catalog_or_servicing(
    fixture: Any, field: str, value: str
) -> None:
    fixture.metadata[0][field] = value
    with pytest.raises(AssertionError):
        fixture.namespace["_inspect_source"](
            "download.msu", "package", "KB42", "official"
        )
    fixture.modules["legacy_windows_package_signature"].status.assert_not_called()
    fixture.expansion.__exit__.assert_called_once()


def test_changed_official_input_is_rejected_before_expansion(fixture: Any) -> None:
    with pytest.raises(AssertionError):
        fixture.namespace["_inspect_source"](
            "download.msu", "package", "KB42", "changed"
        )
    fixture.modules["legacy_windows_hotfix"].ExpandedMsu.assert_not_called()


@pytest.mark.parametrize(
    "status", ["NotSigned", "HashMismatch", "NotTrusted", "UnknownError"]
)
def test_untrusted_package_catalog_cannot_enter_the_servicing_fixture(
    fixture: Any, status: str
) -> None:
    fixture.modules["legacy_windows_package_signature"].status.return_value = status
    with pytest.raises(AssertionError):
        fixture.namespace["_inspect_source"](
            "download.msu", "package", "KB42", "official"
        )
    fixture.expansion.__exit__.assert_called_once()


def test_permanent_package_is_not_accepted_for_removal_preparation(
    fixture: Any,
) -> None:
    fixture.mum.write_text(
        '<assembly><package permanence="permanent"/></assembly>', encoding="utf-8"
    )
    with pytest.raises(AssertionError):
        fixture.namespace["_inspect_source"](
            "download.msu", "package", "KB42", "official"
        )


def test_permanent_package_can_be_inspected_for_installation_only(fixture: Any) -> None:
    fixture.mum.write_text(
        '<assembly><package permanence="permanent"/></assembly>', encoding="utf-8"
    )
    result = fixture.namespace["_inspect_source"](
        "download.msu", "package", "KB42", "official", removal=False
    )
    assert result["declarations"] == [{"permanence": "permanent"}]


def test_owned_cleanup_rejects_unknown_paths(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(fixture.root))
    folder = fixture.root / "unrelated"
    folder.mkdir()
    with pytest.raises(AssertionError):
        fixture.namespace["_remove_workspace"](str(folder))
    assert folder.exists()


def test_owned_cleanup_removes_only_the_validated_workspace(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(fixture.root))
    folder = fixture.root / "legacy-windows-hotfix-lifecycle-owned"
    folder.mkdir()
    assert fixture.namespace["_remove_workspace"](str(folder)) == {
        "workspace_absent": True
    }
    assert not folder.exists()


def test_retained_input_time_is_only_applied_to_the_owned_exact_download(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    folder = fixture.root / "legacy-windows-hotfix-lifecycle-input"
    folder.mkdir()
    source = folder / "package.msu"
    source.write_bytes(b"official")
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(fixture.root))
    monkeypatch.setattr(
        "sys.argv",
        ["fixture", "match-source-time", "package", str(source), "official", "42.5"],
    )
    fixture.namespace["_file_record"] = lambda path: {
        "sha256": "official",
        "mtime": Path(path).stat().st_mtime,
    }
    fixture.namespace["_main"]()
    assert source.stat().st_mtime == 42.5
    assert source.read_bytes() == b"official"
    assert '"mtime": 42.5' in capsys.readouterr().out


def test_matching_hash_does_not_authorize_changing_an_unowned_input_time(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = fixture.root / "package.msu"
    source.write_bytes(b"official")
    original = source.stat().st_mtime
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(fixture.root))
    monkeypatch.setattr(
        "sys.argv",
        ["fixture", "match-source-time", "package", str(source), "official", "42.5"],
    )
    with pytest.raises(AssertionError):
        fixture.namespace["_main"]()
    assert source.stat().st_mtime == original


@pytest.mark.parametrize(
    "name", ["unrelated", "package.msu", "legacy-windows-hotfix-other"]
)
def test_reference_host_paths_require_the_specific_owned_workspace(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(fixture.root))
    with pytest.raises(AssertionError):
        fixture.namespace["_holder_path"](str(fixture.root / name), "identity.json")


def test_reference_host_records_native_birth_and_loaded_clr_files(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = fixture.root / "legacy-windows-hotfix-lifecycle-reference"
    folder.mkdir()
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(fixture.root))
    identity = {"pid": 123, "created": 456, "alive": True}
    fixture.namespace["_holder_process"] = Mock(return_value=identity)

    def _launch(arguments: list[str], **options: Any) -> Any:
        assert options["close_fds"] is True
        assert not {"stdin", "stdout", "stderr"}.intersection(options)
        assert options["creationflags"] == 0x09000200
        Path(arguments[-3]).write_text(
            json.dumps(
                {
                    "pid": 123,
                    "created": 456,
                    "modules": [{"path": "clr.dll", "version": "4.8.9347.0"}],
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(pid=123)

    monkeypatch.setattr(fixture.namespace["subprocess"], "Popen", _launch)
    result = fixture.namespace["_holder_start"](str(folder))
    assert result["native_identity"] == identity
    assert result["reference_host"]["modules"][0]["file"]["sha256"] == "official"
    assert json.loads((folder / "reference-host-identity.json").read_text()) == identity
    script = (folder / "reference-host-holder.ps1").read_text(encoding="utf-8-sig")
    assert "clr.dll" in script and "ToFileTimeUtc" in script


def test_reference_host_release_waits_for_the_exact_birth_to_exit(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = fixture.root / "legacy-windows-hotfix-lifecycle-reference"
    folder.mkdir()
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(fixture.root))
    identity = {"pid": 123, "created": 456, "alive": True}
    (folder / "reference-host-identity.json").write_text(json.dumps(identity))
    (folder / "reference-host-output.log").write_bytes(
        b"preserved reference host output"
    )
    exited = dict(identity, alive=False)
    fixture.namespace["_holder_process"] = Mock(side_effect=[identity, exited])
    monkeypatch.setattr(fixture.namespace["time"], "sleep", lambda _: None)
    result = fixture.namespace["_holder_stop"](str(folder))
    assert result["owned_reference_host_closed"] is True
    assert result["final"] == exited
    assert result["reference_host_output"] == "preserved reference host output"
    assert (folder / "reference-host-release").is_file()
    fixture.namespace["_holder_process"] = Mock(return_value=exited)
    assert fixture.namespace["_holder_stop"](str(folder))["owned_reference_host_closed"]


def test_reference_host_release_rejects_pid_reuse_without_touching_the_child(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = fixture.root / "legacy-windows-hotfix-lifecycle-reference"
    folder.mkdir()
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(fixture.root))
    identity = {"pid": 123, "created": 456, "alive": True}
    (folder / "reference-host-identity.json").write_text(json.dumps(identity))
    fixture.namespace["_holder_process"] = Mock(
        return_value=dict(identity, created=999)
    )
    with pytest.raises(AssertionError):
        fixture.namespace["_holder_stop"](str(folder))
    assert not (folder / "reference-host-release").exists()


def test_native_image_proof_uses_the_production_owner_and_never_executes_clr(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    image = {"path": "existing-clr.dll", "handle": 0x10002}

    @contextmanager
    def mapped_image() -> Any:
        """Retain the owner until the proof scope exits.

        :returns: The live resource image identity for the context body.
        """
        events.append("mapped")
        try:
            yield image
        finally:
            events.append("closed")

    # The fixture intentionally exercises this private production owner.
    # pylint: disable-next=protected-access
    fixture.modules["legacy_windows_hotfix"]._reference_file_use = mapped_image
    api = SimpleNamespace(GetModuleHandleW=Mock(return_value=None))
    monkeypatch.setattr(
        fixture.namespace["ctypes"], "WinDLL", Mock(return_value=api), raising=False
    )
    proof = fixture.namespace["_native_image_proof"]()
    assert proof["image"] == image
    assert proof["executable_clr_modules"] == [None, None, None]
    assert proof["resource_image_verified"] is True
    assert proof["native_scope_closed"] is True
    assert events == ["mapped", "closed"]
    assert api.GetModuleHandleW.call_args_list == [(("clr.dll",),)] * 3


@pytest.mark.parametrize("executable,image", [(123, 0x10002), (None, 0x10000)])
def test_native_image_proof_rejects_runtime_execution_or_unverified_image_handle(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    executable: Any,
    image: int,
) -> None:
    owner = Mock()
    owner.__enter__ = Mock(return_value={"path": "clr.dll", "handle": image})
    owner.__exit__ = Mock(return_value=False)
    # The fixture intentionally exercises this private production owner.
    # pylint: disable-next=protected-access
    fixture.modules["legacy_windows_hotfix"]._reference_file_use = Mock(
        return_value=owner
    )
    api = SimpleNamespace(GetModuleHandleW=Mock(return_value=executable))
    monkeypatch.setattr(
        fixture.namespace["ctypes"], "WinDLL", Mock(return_value=api), raising=False
    )
    with pytest.raises(AssertionError):
        fixture.namespace["_native_image_proof"]()
    assert owner.__exit__.call_count == (0 if executable else 1)
