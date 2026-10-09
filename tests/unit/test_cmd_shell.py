"""Exercise generated housekeeping on development Python, not on Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import ctypes
import ntpath
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

# Ansible's public exception type has no distributed typing metadata.
from ansible.errors import AnsibleError  # type: ignore[import-untyped]

# Pylint cannot resolve this source-only collection namespace in its hook process.
from plugins.shell.cmd import ShellModule  # pylint: disable=import-error


@pytest.fixture(name="shell")
def configured_shell(monkeypatch: pytest.MonkeyPatch) -> ShellModule:
    """Configure the plugin without requiring an installed collection.

    :param monkeypatch: Pytest's scoped patch facility.
    :returns: A shell using an explicit Windows interpreter path.
    """
    plugin = ShellModule()
    options = {"python_interpreter": r"C:\Python34\python.exe", "remote_tmp": "%TEMP%"}
    monkeypatch.setattr(plugin, "get_option", options.__getitem__)
    return plugin


@pytest.fixture(name="native_cleanup", autouse=True)
def native_cleanup_calls(monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Substitute Windows attributes and link deletion on the developer host.

    :param monkeypatch: Scoped native API and directory-removal replacements.
    :returns: Controllable native attribute lookup and last-error state.
    """
    native = Mock()
    native.error = 2

    def _attributes(path: str) -> int:
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            return 0xFFFFFFFF
        value = 0x400 if stat.S_ISLNK(mode) else 0
        if stat.S_ISDIR(mode) or (stat.S_ISLNK(mode) and os.path.isdir(path)):
            value |= 0x10
        return value

    native.GetFileAttributesW.side_effect = _attributes
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=native), raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: native.error, raising=False)
    monkeypatch.setattr(
        ctypes, "WinError", lambda code: OSError(code, "native failure"), raising=False
    )
    rmdir = os.rmdir

    def _remove_directory(path: str) -> None:
        # Windows rmdir removes a directory link; POSIX requires unlink instead.
        if os.path.islink(path):
            os.unlink(path)
        else:
            rmdir(path)

    monkeypatch.setattr(os, "rmdir", _remove_directory)
    return native


def _source(command: str) -> str:
    match = re.search(r"b64decode\^\('([A-Za-z0-9+/=]+)'", command)
    assert match is not None, command
    source = base64.b64decode(match.group(1)).decode("utf-8")
    ast.parse(source, feature_version=(3, 4))
    return source


def _run_python(
    command: str, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-c", _source(command)],
        env=environment,
        check=False,
        capture_output=True,
    )


def _remove(shell: ShellModule, path: Path | str, recurse: bool = False) -> None:
    # Executing the generated source is the behavior under test, with native mocks.
    exec(_source(shell.remove(str(path), recurse)), {})  # pylint: disable=exec-used


def test_windows_paths_and_python_extension(shell: ShellModule) -> None:
    assert shell.join_path("C:/Users/Test User", "module.py") == (
        r"C:\Users\Test User\module.py"
    )
    assert shell.join_path(r"C:\Temp", "").endswith("\\")
    assert shell.get_remote_filename("/controller/modules/win_ping.py") == "win_ping.py"
    assert shell.get_remote_filename(r"C:\Temp\win_ping.py") == "win_ping.py"
    assert shell.path_has_trailing_slash("C:/Temp/")
    assert shell.path_has_trailing_slash("C:\\Temp\\")
    assert not shell.path_has_trailing_slash(r"C:\Temp\win_ping.py")


@pytest.mark.parametrize(
    "interpreter", [r"C:\Python34\python.exe", r"C:\Program Files\Python313\python.exe"]
)
def test_housekeeping_accepts_minimum_and_newer_interpreter_paths(
    shell: ShellModule, monkeypatch: pytest.MonkeyPatch, interpreter: str
) -> None:
    options = {"python_interpreter": interpreter, "remote_tmp": "%TEMP%"}
    monkeypatch.setattr(shell, "get_option", options.__getitem__)
    command = shell.exists(r"C:\Temp\module.py")
    executable = shell.join([interpreter])
    if executable.startswith('"'):
        assert command.startswith("(" + executable + " -c ")
        assert command.endswith(")")
    else:
        assert command.startswith(executable + " -c ")
    assert _source(command) == (
        "import os, sys\nsys.exit(0 if os.path.exists('C:\\\\Temp\\\\module.py') else 1)\n"
    )


def test_module_command_preserves_paths_with_spaces_and_metacharacters(
    shell: ShellModule,
) -> None:
    command = shell.build_module_command(
        "",
        r"#!C:\Program Files\Python34\python.exe",
        r"C:\Users\André & Co\win_ping.py",
        arg_path=r"C:\Users\André & Co\args",
    )
    assert command == (
        '("C:\\Program Files\\Python34\\python.exe" '
        '^"C:\\Users\\André ^& Co\\win_ping.py^" '
        '^"C:\\Users\\André ^& Co\\args^"'
        ")"
    )


@pytest.mark.parametrize(
    "command,expected",
    [
        (
            '"C:\\Program Files\\Python34\\python.exe" module.py',
            '("C:\\Program Files\\Python34\\python.exe" module.py)',
        ),
        (
            '("C:\\Program Files\\Python34\\python.exe" module.py)',
            '("C:\\Program Files\\Python34\\python.exe" module.py)',
        ),
        (r"C:\Python34\python.exe module.py", r"C:\Python34\python.exe module.py"),
        ("", ""),
    ],
)
def test_complete_execution_preparation_only_groups_leading_quoted_commands(
    shell: ShellModule, command: str, expected: str
) -> None:
    assert shell.prepare_command(command) == expected
    assert shell.prepare_command(expected) == expected


def test_grouping_does_not_change_literal_join_or_environment_child_argv(
    shell: ShellModule, monkeypatch: pytest.MonkeyPatch
) -> None:
    interpreter = r"C:\Program Files\Python34\python.exe"
    monkeypatch.setattr(shell, "get_option", lambda _name: interpreter)
    arguments = [interpreter, r"C:\Temp\owned & module.py", r"%TEMP%\literal"]
    joined = shell.join(arguments)
    assert joined == (
        '"C:\\Program Files\\Python34\\python.exe" '
        '^"C:\\Temp\\owned ^& module.py^" ^"^%TEMP^%\\literal^"'
    )
    prefix = shell.env_prefix(LEGACY_WINDOWS_LITERAL='value & %PATH% !name! "λ"')
    assert prefix.startswith('"C:\\Program Files\\Python34\\python.exe" -c ')
    assert not prefix.startswith("(")
    complete = shell.build_module_command(
        prefix, "#!" + interpreter, arguments[1], arguments[2]
    )
    assert complete == "(" + prefix + " " + joined + ")"
    assert "subprocess.call(sys.argv[1:], env=environment)" in _source(prefix)


@pytest.mark.parametrize(
    "interpreter", [r"C:\Python34\python.exe", r"C:\A B\python.exe"]
)
def test_complete_module_command_uses_only_one_command_group(
    shell: ShellModule, interpreter: str
) -> None:
    command = shell.build_module_command("", "#!" + interpreter, r"C:\Temp\module.py")
    literal = shell.join([interpreter, r"C:\Temp\module.py"])
    expected = "(" + literal + ")" if literal.startswith('"') else literal
    assert command == expected
    assert shell.join(iter(["python.exe", "", "%TEMP%", "!value!"])) == (
        'python.exe "" ^"^%TEMP^%^" ^"^!value^!^"'
    )


def test_temporary_directory_lifecycle_and_scoped_removal(
    shell: ShellModule, tmp_path: Path
) -> None:
    parent = tmp_path / "répertoire & %NAME%!"
    task_path = parent / "ansible-tmp-test"
    create = shell.mkdtemp(basefile=task_path.name, tmpdir=str(parent))
    result = _run_python(create)
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode("utf-8").rstrip("\n") == str(task_path)
    assert task_path.is_dir()
    assert _run_python(create).returncode != 0
    assert _run_python(shell.exists(str(task_path))).returncode == 0

    sibling = parent / "preserved.txt"
    sibling.write_text("preserve", encoding="utf-8")
    (task_path / "args").write_text("{}", encoding="utf-8")
    with pytest.raises(OSError):
        _remove(shell, task_path)
    _remove(shell, task_path, recurse=True)
    assert not task_path.exists()
    assert sibling.read_text(encoding="utf-8") == "preserve"
    _remove(shell, task_path, recurse=True)
    assert _run_python(shell.exists(str(task_path))).returncode == 1


@pytest.mark.parametrize(
    "case",
    [
        (False, False, True),
        (False, True, True),
        (True, False, False),
        (True, False, True),
        (True, True, False),
        (True, True, True),
    ],
)
def test_directory_reparse_cleanup_never_lists_its_target(
    shell: ShellModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_cleanup: Mock,
    case: tuple[bool, bool, bool],
) -> None:
    root_link, broken, recurse = case
    outside = tmp_path / "outside"
    if not broken:
        outside.mkdir()
        (outside / "preserved.txt").write_text("preserve", encoding="utf-8")
    task = tmp_path / "task"
    if not root_link:
        task.mkdir()
        (task / "ordinary.txt").write_text("owned", encoding="utf-8")
    link = task if root_link else task / "junction"
    link.symlink_to(outside, target_is_directory=True)
    get_attributes = native_cleanup.GetFileAttributesW.side_effect
    native_cleanup.GetFileAttributesW.side_effect = lambda path: (
        0x410 if path == str(link) else get_attributes(path)
    )
    list_directory = os.listdir

    def _list_owned_directory(path: str) -> list[str]:
        assert path not in (str(link), str(outside))
        return list_directory(path)

    listing = Mock(side_effect=_list_owned_directory)
    monkeypatch.setattr(os, "listdir", listing)
    _remove(shell, task, recurse)
    assert not os.path.lexists(task)
    assert not os.path.lexists(link)
    if not broken:
        assert (outside / "preserved.txt").read_text(encoding="utf-8") == "preserve"
    if root_link:
        listing.assert_not_called()


@pytest.mark.parametrize("broken", [False, True])
@pytest.mark.parametrize("recurse", [False, True])
def test_file_links_are_removed_without_touching_their_targets(
    shell: ShellModule, tmp_path: Path, broken: bool, recurse: bool
) -> None:
    target = tmp_path / "outside.txt"
    if not broken:
        target.write_text("preserve", encoding="utf-8")
    link = tmp_path / "file-link"
    link.symlink_to(target)
    _remove(shell, link, recurse)
    assert not os.path.lexists(link)
    if not broken:
        assert target.read_text(encoding="utf-8") == "preserve"


@pytest.mark.parametrize("path", ["C:\\owned\\junction\\", "C:\\owned\\junction/"])
def test_root_reparse_trailing_separators_are_normalized_before_inspection(
    shell: ShellModule,
    monkeypatch: pytest.MonkeyPatch,
    native_cleanup: Mock,
    path: str,
) -> None:
    native_cleanup.GetFileAttributesW.side_effect = None
    native_cleanup.GetFileAttributesW.return_value = 0x410
    # Generated code uses Windows os.path on targets; emulate only that boundary.
    monkeypatch.setattr(os.path, "normpath", ntpath.normpath)
    listing = Mock()
    removal = Mock()
    monkeypatch.setattr(os, "listdir", listing)
    monkeypatch.setattr(os, "rmdir", removal)
    _remove(shell, path, recurse=True)
    native_cleanup.GetFileAttributesW.assert_called_once_with(r"C:\owned\junction")
    removal.assert_called_once_with(r"C:\owned\junction")
    listing.assert_not_called()


def test_empty_cleanup_path_does_not_become_the_working_directory(
    shell: ShellModule, native_cleanup: Mock
) -> None:
    _remove(shell, "", recurse=True)
    native_cleanup.GetFileAttributesW.assert_not_called()


@pytest.mark.parametrize("directory", [False, True])
def test_nonrecursive_cleanup_removes_ordinary_files_and_empty_directories(
    shell: ShellModule, tmp_path: Path, directory: bool
) -> None:
    target = tmp_path / "owned"
    if directory:
        target.mkdir()
    else:
        target.write_bytes(b"data")
    _remove(shell, target)
    assert not target.exists()


def test_recursive_cleanup_removes_nested_ordinary_directories(
    shell: ShellModule, tmp_path: Path
) -> None:
    task = tmp_path / "task"
    nested = task / "nested" / "deeper"
    nested.mkdir(parents=True)
    (nested / "payload.py").write_bytes(b"data")
    _remove(shell, task, recurse=True)
    assert not task.exists()


@pytest.mark.parametrize("code", [2, 3])
def test_native_missing_errors_are_tolerated(
    shell: ShellModule, tmp_path: Path, native_cleanup: Mock, code: int
) -> None:
    native_cleanup.GetFileAttributesW.side_effect = None
    native_cleanup.GetFileAttributesW.return_value = 0xFFFFFFFF
    native_cleanup.error = code
    _remove(shell, tmp_path / "missing", recurse=True)


@pytest.mark.parametrize("code", [5, 32])
def test_native_attribute_failures_are_not_treated_as_absence(
    shell: ShellModule, tmp_path: Path, native_cleanup: Mock, code: int
) -> None:
    native_cleanup.GetFileAttributesW.side_effect = None
    native_cleanup.GetFileAttributesW.return_value = 0xFFFFFFFF
    native_cleanup.error = code
    with pytest.raises(OSError) as error:
        _remove(shell, tmp_path / "unreadable", recurse=True)
    assert error.value.errno == code


@pytest.mark.parametrize("operation", ["listdir", "rmdir", "remove"])
def test_filesystem_access_errors_propagate(
    shell: ShellModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    target = tmp_path / "owned"
    if operation == "remove":
        target.write_bytes(b"data")
    else:
        target.mkdir()
    monkeypatch.setattr(os, operation, Mock(side_effect=PermissionError("denied")))
    with pytest.raises(PermissionError, match="denied"):
        _remove(shell, target, recurse=operation != "rmdir")
    assert target.exists()


@pytest.mark.parametrize("operation", ["listdir", "rmdir", "remove"])
def test_disappearance_after_attribute_read_is_tolerated(
    shell: ShellModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    target = tmp_path / "owned"
    if operation == "remove":
        target.write_bytes(b"data")
    else:
        target.mkdir()
    monkeypatch.setattr(os, operation, Mock(side_effect=FileNotFoundError("gone")))
    _remove(shell, target, recurse=operation != "rmdir")


def test_target_environment_expansion(shell: ShellModule, tmp_path: Path) -> None:
    environment = {**os.environ, "LEGACY_WINDOWS_TEST_TMP": str(tmp_path)}
    command = shell.mkdtemp(basefile="test-task", tmpdir="$LEGACY_WINDOWS_TEST_TMP")
    result = _run_python(command, environment)
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode("utf-8").strip() == str(tmp_path / "test-task")
    result = _run_python(shell.expand_user("$LEGACY_WINDOWS_TEST_TMP"), environment)
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode("utf-8").strip() == str(tmp_path)
    result = _run_python(shell.pwd())
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode("utf-8").strip() == os.getcwd()


def test_relative_temporary_parent_fails_before_creation(shell: ShellModule) -> None:
    result = _run_python(shell.mkdtemp(basefile="job", tmpdir="relative"))
    assert result.returncode != 0
    assert b"ansible_remote_tmp must resolve to an absolute path" in result.stderr


@pytest.mark.parametrize(
    "interpreter",
    ["auto", "auto_silent", "python.exe", r"\python.exe", '"C:\\python.exe"'],
)
def test_housekeeping_requires_an_explicit_interpreter(
    shell: ShellModule, monkeypatch: pytest.MonkeyPatch, interpreter: str
) -> None:
    monkeypatch.setattr(shell, "get_option", lambda _name: interpreter)
    with pytest.raises(AnsibleError, match="ansible_python_interpreter"):
        shell.pwd()


def test_unsupported_options_fail_clearly(shell: ShellModule) -> None:
    assert shell.env_prefix() == ""
    with pytest.raises(AnsibleError, match="named Windows users"):
        shell.expand_user("~other")
    with pytest.raises(AnsibleError, match="one path component"):
        shell.mkdtemp(basefile=r"..\outside")


@pytest.mark.parametrize("cross_user", [False, True])
def test_cross_user_staging_uses_the_requested_parent_directory(
    shell: ShellModule, tmp_path: Path, cross_user: bool
) -> None:
    command = shell.mkdtemp(
        basefile="cross-user-task", system=cross_user, tmpdir=str(tmp_path)
    )
    result = _run_python(command)
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode("utf-8").strip() == str(tmp_path / "cross-user-task")
    assert (tmp_path / "cross-user-task").is_dir()


def test_task_environment_is_literal_inherited_and_process_local(
    shell: ShellModule, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LEGACY_WINDOWS_INHERITED", "protected")
    monkeypatch.setenv("LEGACY_WINDOWS_OVERRIDE", "original")
    literal = 'spaces λ %PATH% !value! & | < > ^ "\r\nnext'
    prefix = shell.env_prefix(
        LEGACY_WINDOWS_OVERRIDE=literal, LEGACY_WINDOWS_EMPTY="", LEGACY_WINDOWS_N=4
    )
    command = (
        "import os,sys; "
        f"assert os.environ['LEGACY_WINDOWS_OVERRIDE'] == {literal!r}; "
        "assert os.environ['LEGACY_WINDOWS_INHERITED'] == 'protected'; "
        "assert os.environ['LEGACY_WINDOWS_EMPTY'] == ''; "
        "assert os.environ['LEGACY_WINDOWS_N'] == '4'; sys.exit(17)"
    )
    result = subprocess.run(
        [sys.executable, "-c", _source(prefix), sys.executable, "-c", command],
        check=False,
        capture_output=True,
    )
    assert result.returncode == 17, result.stderr
    assert os.environ["LEGACY_WINDOWS_OVERRIDE"] == "original"
    assert "LEGACY_WINDOWS_EMPTY" not in os.environ


@pytest.mark.parametrize("name", ["Path", "pAtH", "temp", "TeMp"])
def test_mixed_case_overrides_replace_inherited_windows_environment_names(
    shell: ShellModule, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    inherited_name = name.upper()
    monkeypatch.setenv(inherited_name, "original")
    prefix = shell.env_prefix(**{name: "replacement"})
    command = (
        "import os; "
        f"assert os.environ[{inherited_name!r}] == 'replacement'; "
        f"assert {name!r} not in os.environ"
    )
    result = subprocess.run(
        [sys.executable, "-c", _source(prefix), sys.executable, "-c", command],
        check=False,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert os.environ[inherited_name] == "original"


@pytest.mark.parametrize(
    "overrides", [{"": "value"}, {"BAD=NAME": "x"}, {"BAD\0NAME": "x"}, {"N": "x\0"}]
)
def test_invalid_task_environment_fails_before_launch(
    shell: ShellModule, overrides: dict[str, str]
) -> None:
    with pytest.raises(AnsibleError, match="Task environment names"):
        shell.env_prefix(**overrides)
