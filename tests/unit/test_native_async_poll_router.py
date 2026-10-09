"""Use fresh core loaders to verify the explicit mixed-host polling entry point."""

# SPDX-License-Identifier: GPL-3.0-or-later

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.unit.payload_support import ROOT


def _run_fresh_polling_probe(tmp_path: Path, program: str, *arguments: str) -> str:
    collections = tmp_path / "collections"
    namespace = collections / "ansible_collections/sustainablelobster"
    namespace.mkdir(parents=True)
    (namespace / "legacy_windows").symlink_to(ROOT, target_is_directory=True)
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n", encoding="utf-8")
    environment = {
        **os.environ,
        "ANSIBLE_CONFIG": str(config),
        "ANSIBLE_COLLECTIONS_PATH": str(collections),
        "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "false",
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "controller-tmp"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    environment.pop("ANSIBLE_ACTION_PLUGINS", None)
    result = subprocess.run(
        [sys.executable, "-c", program, *arguments],
        env=environment,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_core_poll_and_cleanup_bypass_normal_collection_action_routing(
    tmp_path: Path,
) -> None:
    collection = tmp_path / "collections/ansible_collections/testing/polling"
    metadata = collection / "meta"
    metadata.mkdir(parents=True)
    (metadata / "runtime.yml").write_text(
        """---
plugin_routing:
  modules:
    async_status:
      action_plugin: sustainablelobster.legacy_windows.async_status
  action:
    async_status:
      redirect: sustainablelobster.legacy_windows.async_status
action_groups:
  jobs:
    - async_status
""",
        encoding="utf-8",
    )
    modules = collection / "plugins/modules"
    modules.mkdir(parents=True)
    (modules / "async_status.py").symlink_to(ROOT / "plugins/modules/async_status.py")
    program = r"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from ansible._internal._task import TaskContext, UnifiedTaskResult
from ansible._internal._templating._engine import TemplateEngine
from ansible.executor.task_executor import TaskExecutor
from ansible.inventory.host import Host
from ansible.parsing.dataloader import DataLoader
from ansible.playbook.play import Play
from ansible.playbook.play_context import PlayContext
from ansible.plugins import loader as plugin_loaders
from ansible.plugins.loader import action_loader, connection_loader, init_plugin_loader
init_plugin_loader()
workspace = Path.cwd()
cache = workspace / 'cache'
cache.mkdir()
jid = 'j123.456'
record = cache / jid
record.write_text(json.dumps({
    'started': True, 'finished': True, 'changed': True, 'stdout': 'native cache result'
}), encoding='utf-8')
loader = DataLoader()
loader.set_basedir(str(workspace))
variables = {
    'ansible_python_interpreter': sys.executable,
    'ansible_async_dir': str(cache),
    'ansible_remote_tmp': str(workspace / 'staging'),
}
templar = TemplateEngine(loader=loader, variables=variables)
play = Play.load({
    'hosts': 'localhost',
    'collections': ['testing.polling'],
    'module_defaults': {'group/testing.polling.jobs': {'mode': 'status'}},
    'tasks': [{'async_status': {'jid': jid}, 'async': 20, 'poll': 1}],
}, loader=loader)
task = play.tasks[0].block[0]
assert task.module_defaults
context = PlayContext()
context.connection = 'local'
connection = connection_loader.get('local', context, None)
connection.set_options(var_options=variables)
connection._shell.set_options(var_options=variables)
executor = TaskExecutor(
    Host('localhost'), context, loader, plugin_loaders,
    SimpleNamespace(send_callback=lambda *args: None), None,
)
executor._connection = connection
with TaskContext.create(task, variables, 'localhost'):
    handler, module = executor._get_action_handler_with_module_context(templar)
    native = action_loader.get('sustainablelobster.legacy_windows.async_status', class_only=True)
    assert isinstance(handler, native)
    assert module.action_plugin == 'sustainablelobster.legacy_windows.async_status'
    result = executor._poll_async_result(
        UnifiedTaskResult.from_action_result_dict({
            'ansible_job_id': jid, 'started': True, 'finished': False,
        }), templar, variables,
    )
assert result.finished and result.changed
assert result.as_result_dict()['stdout'] == 'native cache result'
assert not record.exists()
print('PASS: real core poll reads the native-shaped record and cleanup removes it')
"""
    assert "real core poll reads" in _run_fresh_polling_probe(tmp_path, program)


@pytest.mark.parametrize("mode", ["status", "cleanup"])
@pytest.mark.parametrize("native_record", [False, True])
def test_native_shell_still_builds_builtin_status_payload(
    tmp_path: Path, mode: str, native_record: bool
) -> None:
    program = r"""
import json
import subprocess
import sys
from pathlib import Path
from ansible._internal._task import TaskContext
from ansible.parsing.dataloader import DataLoader
from ansible.playbook.play_context import PlayContext
from ansible.playbook.task import Task
from ansible.plugins.loader import action_loader, connection_loader, init_plugin_loader, shell_loader
from ansible.template import Templar
init_plugin_loader()
mode = sys.argv[1]
native_record = sys.argv[2] == 'native'
workspace = Path.cwd()
cache = workspace / 'cache'
cache.mkdir()
jid = 'j123.456'
record = cache / jid
job_result = {'started': True, 'finished': True, 'stdout': 'native cache result'}
if native_record:
    sys.path.insert(0, str(workspace / 'collections/ansible_collections/sustainablelobster/legacy_windows/plugins/module_utils'))
    from legacy_windows_async_worker import atomic_json
    atomic_json(str(record), job_result)
else:
    record.write_text(json.dumps(job_result), encoding='utf-8')
variables = {'ansible_python_interpreter': sys.executable}
loader = DataLoader()
loader.set_basedir(str(workspace))
context = PlayContext()
native_shell = shell_loader.get('sustainablelobster.legacy_windows.cmd')
native_shell.set_options(var_options={'ansible_python_interpreter': r'C:\Python34\python.exe'})
connection = connection_loader.get('local', context, None, shell=native_shell)
connection.set_options(var_options=variables)
task = Task.load({
    'async_status': {'jid': jid, 'mode': mode},
    'collections': ['sustainablelobster.legacy_windows'],
}, loader=loader)
action = action_loader.get(
    'ansible.legacy.async_status', task=task, connection=connection,
    play_context=context, loader=loader, templar=Templar(loader=loader, variables=variables),
)
assert type(action) is action_loader.get('ansible.builtin.async_status', class_only=True)
with TaskContext.create(task, variables, 'localhost'):
    bits, source = action._configure_module(
        'ansible.legacy.async_status', {'jid': jid, 'mode': mode, '_async_dir': str(cache)}, variables,
    )
assert Path(source).name == 'async_status.py' and 'ansible/modules' in source
assert bits.module_style == 'new'
payload = workspace / 'builtin-status.py'
payload.write_bytes(bits.b_module_data)
process = subprocess.run([sys.executable, str(payload)], capture_output=True, text=True, check=False)
assert process.returncode == 0, process.stdout + process.stderr
result = json.loads(process.stdout)
if mode == 'status':
    assert result['finished'] is (not native_record)
    if native_record:
        assert result['results_file'] == str(record)
    else:
        assert result['stdout'] == 'native cache result'
    assert record.exists()
else:
    assert result['erased'] == str(record)
    assert not record.exists()
print('PASS: builtin payload uses the cache on controller Python despite native shell selection')
"""
    assert "despite native shell selection" in _run_fresh_polling_probe(
        tmp_path, program, mode, "native" if native_record else "plain"
    )


@pytest.mark.parametrize("mode", ["status", "cleanup"])
def test_native_shell_with_ssh_needs_external_windows_status_payload(
    tmp_path: Path, mode: str
) -> None:
    program = r"""
import sys
from ansible._internal._task import TaskContext
from ansible.errors import AnsibleError
from ansible.parsing.dataloader import DataLoader
from ansible.playbook.play_context import PlayContext
from ansible.playbook.task import Task
from ansible.plugins.loader import action_loader, connection_loader, init_plugin_loader, shell_loader
from ansible.template import Templar
init_plugin_loader()
loader = DataLoader()
context = PlayContext()
shell = shell_loader.get('sustainablelobster.legacy_windows.cmd')
variables = {'ansible_python_interpreter': r'C:\Python34\python.exe'}
shell.set_options(var_options=variables)
connection = connection_loader.get('ssh', context, None, shell=shell)
connection.set_options(var_options={})
task = Task.load({
    'async_status': {'jid': 'j123.456', 'mode': sys.argv[1]},
    'collections': ['sustainablelobster.legacy_windows'],
}, loader=loader)
action = action_loader.get(
    'ansible.legacy.async_status', task=task, connection=connection,
    play_context=context, loader=loader, templar=Templar(loader=loader, variables=variables),
)
with TaskContext.create(task, variables, 'not-connected'):
    try:
        action._configure_module(
            'ansible.legacy.async_status',
            {'jid': 'j123.456', 'mode': sys.argv[1], '_async_dir': r'C:\Temp\cache'},
            variables,
        )
    except AnsibleError as error:
        assert 'ansible.windows.async_status' in str(error), str(error)
        assert 'not found' in str(error), str(error)
    else:
        raise AssertionError('A standalone native collection must not supply the external PowerShell status payload')
assert not connection.connected
print('PASS: SSH/native shell builds external Windows status, without opening a connection')
"""
    assert "without opening a connection" in _run_fresh_polling_probe(
        tmp_path, program, mode
    )


def test_status_import_before_loader_initialization_keeps_builtin_lifecycle(
    tmp_path: Path,
) -> None:
    collections = tmp_path / "collections"
    namespace = collections / "ansible_collections/sustainablelobster"
    namespace.mkdir(parents=True)
    (namespace / "legacy_windows").symlink_to(ROOT, target_is_directory=True)
    environment = {
        **os.environ,
        "ANSIBLE_COLLECTIONS_PATH": str(collections),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    environment.pop("ANSIBLE_ACTION_PLUGINS", None)
    program = r"""
from ansible.utils.collection_loader import AnsibleCollectionConfig
assert AnsibleCollectionConfig.collection_finder is None
from plugins.action.async_status import ActionModule
from ansible.plugins.action.async_status import ActionModule as BuiltinAction
assert issubclass(ActionModule, BuiltinAction)
assert AnsibleCollectionConfig.collection_finder is None
from ansible.plugins.loader import action_loader, init_plugin_loader
init_plugin_loader()
assert action_loader.get('sustainablelobster.legacy_windows.win_ping', class_only=True) is not None
assert action_loader.get('sustainablelobster.legacy_windows.async_status', class_only=True) is not None
print('PASS: native status imports before init_plugin_loader without global initialization')
"""
    result = subprocess.run(
        [sys.executable, "-c", program],
        env=environment,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "imports before init_plugin_loader" in result.stdout


def test_default_loader_rejects_native_automatic_poll_before_launch(
    tmp_path: Path,
) -> None:
    collections = tmp_path / "collections"
    namespace = collections / "ansible_collections/sustainablelobster"
    namespace.mkdir(parents=True)
    (namespace / "legacy_windows").symlink_to(ROOT, target_is_directory=True)
    program = r"""
from types import SimpleNamespace
from ansible.errors import AnsibleActionFail
from ansible.plugins.loader import action_loader, init_plugin_loader
init_plugin_loader()
selected = action_loader.get('ansible.legacy.async_status', class_only=True)
builtin = action_loader.get('ansible.builtin.async_status', class_only=True)
assert selected is builtin
assert getattr(selected, '_supports_native_windows_polling', False) is not True
from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils._module import PythonModuleAction
action = object.__new__(PythonModuleAction)
action._task = SimpleNamespace(async_val=30, poll=1)
action._connection = SimpleNamespace(become=None)
try:
    action._check_execution_support(allow_async=True)
except AnsibleActionFail as error:
    assert '[defaults] action_plugins = ' in str(error)
    assert "in your project's ansible.cfg" in str(error)
    assert 'otherwise use poll: 0 and sustainablelobster.legacy_windows.async_status' in str(error)
else:
    raise AssertionError('Default loader must reject automatic polling before launch')
print('PASS: real default loader retains builtin status and native early rejection')
"""
    environment = {
        **os.environ,
        "ANSIBLE_COLLECTIONS_PATH": str(collections),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    environment.pop("ANSIBLE_ACTION_PLUGINS", None)
    result = subprocess.run(
        [sys.executable, "-c", program],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "real default loader retains builtin status" in result.stdout


@pytest.mark.parametrize("activation", ["environment", "project-config"])
def test_standard_opt_in_resolves_native_and_preserves_builtin_routing(
    tmp_path: Path,
    activation: str,
) -> None:
    collections = tmp_path / "collections"
    namespace = collections / "ansible_collections/sustainablelobster"
    namespace.mkdir(parents=True)
    (namespace / "legacy_windows").symlink_to(ROOT, target_is_directory=True)
    program = r"""
from types import SimpleNamespace
from unittest.mock import patch
from ansible.plugins.loader import action_loader, init_plugin_loader, shell_loader
init_plugin_loader()
router = action_loader.get('ansible.legacy.async_status', class_only=True)
native = action_loader.get('sustainablelobster.legacy_windows.async_status', class_only=True)
builtin = action_loader.get('ansible.builtin.async_status', class_only=True)
assert router._supports_native_windows_polling is True
assert router is not builtin and issubclass(router, native)
native_shell = shell_loader.get('sustainablelobster.legacy_windows.cmd', class_only=True)
for shell_name in ['sustainablelobster.legacy_windows.cmd', 'sh', 'cmd']:
    shell_class = shell_loader.get(shell_name, class_only=True)
    action = object.__new__(router)
    action._connection = SimpleNamespace(_shell=object.__new__(shell_class), become=object())
    is_native = isinstance(action._connection._shell, native_shell)
    variables = {'literal': 'kept'}
    native_result = {'native': True, 'sentinel': [None, False, 1]}
    builtin_result = {'builtin': True, 'sentinel': [None, False, 1]}
    with patch.object(native, 'run', return_value=native_result) as native_run, \
         patch.object(builtin, 'run', return_value=builtin_result) as builtin_run:
        result = action.run(task_vars=variables)
        assert result is (native_result if is_native else builtin_result)
        if is_native:
            native_run.assert_called_once_with(None, variables)
        else:
            builtin_run.assert_called_once_with(action, None, variables)
        (builtin_run if is_native else native_run).assert_not_called()
    arguments = {'module_name': 'ansible.legacy.async_status', 'task_vars': variables}
    with patch.object(native, '_execute_module', return_value=native_result) as native_execute, \
         patch.object(builtin, '_execute_module', return_value=builtin_result) as builtin_execute:
        result = action._execute_module(**arguments)
        assert result is (native_result if is_native else builtin_result)
        if is_native:
            native_execute.assert_called_once_with(**arguments)
        else:
            builtin_execute.assert_called_once_with(action, **arguments)
        (builtin_execute if is_native else native_execute).assert_not_called()
print('PASS: standard plugin path resolves opt-in; native, POSIX and builtin-cmd branches preserve their selected result and arguments')
"""
    environment = {
        **os.environ,
        "ANSIBLE_COLLECTIONS_PATH": str(collections),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if activation == "environment":
        environment["ANSIBLE_ACTION_PLUGINS"] = str(
            ROOT / "plugins/action/_native_async_polling"
        )
    else:
        environment.pop("ANSIBLE_ACTION_PLUGINS", None)
        config = tmp_path / "ansible.cfg"
        config.write_text(
            (ROOT / "docs/examples/async-polling.cfg").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        environment["ANSIBLE_CONFIG"] = str(config)
    result = subprocess.run(
        [sys.executable, "-c", program],
        env=environment,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "native, POSIX and builtin-cmd branches" in result.stdout
