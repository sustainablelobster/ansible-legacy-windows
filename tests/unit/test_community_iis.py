"""Exercise IIS interfaces against an owned native-provider boundary model."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native boundaries are substituted; these tests do not claim Windows coverage.
# pylint: disable=protected-access

import json
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


class Property:
    """Represent one schema-validated native configuration property."""

    def __init__(self, name: str, value: Any) -> None:
        self.name, self.value = name, value
        self.explicit = False

    def get(self, name: str) -> Any:
        """Read the modeled native property metadata or value.

        :param name: Native property, method or element name.
        :returns: Modeled native result or loaded test helper.
        :rtype: object
        """
        if name == "Schema":
            return SimpleNamespace(get=lambda _name: "string")
        return {"Name": self.name, "Value": self.value, "StringValue": str(self.value)}[
            name
        ]

    def put(self, name: str, value: Any) -> None:
        """Validate and replace a modeled native value.

        :param name: Native property, method or element name.
        :param value: Requested native property value.
        :raises OSError: The modeled native operation is invalid.
        """
        assert name == "Value"
        if self.name in {"id", "queueLength"}:
            value = int(value)
            if value < 0:
                raise OSError("Schema validation failed")
        self.value = value
        self.explicit = True


class Collection:
    """Represent ordered IIS collections and indexed property lookups."""

    def __init__(
        self, entries: list[Any] | None = None, defaults: dict[str, Any] | None = None
    ) -> None:
        self.entries = entries or []
        self.defaults = defaults or {}

    def get(self, name: str) -> Any:
        """Read a native collection count.

        :param name: Native property, method or element name.
        :returns: Modeled native result or loaded test helper.
        :rtype: object
        """
        assert name == "Count"
        return len(self.entries)

    def _item(self, index: int | str) -> Any:
        if isinstance(index, int):
            return self.entries[index]
        for entry in self.entries:
            name = entry.name if isinstance(entry, (Property, Element)) else ""
            if name.lower() == index.lower():
                return entry
        raise OSError("Native schema member not found: " + index)

    def call(self, name: str, *values: Any) -> Any:
        """Apply one modeled native collection operation.

        :param name: Native property, method or element name.
        :param values: Ordered native operation arguments.
        :returns: Modeled native result or loaded test helper.
        :rtype: object
        :raises AssertionError: The modeled native operation is invalid.
        """
        if name == "Item":
            return self._item(values[0])
        if name == "CreateNewElement":
            return (
                Element(values[0], deepcopy(self.defaults))
                if self.defaults
                else element(values[0])
            )
        if name == "AddElement":
            self.entries.append(values[0])
        elif name == "DeleteElement":
            self.entries.pop(values[0])
        elif name == "Clear":
            self.entries.clear()
        else:
            raise AssertionError(name)
        return None


# The native element surface used here has one read operation.
class Element:  # pylint: disable=too-few-public-methods
    """Represent exactly the installed IIS schema used by the public workflows."""

    def __init__(
        self,
        name: str,
        properties: dict[str, Any] | None = None,
        children: list[Any] | None = None,
    ) -> None:
        self.name = name
        self.properties = Collection(
            [Property(key, value) for key, value in (properties or {}).items()]
        )
        self.children = Collection(children)
        self.collection = Collection()
        if name == "schedule":
            self.collection.defaults = {"value": ""}

    def get(self, name: str) -> Any:
        """Read a modeled element's properties, children or collection.

        :param name: Native property, method or element name.
        :returns: Modeled native result or loaded test helper.
        :rtype: object
        """
        return {
            "Properties": self.properties,
            "ChildElements": self.children,
            "Collection": self.collection,
        }[name]


def element(name: str) -> Element:
    """Build an element using representative native defaults, not module state.

    :param name: Native property, method or element name.
    :returns: Modeled native result or loaded test helper.
    :rtype: object
    :raises AssertionError: The modeled native operation is invalid.
    """
    if name == "site":
        return Element(
            name,
            {"name": "", "id": 0, "serverAutoStart": True},
            [
                Element("bindings"),
                Element("logFile", {"directory": "", "period": "Daily"}),
            ],
        )
    if name == "application":
        return Element(name, {"path": "", "applicationPool": "DefaultAppPool"})
    if name == "virtualDirectory":
        return Element(
            name, {"path": "", "physicalPath": "", "userName": "", "password": ""}
        )
    if name == "binding":
        return Element(name, {"protocol": "", "bindingInformation": "", "sslFlags": 0})
    if name == "add":
        return Element(
            name,
            {
                "name": "",
                "autoStart": True,
                "queueLength": 1000,
                "managedRuntimeVersion": "",
                "managedPipelineMode": "Integrated",
            },
            [
                Element("cpu", {"limit": 0}),
                Element("failure", {"rapidFailProtection": True}),
                Element(
                    "processModel", {"identityType": 4, "userName": "", "password": ""}
                ),
                Element(
                    "recycling",
                    {"disallowOverlappingRotation": False},
                    [
                        Element(
                            "periodicRestart",
                            {"time": "29:00:00"},
                            [Element("schedule")],
                        )
                    ],
                ),
            ],
        )
    raise AssertionError(name)


class Manager:
    """Own a transaction and its committed snapshot independently of the module."""

    def __init__(self) -> None:
        self.sites, self.pools = Element("sites"), Element("applicationPools")
        default = element("add")
        default.properties.entries[0].value = "DefaultAppPool"
        self.pools.collection.entries.append(default)
        self.commits = 0

    def put(self, name: str, value: str) -> None:
        """Require a machine-level native configuration transaction.

        :param name: Native property, method or element name.
        :param value: Requested native property value.
        """
        assert name == "CommitPath" and value == "MACHINE/WEBROOT/APPHOST"

    def call(self, name: str, *values: Any) -> Any:
        """Read sections or commit a native transaction.

        :param name: Native property, method or element name.
        :param values: Ordered native operation arguments.
        :returns: Modeled native result or loaded test helper.
        :rtype: object
        """
        if name == "CommitChanges":
            # Native new elements expose an empty schema runtime, but omission
            # inherits the pool default only when committed. An explicit empty
            # assignment must survive as empty rather than inherit v4.0.
            for pool in self.pools.collection.entries:
                runtime = pool.properties.call("Item", "managedRuntimeVersion")
                if not runtime.explicit:
                    runtime.value = "v4.0"
            self.commits += 1
            return None
        assert name == "GetAdminSection"
        return self.sites if values[0].endswith("/sites") else self.pools


@pytest.fixture(name="iis")
def iis_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload helper without initializing Windows Automation.

    :param monkeypatch: Scoped native-boundary substitutions.
    :returns: Modeled native result or loaded test helper.
    :rtype: object
    """
    directory = ROOT / "legacy_community_windows/plugins/module_utils"
    monkeypatch.syspath_prepend(str(directory))
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        ROOT
        / "legacy_community_windows/plugins/module_utils/legacy_community_windows_iis.py",
        "tested_iis",
    )


@pytest.fixture(name="manager")
def native_manager(iis: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Manager:
    """Replace the process boundary with an owned native transaction model.

    :param iis: Loaded IIS helper under test.
    :param monkeypatch: Scoped native-boundary substitutions.
    :returns: Modeled native result or loaded test helper.
    :rtype: object
    """
    manager = Manager()

    class Automation:
        """Model native context ownership, without making COM calls."""

        def __enter__(self) -> "Automation":
            return self

        def __exit__(self, *_arguments: Any) -> None:
            return None

        def create(self, _name: str) -> Manager:
            """Return the independently owned native transaction.

            :returns: Modeled native result or loaded test helper.
            :rtype: object
            """
            return manager

    monkeypatch.setattr(iis, "IisAutomation", Automation)
    monkeypatch.setattr(iis, "_path", lambda value: value)
    monkeypatch.setattr(iis, "_runtime_state", lambda *_arguments: "Started")
    monkeypatch.setattr(
        iis,
        "_state",
        lambda _kind, _name, desired, _preview: (desired == "restarted", "Started"),
    )
    return manager


def site(iis: ModuleType, **values: Any) -> dict[str, Any]:
    """Create or inspect the same test-owned public site.

    :param iis: Loaded IIS helper under test.
    :param values: Ordered native operation arguments.
    :returns: Modeled native result or loaded test helper.
    :rtype: object
    """
    return cast(
        dict[str, Any],
        iis.manage(
            "win_iis_website",
            {"name": "Owned site 雪", "physical_path": r"C:\web", **values},
        ),
    )


def test_site_lifecycle_bindings_pool_and_idempotence(
    iis: ModuleType, manager: Manager
) -> None:
    created = site(
        iis, state="started", port=8123, hostname="owned.example", site_id="23"
    )
    assert created["changed"] is True
    assert created["site"]["ID"] == 23
    assert created["site"]["Bindings"] == ["*:8123:owned.example"]
    assert manager.commits == 1
    repeated = site(iis, state="started", port=8999, site_id="99")
    assert repeated["changed"] is False
    assert repeated["site"]["ID"] == 23
    assert repeated["site"]["Bindings"] == ["*:8123:owned.example"]
    assert manager.commits == 1
    removed = iis.manage(
        "win_iis_website", {"name": "Owned site 雪", "state": "absent"}
    )
    assert removed == {"changed": True, "site": {}}
    assert (
        iis.manage("win_iis_website", {"name": "Owned site 雪", "state": "absent"})[
            "changed"
        ]
        is False
    )


def test_site_nested_parameters_and_invalid_attributes_never_commit(
    iis: ModuleType, manager: Manager
) -> None:
    site(iis, parameters=r"logFile.directory:C:\logs|logfile.period:Hourly")
    assert (
        site(iis, parameters=r"logFile.directory:C:\logs|logfile.period:Hourly")[
            "changed"
        ]
        is False
    )
    with pytest.raises(OSError, match="Native schema member"):
        site(iis, parameters="missing.attribute:value")
    assert manager.commits == 1


@pytest.mark.parametrize("module", ["win_iis_website", "win_iis_virtualdirectory"])
def test_released_check_mode_unsupported_modules_do_not_initialize_native_state(
    iis: ModuleType, monkeypatch: pytest.MonkeyPatch, module: str
) -> None:
    monkeypatch.setattr(
        iis, "IisAutomation", lambda: pytest.fail("Preview reached Windows")
    )
    assert (
        iis.manage(module, {"name": "test", "_ansible_check_mode": True})["skipped"]
        is True
    )


@pytest.mark.parametrize(
    "module", ["win_iis_webapplication", "win_iis_virtualdirectory"]
)
def test_application_and_directory_create_repeat_update_remove(
    iis: ModuleType, manager: Manager, module: str
) -> None:
    site(iis)
    values = {"site": "Owned site 雪", "name": "child 雪", "physical_path": r"C:\child"}
    first = iis.manage(module, values)
    assert first["changed"] is True
    repeated = iis.manage(module, values)
    assert repeated["changed"] is False
    update = iis.manage(module, dict(values, physical_path=r"C:\other"))
    assert update["changed"] is True
    removed = iis.manage(module, dict(values, state="absent"))
    assert removed["changed"] is True
    assert iis.manage(module, dict(values, state="absent"))["changed"] is False
    assert manager.commits == 4


def test_application_preview_does_not_commit_and_preserves_public_return_defaults(
    iis: ModuleType, manager: Manager
) -> None:
    site(iis)
    preview = iis.manage(
        "win_iis_webapplication",
        {
            "site": "Owned site 雪",
            "name": "child",
            "physical_path": r"C:\child",
            "_ansible_check_mode": True,
        },
    )
    assert preview == {
        "changed": True,
        "physical_path": r"C:\child",
        "application_pool": None,
    }
    assert manager.commits == 1


def test_existing_application_preview_returns_the_unchanged_current_configuration(
    iis: ModuleType, manager: Manager
) -> None:
    site(iis)
    parameters = {
        "site": "Owned site 雪",
        "name": "child",
        "physical_path": r"C:\original",
    }
    iis.manage("win_iis_webapplication", parameters)
    preview = iis.manage(
        "win_iis_webapplication",
        dict(parameters, physical_path=r"C:\predicted", _ansible_check_mode=True),
    )
    assert preview["changed"] is True
    assert preview["physical_path"] == r"C:\original"
    assert manager.commits == 2


def test_existing_pool_preview_returns_current_attributes_not_predicted_ones(
    iis: ModuleType, manager: Manager
) -> None:
    iis.manage(
        "win_iis_webapppool", {"name": "owned", "attributes": {"queueLength": 1234}}
    )
    preview = iis.manage(
        "win_iis_webapppool",
        {
            "name": "owned",
            "attributes": {"queueLength": 4321},
            "_ansible_check_mode": True,
        },
    )
    assert preview["changed"] is True
    assert preview["info"]["attributes"]["queueLength"] == 1234
    assert manager.commits == 1


@pytest.mark.parametrize(
    "module", ["win_iis_webapplication", "win_iis_virtualdirectory"]
)
def test_connect_as_modes_are_idempotent_and_password_is_not_returned(
    iis: ModuleType, manager: Manager, module: str
) -> None:
    site(iis)
    values = {
        "site": "Owned site 雪",
        "name": "credentials",
        "physical_path": r"C:\child",
        "connect_as": "specific_user",
        "username": "DOMAIN\\reader",
        "password": "secret",
    }
    assert iis.manage(module, values)["changed"] is True
    assert iis.manage(module, values)["changed"] is False
    result = iis.manage(module, dict(values, connect_as="pass_through"))
    assert result["changed"] is True
    assert "secret" not in str(result)
    assert manager.commits == 3


@pytest.mark.parametrize(
    "values, message",
    [
        ({}, "Missing required argument"),
        ({"state": "broken"}, "Invalid state"),
        ({"port": 70000}, "port must"),
        ({"site_id": "0"}, "site_id must"),
        ({"parameters": "missingcolon"}, "property:value"),
    ],
)
def test_invalid_site_inputs_do_not_commit(
    iis: ModuleType, manager: Manager, values: dict[str, Any], message: str
) -> None:
    arguments = {"name": "test", "physical_path": r"C:\web", **values}
    if not values:
        arguments.pop("name")
    with pytest.raises(ValueError, match=message):
        iis.manage("win_iis_website", arguments)
    assert manager.commits == 0


def test_pool_attributes_nested_values_preview_and_secret_redaction(
    iis: ModuleType, manager: Manager
) -> None:
    values = {
        "name": "Owned pool",
        "attributes": {
            "queueLength": 222,
            "processModel.userName": "reader",
            "processModel.password": "secret",
        },
    }
    result = iis.manage("win_iis_webapppool", values)
    assert result["changed"] is True
    assert result["info"]["attributes"]["queueLength"] == 222
    assert "secret" not in str(result)
    assert iis.manage("win_iis_webapppool", values)["changed"] is False
    assert manager.commits == 1
    assert (
        iis.manage("win_iis_webapppool", dict(values, state="restarted"))["changed"]
        is True
    )


@pytest.mark.parametrize("state", ["present", "started"])
@pytest.mark.parametrize("runtime", ["", "v2.0", None])
def test_first_pool_creation_persists_requested_runtime_before_first_repeat(
    iis: ModuleType, manager: Manager, state: str, runtime: str | None
) -> None:
    parameters: dict[str, Any] = {"name": "Owned runtime", "state": state}
    if runtime is not None:
        parameters["attributes"] = {
            "managedPipelineMode": "Classic",
            "managedRuntimeVersion": runtime,
        }
    created = iis.manage("win_iis_webapppool", parameters)
    assert created["changed"] is True
    persisted = manager.pools.collection.entries[-1]
    native_runtime = persisted.properties.call("Item", "managedRuntimeVersion")
    assert native_runtime.value == ("v4.0" if runtime is None else runtime)
    assert native_runtime.explicit is (runtime is not None)
    assert created["info"]["attributes"]["managedRuntimeVersion"] == (
        native_runtime.value
    )
    if runtime is not None:
        assert persisted.properties.call("Item", "managedPipelineMode").value == (
            "Classic"
        )
        assert created["info"]["attributes"]["managedRuntimeVersion"] == runtime
    assert manager.commits == 1
    assert iis.manage("win_iis_webapppool", parameters)["changed"] is False
    assert manager.commits == 1


@pytest.mark.parametrize("state", ["present", "started"])
def test_new_pool_info_uses_a_fresh_native_manager_not_the_creating_cache(
    iis: ModuleType,
    manager: Manager,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    creating_call = manager.call
    committed: list[Manager] = []

    def commit_with_stale_creator(name: str, *values: Any) -> Any:
        """Commit effective defaults without refreshing the creator's cache.

        :param name: Native manager operation.
        :param values: Native method arguments.
        :returns: Native method result.
        :rtype: object
        """
        result = creating_call(name, *values)
        if name == "CommitChanges":
            fresh = Manager()
            fresh.sites, fresh.pools = deepcopy(manager.sites), deepcopy(manager.pools)
            committed.append(fresh)
            manager.pools.collection.entries[-1].properties.call(
                "Item", "managedRuntimeVersion"
            ).value = ""
        return result

    monkeypatch.setattr(manager, "call", commit_with_stale_creator)
    monkeypatch.setattr(
        iis.IisAutomation,
        "create",
        lambda _self, _name: committed[-1] if committed else manager,
    )
    created = iis.manage(
        "win_iis_webapppool",
        {
            "name": "Owned inherited runtime",
            "state": state,
            "attributes": {"processModel.password": "never-returned"},
        },
    )
    assert created["changed"] is True
    assert created["info"]["attributes"]["managedRuntimeVersion"] == "v4.0"
    assert created["info"]["attributes"]["state"] == "Started"
    assert "never-returned" not in str(created)
    assert manager.commits == 1


def test_explicit_new_runtime_does_not_commit_before_other_attribute_validation(
    iis: ModuleType, manager: Manager
) -> None:
    with pytest.raises(OSError, match="Schema validation failed"):
        iis.manage(
            "win_iis_webapppool",
            {
                "name": "Invalid new pool",
                "attributes": {"managedRuntimeVersion": "", "queueLength": -1},
            },
        )
    assert manager.commits == 0


@pytest.fixture(name="pool_reader")
def native_pool_reader() -> ModuleType:
    """Load the independent AppCmd readback used by the public pool demo.

    :returns: Fixture reader without Windows provider imports.
    :rtype: ModuleType
    """
    return load_module(
        ROOT / "tests/integration/fixtures/community_iis_pool_read.py",
        "tested_native_pool_reader",
    )


@pytest.mark.parametrize("runtime", ["", "v2.0", None])
@pytest.mark.parametrize("sysnative", [True, False])
def test_native_pool_readback_distinguishes_empty_explicit_and_omitted_values(
    pool_reader: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    runtime: str | None,
    sysnative: bool,
) -> None:
    explicit = "" if runtime is None else f' managedRuntimeVersion="{runtime}"'
    output = (
        '<appcmd><APPPOOL APPPOOL.NAME="owned-present" '
        f'RuntimeVersion="{runtime or ""}" PipelineMode="Classic">'
        f'<add name="owned-present"{explicit} />'
        '</APPPOOL><APPPOOL APPPOOL.NAME="unrelated" RuntimeVersion="v4.0">'
        '<add name="unrelated" password="not-returned" /></APPPOOL></appcmd>'
    ).encode()
    process = Mock(returncode=0)
    process.communicate.return_value = (output, b"")
    process.__enter__ = Mock(return_value=process)
    process.__exit__ = Mock(return_value=False)
    popen = Mock(return_value=process)
    monkeypatch.setattr(pool_reader.subprocess, "Popen", popen)
    monkeypatch.setattr(pool_reader.os.path, "isfile", lambda _path: sysnative)
    values = pool_reader.read_pools("owned-")
    assert list(values) == ["present"]
    assert values["present"]["explicit_runtime"] == runtime
    assert values["present"]["runtime"] == (runtime or "")
    assert values["present"]["pipeline"] == "Classic"
    assert len(values["present"]["configuration_sha256"]) == 64
    assert "not-returned" not in str(values)
    command = popen.call_args.args[0]
    assert ("Sysnative" in command[0]) is sysnative
    assert command[1:] == ["list", "apppool", "/config", "/xml"]


@pytest.mark.parametrize(
    "status,output,expected",
    [
        (5, b"", (OSError, "rc=5")),
        (
            0,
            b'<appcmd><APPPOOL APPPOOL.NAME="owned-missing" /></appcmd>',
            (ValueError, "omitted configuration"),
        ),
    ],
)
def test_native_pool_readback_rejects_failed_or_incomplete_native_output(
    pool_reader: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    output: bytes,
    expected: tuple[type[Exception], str],
) -> None:
    process = Mock(returncode=status)
    process.communicate.return_value = (output, b"not-returned")
    process.__enter__ = Mock(return_value=process)
    process.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(pool_reader.subprocess, "Popen", Mock(return_value=process))
    with pytest.raises(expected[0], match=expected[1]):
        pool_reader.read_pools("owned-")


def test_schedule_comparison_uses_persisted_timespan_not_native_ticks(
    iis: ModuleType, manager: Manager, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = element("add")
    assert iis._attribute(pool, "recycling.periodicRestart.schedule", ["03:00:00"])
    schedule = (
        pool.children.call("Item", "recycling")
        .children.call("Item", "periodicRestart")
        .children.call("Item", "schedule")
    )
    prop = schedule.collection.entries[0].properties.call("Item", "value")
    monkeypatch.setattr(
        prop, "get", lambda name: 108000000000 if name == "Value" else "03:00:00"
    )
    assert not iis._attribute(pool, "recycling.periodicRestart.schedule", ["03:00:00"])
    assert manager.commits == 0


@pytest.mark.parametrize("attributes", ["invalid", {"missing": 1}, {"queueLength": -1}])
def test_invalid_pool_attributes_never_commit(
    iis: ModuleType, manager: Manager, attributes: Any
) -> None:
    with pytest.raises((ValueError, OSError)):
        iis.manage("win_iis_webapppool", {"name": "Owned", "attributes": attributes})
    assert manager.commits == 0


def test_native_validation_messages_cannot_echo_supplied_passwords(
    iis: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_module: str, _parameters: dict[str, Any]) -> dict[str, Any]:
        raise OSError("Native password validation rejected top-secret / pool-secret")

    monkeypatch.setattr(iis, "_manage", fail)
    with pytest.raises(OSError) as error:
        iis.manage(
            "win_iis_webapppool",
            {
                "password": "top-secret",
                "attributes": {"processModel.password": "pool-secret"},
            },
        )
    assert "top-secret" not in str(error.value)
    assert "pool-secret" not in str(error.value)
    assert "[redacted]" in str(error.value)


def test_binding_exact_matching_does_not_remove_siblings(
    iis: ModuleType, manager: Manager
) -> None:
    site(iis)
    binding = {"website": "Owned site 雪", "port": 8456, "host_header": "owned.example"}
    first = iis.manage("win_iis_webbinding", binding)
    assert first["changed"] is True
    assert first["operation_type"] == "added"
    assert first["binding_info"]["bindingInformation"] == "*:8456:owned.example"
    assert iis.manage("win_iis_webbinding", binding)["operation_type"] == "matched"
    removed = iis.manage("win_iis_webbinding", dict(binding, state="absent"))
    assert removed["changed"] is True
    assert removed["operation_type"] == "removed"
    assert site(iis)["site"]["Bindings"] == ["*:80:"]
    assert iis.manage("win_iis_webbinding", dict(binding, state="absent")) == {
        "changed": False
    }
    assert manager.commits == 3


@pytest.mark.parametrize(
    "values, message",
    [
        ({"host_header": "*"}, "Omit host_header"),
        ({"ssl_flags": "9"}, "ssl_flags must"),
        ({"ssl_flags": "1"}, "only be set for HTTPS"),
        ({"certificate_hash": "abc"}, "thumbprint requires"),
        (
            {"protocol": "https", "ssl_flags": "2", "certificate_hash": "abc"},
            "Central Certificate Store",
        ),
    ],
)
def test_binding_validation_precedes_all_commits(
    iis: ModuleType, manager: Manager, values: dict[str, Any], message: str
) -> None:
    site(iis)
    with pytest.raises(ValueError, match=message):
        iis.manage("win_iis_webbinding", {"name": "Owned site 雪", **values})
    assert manager.commits == 1


def test_public_frontends_delegate_without_altering_released_arguments(
    iis: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for name in (
        "win_iis_website",
        "win_iis_webapppool",
        "win_iis_webapplication",
        "win_iis_virtualdirectory",
        "win_iis_webbinding",
    ):
        payload = load_module(
            ROOT / "legacy_community_windows/plugins/modules" / (name + ".py"),
            "tested_" + name,
        )
        arguments = tmp_path / (name + ".json")
        arguments.write_text(json.dumps({}), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", [name + ".py", str(arguments)])
        code, result = invoke_payload(payload, capsys)
        assert code == 1
        assert result["failed"] is True
        assert result["changed"] is False
        assert "Missing required argument: name" in result["msg"]
    assert iis.manage is not None


@pytest.mark.usefixtures("manager")
@pytest.mark.parametrize(
    "name",
    [
        "win_iis_website",
        "win_iis_webapppool",
        "win_iis_webapplication",
        "win_iis_virtualdirectory",
        "win_iis_webbinding",
    ],
)
def test_public_frontends_normalize_known_options_and_keep_unknown_options_permissive(
    iis: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    name: str,
) -> None:
    site(iis)
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules" / (name + ".py"),
        "case_tested_" + name,
    )
    monkeypatch.setattr(payload, "manage", iis.manage)
    arguments = {
        "NAME": "Not created",
        "SITE": "Owned site 雪",
        "STATE": "absent",
        "unknown_option": "preserved legacy permissiveness",
    }
    if name == "win_iis_webbinding":
        arguments.pop("NAME")
        arguments["WEBSITE"] = "Owned site 雪"
        arguments["PORT"] = "8456"
    elif name == "win_iis_webapplication":
        arguments["PATH"] = "C:\\owned"
    argument_file = tmp_path / (name + ".json")
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [name + ".py", str(argument_file)])
    code, result = invoke_payload(payload, capsys)
    assert code == 0 and result["changed"] is False
    if name == "win_iis_webapplication":
        assert result["physical_path"] == "C:\\owned"
