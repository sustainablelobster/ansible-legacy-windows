"""Check exact owned LAN-proxy recovery without claiming Windows execution."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import copy
import ctypes
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="recovery")
def proxy_recovery(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load maintained recovery with independently mutable controller state.

    :param monkeypatch: Scoped native import substitute.
    :returns: Maintained recovery functions and mutable observed state.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/http_default_proxy_fixture.yml").read_text()
    )["http_default_proxy_program"]
    tree = ast.parse(source)
    nodes: list[ast.stmt] = [
        node
        for node in tree.body
        if isinstance(node, (ast.Import, ast.FunctionDef, ast.ClassDef))
    ]
    state = SimpleNamespace(
        connection={"flags": 9, "proxy": None, "bypass": None, "auto_config_url": None},
        values={
            "": {"ProxyEnable": [0, 4], "Unrelated": ["preserved", 1]},
            "Connections": {"SavedLegacySettings": [{"bytes": "b3JpZ2luYWw="}, 3]},
        },
    )
    registry = SimpleNamespace(HKEY_CURRENT_USER=1, KEY_SET_VALUE=2)
    monkeypatch.setitem(__import__("sys").modules, "winreg", registry)
    namespace: dict[str, Any] = {
        "dword": ctypes.c_uint32,
        "pointer": ctypes.c_void_p,
        "wininet": SimpleNamespace(InternetSetOptionW=Mock(return_value=True)),
        "path": "owned",
        "controlled": {
            "": (
                "ProxyEnable",
                "ProxyServer",
                "ProxyOverride",
                "AutoConfigURL",
                "AutoDetect",
            ),
            "Connections": ("DefaultConnectionSettings", "SavedLegacySettings"),
        },
    }
    # No native DLLs, configuration writes or task dispatcher are executed here.
    # pylint: disable-next=exec-used
    exec(
        compile(ast.Module(nodes, type_ignores=[]), "<LAN recovery>", "exec"), namespace
    )

    def open_key(_root: Any, key: str, *_arguments: Any) -> Any:
        """Return the controlled key as a scoped substitute.

        :param key: Native registry path.
        :param _arguments: Registry access flags.
        :returns: Context manager yielding its suffix.
        """
        context = Mock()
        suffix = "Connections" if key.endswith("\\Connections") else ""
        context.__enter__ = Mock(return_value=suffix)
        context.__exit__ = Mock(return_value=False)
        return context

    registry.OpenKey = open_key
    registry.DeleteValue = lambda suffix, name: state.values[suffix].pop(name)

    def set_value(suffix: str, name: str, _reserved: int, kind: int, data: Any) -> None:
        state.values[suffix][name] = [
            namespace["encoded"](data) if isinstance(data, bytes) else data,
            kind,
        ]

    registry.SetValueEx = set_value
    namespace["read_connection"] = lambda: dict(state.connection)
    namespace["registry"] = lambda: copy.deepcopy(state.values)
    namespace["snapshot"] = lambda: {
        "connection": dict(state.connection),
        "registry": copy.deepcopy(state.values),
    }

    def write(_handle: Any, option: int, listing: Any, _size: int) -> bool:
        """Simulate native writes and the refresh counter side effect.

        :param option: Native setting or notification selector.
        :param listing: Native option-list address.
        :returns: Native success.
        """
        if option == 75:
            values = ctypes.cast(
                listing, ctypes.POINTER(namespace["Options"])
            ).contents.options
            state.connection = {"flags": values[0].value.number}
            state.connection.update(
                {
                    name: (
                        ctypes.wstring_at(values[index].value.text)
                        if values[index].value.text
                        else None
                    )
                    for index, name in enumerate(
                        ("proxy", "bypass", "auto_config_url"), 1
                    )
                }
            )
        if option == 39:
            state.values["Connections"]["SavedLegacySettings"] = [
                {"bytes": "cmVmcmVzaA=="},
                3,
            ]
        return True

    namespace["wininet"].InternetSetOptionW.side_effect = write
    state.before = namespace["snapshot"]()
    state.restore = namespace["restore"]
    state.native = namespace["wininet"]
    return state


def test_original_flags_latent_strings_and_registry_values_are_restored(
    recovery: Any,
) -> None:
    recovery.connection.update(
        flags=2, proxy="127.0.0.1:1234", bypass="", auto_config_url=None
    )
    recovery.values[""]["ProxyEnable"] = [1, 4]
    recovery.values[""]["ProxyServer"] = ["127.0.0.1:1234", 1]
    recovery.restore(recovery.before)
    assert recovery.connection == recovery.before["connection"]
    assert recovery.values == recovery.before["registry"]
    assert [
        call.args[1] for call in recovery.native.InternetSetOptionW.call_args_list
    ] == [75, 39, 37]


def test_unrelated_registry_changes_fail_without_overwriting_them(
    recovery: Any,
) -> None:
    recovery.values[""]["Unrelated"] = ["unexpected", 1]
    with pytest.raises(AssertionError, match="Original LAN/IE proxy settings differ"):
        recovery.restore(recovery.before)
    assert recovery.values[""]["Unrelated"] == ["unexpected", 1]


def test_embedded_fixture_remains_python34_syntax() -> None:
    document = yaml.safe_load(
        (ROOT / "tests/integration/vars/http_default_proxy_fixture.yml").read_text()
    )
    ast.parse(document["http_default_proxy_program"], feature_version=(3, 4))
