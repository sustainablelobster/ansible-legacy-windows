"""Exercise the released trust interface and Windows LSA ownership offline."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native records and API calls are inspected only at the Windows boundary.
# pylint: disable=protected-access
# Keep fixture ownership/readiness tests beside the public trust lifecycle tests.
# pylint: disable=too-many-lines

import copy
import ctypes
import importlib
import json
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Callable
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import (
    HELPER,
    ROOT,
    invoke_payload,
    load_module,
    native_error,
)
from tests.unit.test_python_action import _action

_NAME = "partner.example.test"
_BASE = "DC=example,DC=test"
_DN = "CN=" + _NAME + ",CN=System," + _BASE
_SID = b"\x01\x04\x00\x00\x00\x00\x00\x05" + b"\x15\x00\x00\x00" * 4
_PASSWORD = "FixtureTrustSecret1!"
_DEFAULT = {
    "name": _NAME,
    "direction": "bidirectional",
    "type": "forest",
    "trust_password": _PASSWORD,
}


class Directory:
    """Model observable LDAP trust state independently from native writes."""

    def __init__(self) -> None:
        self.entry: dict[str, Any] | None = None
        self.closed = False
        self.reads: list[tuple[Any, ...]] = []
        self.events: list[tuple[Any, ...]] = []
        self.failure: str | None = None
        self.root_dse = {"dnshostname": [b"dc01.example.test"]}

    def __enter__(self) -> "Directory":
        return self

    def __exit__(self, *_arguments: Any) -> None:
        self.closed = True

    def naming_context(self) -> str:
        """Return the independent directory's default search base.

        :returns: The fixture domain DN.
        """
        return _BASE

    def search(self, *arguments: Any) -> list[dict[str, Any]]:
        """Record requested LDAP state without emulating implementation helpers.

        :param arguments: Native search base, scope, filter and attributes.
        :returns: Current trust state or absence.
        :raises OSError: The configured independent directory boundary fails.
        """
        self.reads.append(arguments)
        if self.failure == "read" or self.failure == "readback" and len(self.reads) > 1:
            raise OSError("Directory unavailable " + _PASSWORD)
        return [copy.deepcopy(self.entry)] if self.entry else []

    def seed(
        self, direction: int = 3, attributes: int = 8, trust_type: int = 2
    ) -> None:
        """Seed raw Windows trust properties without using the implementation.

        :param direction: Raw Windows trust direction mask.
        :param attributes: Raw trust attribute flags.
        :param trust_type: Raw Windows trust type.
        """
        self.entry = {
            "dn": _DN,
            "attributes": {
                "trustDirection": [str(direction).encode()],
                "trustAttributes": [str(attributes).encode()],
                "trustType": [str(trust_type).encode()],
                "securityIdentifier": [_SID],
            },
        }


class Policy:
    """Apply independent native boundary effects to the fixture directory."""

    def __init__(self, directory: Directory, server: str) -> None:
        self.directory, self.server = directory, server

    def __enter__(self) -> "Policy":
        self.directory.events.append(("open", self.server))
        return self

    def __exit__(self, *_arguments: Any) -> None:
        self.directory.events.append(("close", self.server))

    def create(
        self, information: dict[str, Any], direction: int, forest: bool, password: str
    ) -> None:
        """Store the trust only after a successful independent create boundary.

        :param information: Discovered domain identity.
        :param direction: Requested direction mask.
        :param forest: Whether the trust is forest-transitive.
        :param password: Supplied fixture shared secret.
        :raises OSError: A configured create failure prevents the write.
        """
        self.directory.events.append(
            ("create", information, direction, forest, password)
        )
        if self.directory.failure == "create":
            raise OSError("Trust creation denied " + password)
        self.directory.seed(direction, 8 if forest else 4)

    def set_selective(self, name: str, enabled: bool) -> None:
        """Change the independent selective-authentication bit only.

        :param name: Requested trust identity.
        :param enabled: Desired selective-authentication state.
        :raises OSError: A configured native write fails.
        """
        self.directory.events.append(("selective", name, enabled))
        if self.directory.failure == "selective":
            raise OSError("Selective authentication denied " + _PASSWORD)
        assert self.directory.entry is not None
        attributes = self.directory.entry["attributes"]
        flags = int(attributes["trustAttributes"][0])
        attributes["trustAttributes"] = [
            str(flags | 16 if enabled else flags & ~16).encode()
        ]

    def delete(self, sid: bytes) -> None:
        """Remove the independently selected local-side trust.

        :param sid: Existing binary trusted-domain SID.
        :raises OSError: A configured deletion failure preserves the trust.
        """
        self.directory.events.append(("delete", sid))
        if self.directory.failure == "delete":
            raise OSError("Trust removal denied " + _PASSWORD)
        self.directory.entry = None


@pytest.fixture(name="directory")
def directory_fixture() -> Directory:
    """Provide independent directory state for one public module invocation.

    :returns: The fixture directory.
    """
    return Directory()


@pytest.fixture(name="runtime")
def runtime_fixture(
    monkeypatch: pytest.MonkeyPatch, directory: Directory
) -> SimpleNamespace:
    """Load the real payload and replace only directory/security boundaries.

    :param monkeypatch: Scoped target import paths and native replacements.
    :param directory: Independent trust state.
    :returns: Payload, target helper, and native boundary spies.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    helper = importlib.import_module("legacy_ad_trust")
    resolver = Mock(return_value=[("resolved",)])
    discovered = {
        "name": _NAME,
        "flat_name": "PARTNER",
        "forest_name": _NAME,
        "sid": _SID,
    }
    target = Mock(return_value=discovered)
    monkeypatch.setattr(helper, "LDAPConnection", lambda _server: directory)
    monkeypatch.setattr(helper, "TrustPolicy", lambda server: Policy(directory, server))
    monkeypatch.setattr(helper, "target_domain", target)
    monkeypatch.setattr(helper.socket, "getaddrinfo", resolver)
    payload = load_module(
        ROOT / "legacy_ad/plugins/modules/domain_trust.py", "tested_ad_trust"
    )
    return SimpleNamespace(
        payload=payload,
        helper=helper,
        resolver=resolver,
        target=target,
        discovered=discovered,
    )


@pytest.fixture(name="run_request")
def request_fixture(
    runtime: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[..., Any]:
    """Invoke the actual payload's JSON entry point using owned argument files.

    :param runtime: Real payload and native boundary replacements.
    :param monkeypatch: Scoped process argument replacement.
    :param tmp_path: Owned argument file directory.
    :param capsys: Captured module JSON output.
    :returns: Callable accepting public module arguments.
    """
    arguments = tmp_path / "trust-arguments.json"
    monkeypatch.setattr(sys, "argv", ["domain_trust.py", str(arguments)])

    def _run(values: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        arguments.write_text(json.dumps(values), encoding="utf-8")
        return invoke_payload(runtime.payload, capsys)

    return _run


def test_creation_preview_does_not_resolve_dns_or_open_policy(
    run_request: Callable[..., Any], runtime: SimpleNamespace, directory: Directory
) -> None:
    code, result = run_request(
        dict(_DEFAULT, _ansible_check_mode=True, _ansible_diff=True)
    )
    assert code == 0
    assert result == {
        "changed": True,
        "distinguished_name": None,
        "diff": {
            "before": {},
            "after": {
                "name": _NAME,
                "direction": "BiDirectional",
                "trust_type": "Forest",
                "selective_authentication": False,
            },
        },
    }
    runtime.resolver.assert_not_called()
    runtime.target.assert_not_called()
    assert directory.events == [] and directory.entry is None and directory.closed


def test_forest_creation_selective_update_and_repeat_are_idempotent(
    run_request: Callable[..., Any], runtime: SimpleNamespace, directory: Directory
) -> None:
    code, result = run_request(dict(_DEFAULT, selective_authentication=True))
    assert code == 0 and result == {"changed": True, "distinguished_name": _DN}
    runtime.resolver.assert_called_once_with(_NAME, None)
    runtime.target.assert_called_once_with(_NAME, True)
    assert directory.entry is not None
    assert directory.entry["attributes"]["trustAttributes"] == [b"24"]
    assert [event[0] for event in directory.events] == [
        "open",
        "create",
        "close",
        "open",
        "selective",
        "close",
    ]
    directory.events.clear()
    runtime.resolver.reset_mock()
    runtime.target.reset_mock()
    repeated = run_request(
        dict(
            _DEFAULT,
            selective_authentication=True,
            trust_password="ChangedButUnusedSecret1!",
        )
    )
    assert repeated == (0, {"changed": False, "distinguished_name": _DN})
    assert directory.events == []
    runtime.resolver.assert_not_called()
    runtime.target.assert_not_called()


def test_external_creation_matches_baseline_quarantine_and_ignores_selective_flag(
    run_request: Callable[..., Any], runtime: SimpleNamespace, directory: Directory
) -> None:
    code, result = run_request(
        dict(
            _DEFAULT,
            type="external",
            direction="outbound",
            selective_authentication=True,
            _ansible_diff=True,
        )
    )
    assert code == 0 and result["changed"] is True
    assert directory.entry is not None
    assert directory.entry["attributes"]["trustDirection"] == [b"2"]
    assert directory.entry["attributes"]["trustAttributes"] == [b"4"]
    assert result["diff"]["after"]["selective_authentication"] is True
    runtime.target.assert_called_once_with(_NAME, False)
    assert not any(event[0] == "selective" for event in directory.events)


@pytest.mark.parametrize("check", [False, True])
def test_selective_authentication_preserves_unrelated_flags_and_check_mode(
    run_request: Callable[..., Any], directory: Directory, check: bool
) -> None:
    directory.seed(attributes=8 | 128)
    code, result = run_request(
        dict(
            _DEFAULT,
            selective_authentication=True,
            _ansible_check_mode=check,
            _ansible_diff=True,
        )
    )
    assert code == 0 and result["changed"] is True
    assert result["diff"]["before"]["selective_authentication"] is False
    assert result["diff"]["after"]["selective_authentication"] is True
    assert directory.entry is not None
    assert directory.entry["attributes"]["trustAttributes"] == [
        str(136 if check else 152).encode()
    ]
    assert bool(directory.events) is not check


@pytest.mark.parametrize(
    "option,wanted,existing",
    [("direction", "inbound", "BiDirectional"), ("type", "external", "Forest")],
)
def test_immutable_trust_properties_fail_without_native_changes(
    run_request: Callable[..., Any],
    directory: Directory,
    option: str,
    wanted: str,
    existing: str,
) -> None:
    directory.seed()
    code, result = run_request(dict(_DEFAULT, **{option: wanted}))
    assert code == 1 and result["changed"] is False
    assert result["distinguished_name"] == _DN
    assert existing in result["msg"] and "Remove the trust first" in result["msg"]
    assert directory.events == []


def test_external_selective_authentication_update_is_rejected(
    run_request: Callable[..., Any], directory: Directory
) -> None:
    directory.seed(attributes=4)
    code, result = run_request(
        dict(_DEFAULT, type="external", selective_authentication=True)
    )
    assert code == 1 and result["changed"] is False
    assert "only be set on forest trusts" in result["msg"]
    assert directory.events == []


@pytest.mark.parametrize("check", [False, True])
def test_removal_keeps_observed_dn_and_never_contacts_remote_domain(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    directory: Directory,
    check: bool,
) -> None:
    directory.seed()
    code, result = run_request(
        {
            "name": _NAME,
            "state": "absent",
            "_ansible_check_mode": check,
            "_ansible_diff": True,
        }
    )
    assert (
        code == 0 and result["changed"] is True and result["distinguished_name"] == _DN
    )
    assert result["diff"]["after"] == {}
    assert (directory.entry is not None) is check
    runtime.resolver.assert_not_called()
    runtime.target.assert_not_called()
    assert bool(directory.events) is not check


def test_absent_trust_is_idempotent_without_optional_parameters(
    run_request: Callable[..., Any], directory: Directory
) -> None:
    assert run_request({"name": _NAME, "state": "absent"}) == (
        0,
        {"changed": False, "distinguished_name": None},
    )
    assert directory.events == []


def test_dns_failure_precedes_creation_and_redacts_the_supplied_secret(
    run_request: Callable[..., Any], runtime: SimpleNamespace, directory: Directory
) -> None:
    runtime.resolver.side_effect = OSError("Unknown host " + _PASSWORD)
    code, result = run_request(dict(_DEFAULT, _ansible_inject_invocation=True))
    assert code == 1 and result["changed"] is True
    assert "DNS resolution failed" in result["msg"]
    assert _PASSWORD not in json.dumps(result)
    assert directory.events == [] and directory.closed


@pytest.mark.parametrize(
    "failure,fragment,created",
    [
        ("create", "Failed to create trust", False),
        ("selective", "Trust created but failed to enable", True),
        ("readback", "creation succeeded but validation failed", True),
    ],
)
def test_partial_creation_failures_keep_upstream_state_and_close_native_policy(
    run_request: Callable[..., Any],
    directory: Directory,
    failure: str,
    fragment: str,
    created: bool,
) -> None:
    directory.failure = failure
    code, result = run_request(dict(_DEFAULT, selective_authentication=True))
    assert (
        code == 1 and result["changed"] is True and result["distinguished_name"] is None
    )
    assert fragment in result["msg"] and _PASSWORD not in json.dumps(result)
    assert (directory.entry is not None) is created
    assert len([event for event in directory.events if event[0] == "open"]) == len(
        [event for event in directory.events if event[0] == "close"]
    )
    assert directory.closed


@pytest.mark.parametrize("failure,state", [("read", "present"), ("delete", "absent")])
def test_directory_and_removal_failures_are_secret_safe(
    run_request: Callable[..., Any], directory: Directory, failure: str, state: str
) -> None:
    directory.seed()
    directory.failure = failure
    code, result = run_request(dict(_DEFAULT, state=state))
    assert code == 1 and result["failed"] is True
    assert _PASSWORD not in json.dumps(result)
    assert directory.entry is not None and directory.closed
    assert result["changed"] is (state == "absent")


@pytest.mark.parametrize(
    "arguments,fragment",
    [
        ({}, "name is required"),
        ({"name": _NAME}, "direction is required"),
        (dict(_DEFAULT, direction="both"), "direction must be"),
        (dict(_DEFAULT, type="MIT"), "type must be"),
        (dict(_DEFAULT, state="invalid"), "state must be"),
        (
            dict(_DEFAULT, selective_authentication="invalid"),
            "selective_authentication",
        ),
    ],
)
def test_invalid_interface_fails_before_directory_access(
    run_request: Callable[..., Any],
    directory: Directory,
    arguments: dict[str, Any],
    fragment: str,
) -> None:
    code, result = run_request(arguments)
    assert code == 1 and result["changed"] is False and fragment in result["msg"]
    assert directory.reads == [] and directory.events == []


def test_trust_lookup_escapes_filter_input(
    run_request: Callable[..., Any], directory: Directory
) -> None:
    run_request({"name": "x*)(name=*)", "state": "absent"})
    assert "x\\2a\\29\\28name=\\2a\\29" in directory.reads[0][2]


@pytest.fixture(name="native")
def native_fixture(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the real native helper without initializing Windows DLLs.

    :param monkeypatch: Scoped target helper import path.
    :returns: Native trust bindings.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    return importlib.import_module("legacy_ad_trust_native")


def test_unicode_policy_names_count_utf16_bytes(native: ModuleType) -> None:
    name, backing = native._unicode("a😀")
    assert name.length == 6 and name.maximum_length == 8
    assert ctypes.string_at(name.buffer, name.length) == "a😀".encode("utf-16-le")
    assert native._text(name) == "a😀" and backing.raw.endswith(b"\0\0")


@pytest.mark.parametrize("direction,forest", [(1, True), (2, False), (3, True)])
def test_native_creation_passes_exact_authentication_sides_and_clears_owned_secret(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, direction: int, forest: bool
) -> None:
    security, kernel = Mock(), Mock()
    policy = native.TrustPolicy.__new__(native.TrustPolicy)
    policy.security, policy.kernel, policy.handle = security, kernel, 7
    observed: dict[str, Any] = {}

    def _create(
        _handle: Any, trust_pointer: Any, auth_pointer: Any, access: int, output: Any
    ) -> int:
        trust = ctypes.cast(
            trust_pointer, ctypes.POINTER(native._TrustInformation)
        ).contents
        auth = ctypes.cast(
            auth_pointer, ctypes.POINTER(native._TrustAuthentication)
        ).contents
        observed.update(
            name=native._text(trust.name),
            flat_name=native._text(trust.flat_name),
            direction=trust.direction,
            trust_type=trust.trust_type,
            flags=trust.attributes,
            incoming=auth.incoming_count,
            outgoing=auth.outgoing_count,
            access=access,
        )
        authentication = (
            auth.incoming.contents if direction & 1 else auth.outgoing.contents
        )
        observed.update(
            kind=authentication.kind,
            secret=ctypes.string_at(authentication.value, authentication.length),
            secret_address=authentication.value,
            length=authentication.length,
        )
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = 42
        return 0

    security.LsaCreateTrustedDomainEx.side_effect = _create
    clear = Mock(wraps=ctypes.memset)
    monkeypatch.setattr(native.ctypes, "memset", clear)
    policy.create(
        {"name": _NAME, "flat_name": "PARTNER", "sid": _SID},
        direction,
        forest,
        _PASSWORD,
    )
    assert observed["name"] == _NAME and observed["flat_name"] == "PARTNER"
    assert observed["direction"] == direction and observed["trust_type"] == 2
    assert observed["flags"] == (8 if forest else 4) and observed["access"] == 0x30
    assert observed["incoming"] == int(bool(direction & 1)) and observed[
        "outgoing"
    ] == int(bool(direction & 2))
    assert observed["kind"] == 2 and observed["secret"] == _PASSWORD.encode("utf-16-le")
    security.LsaClose.assert_called_once()
    assert security.LsaClose.call_args[0][0].value == 42
    clear.assert_called_once()
    assert clear.call_args[0][1:] == (0, len(_PASSWORD.encode("utf-16-le")) + 1)


@pytest.mark.parametrize("previous", [False, True])
@pytest.mark.parametrize("failure", [None, "consumer", "restore"])
def test_anonymous_identity_restores_original_token_on_success_and_failure(
    native: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    previous: bool,
    failure: str | None,
) -> None:
    def _open(_thread: Any, access: int, as_self: bool, output: Any) -> bool:
        assert access == 0xE and as_self
        output._obj.value = 77 if previous else None
        return previous

    security = SimpleNamespace(
        OpenThreadToken=Mock(side_effect=_open),
        ImpersonateAnonymousToken=Mock(return_value=True),
        SetThreadToken=Mock(return_value=failure != "restore"),
        RevertToSelf=Mock(return_value=failure != "restore"),
    )
    kernel = SimpleNamespace(GetCurrentThread=Mock(return_value=9), CloseHandle=Mock())
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 1008, raising=False)
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)

    def _run() -> None:
        with native._anonymous(security, kernel):
            if failure == "consumer":
                raise ValueError("Read-only identity lookup failed")

    if failure:
        with pytest.raises((OSError, ValueError)):
            _run()
    else:
        _run()
    assert security.SetThreadToken.call_count == int(previous)
    assert security.RevertToSelf.call_count == int(not previous)
    assert kernel.CloseHandle.call_count == int(previous)
    if previous:
        assert kernel.CloseHandle.call_args[0][0].value == 77


def test_policy_handle_closes_when_its_consumer_fails(native: ModuleType) -> None:
    security = Mock()

    def _open(name: Any, attributes: Any, access: int, output: Any) -> int:
        assert native._text(name._obj) == "dc01.example.test"
        assert attributes._obj.length == ctypes.sizeof(native._ObjectAttributes)
        assert access == 0x809
        output._obj.value = 42
        return 0

    security.LsaOpenPolicy.side_effect = _open
    with pytest.raises(ValueError, match="consumer"):
        with native._policy(security, "\\\\dc01.example.test", 0x809) as handle:
            assert handle.value == 42
            raise ValueError("consumer failed")
    security.LsaClose.assert_called_once()
    assert security.LsaClose.call_args[0][0].value == 42


@pytest.mark.parametrize("enabled", [False, True])
def test_native_selective_update_preserves_unrelated_bits_and_frees_query_buffer(
    native: ModuleType, enabled: bool
) -> None:
    information = native._TrustInformation()
    information.attributes = 8 | 16 | 128
    security = Mock()
    policy = native.TrustPolicy.__new__(native.TrustPolicy)
    policy.security, policy.handle = security, 7
    observed: list[int] = []

    def _query(_handle: Any, name: Any, level: int, output: Any) -> int:
        assert native._text(name._obj) == _NAME and level == 6
        output._obj.value = ctypes.addressof(information)
        return 0

    def _set(_handle: Any, _name: Any, level: int, buffer: Any) -> int:
        assert level == 6
        observed.append(
            ctypes.cast(
                buffer, ctypes.POINTER(native._TrustInformation)
            ).contents.attributes
        )
        return 0

    security.LsaQueryTrustedDomainInfoByName.side_effect = _query
    security.LsaSetTrustedDomainInfoByName.side_effect = _set
    policy.set_selective(_NAME, enabled)
    assert observed == [152 if enabled else 136]
    security.LsaFreeMemory.assert_called_once()
    assert security.LsaFreeMemory.call_args[0][0].value == ctypes.addressof(information)


def test_action_stages_all_owned_trust_helpers_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action_module = load_module(
        ROOT / "legacy_ad/plugins/action/domain_trust.py", "tested_ad_trust_action"
    )
    action, shell, events = _action(action_module.ActionModule, monkeypatch)
    action.run()
    transferred = [Path(str(event[1])) for event in events if event[0] == "transfer"]
    assert [source.name for source in transferred] == [
        "legacy_windows_module.py",
        "legacy_ad_ldap.py",
        "legacy_ad_result.py",
        "legacy_ad_trust.py",
        "legacy_ad_trust_native.py",
    ]
    assert all(source.is_file() for source in transferred)
    assert shell.tmpdir is None
    assert len([event for event in events if event[0] == "cleanup"]) == 1


@pytest.fixture(name="auth_observer")
def auth_observer_fixture(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Provide native LDAP/SSPI boundaries for the maintained auth observer.

    :param monkeypatch: Scoped helper imports and native boundary replacements.
    :returns: Observer, native calls, owned buffers and directory-close events.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    observer = load_module(
        ROOT / "tests/integration/fixtures/legacy_ad_trust_auth.py",
        "tested_trust_auth_observer",
    )
    state = SimpleNamespace(failure=None, closed=False, bound=None, queried=[])
    package = observer._PackageInformation()
    package.name = "Kerberos"

    def _read_ldap_option(_handle: Any, number: int, output: Any) -> int:
        if number == 0x99:
            # Native Windows writes the full caller-owned CtxtHandle here.
            assert isinstance(output._obj, observer._ContextHandle)
            assert ctypes.sizeof(output._obj) == 2 * ctypes.sizeof(ctypes.c_void_p)
            if state.failure == "context":
                return 82
            output._obj.lower, output._obj.upper = 11, 22
        else:
            assert number in (0x95, 0x96)
            output._obj.value = 1
        return 0

    def _query_context(context: Any, number: int, output: Any) -> int:
        assert isinstance(context._obj, observer._ContextHandle)
        assert (context._obj.lower, context._obj.upper) == (11, 22)
        state.queried.append(number)
        if number == 12:
            if state.failure == "package":
                return -2146893054
            output._obj.package = ctypes.pointer(package)
            output._obj.state = 0
        else:
            assert number == 13
            if state.failure == "names":
                return -2146893054
            output._obj.client = "owned-user@PARTNER.EXAMPLE.TEST"
            output._obj.server = "ldap/dc01.example.test@EXAMPLE.TEST"
        return 0

    def _search_directory(
        identity: str, scope: int, expression: str, attributes: Any
    ) -> Any:
        assert identity == _BASE and scope == 0 and expression == "(objectClass=*)"
        assert attributes == ["objectGUID", "objectClass"]
        if state.failure == "search":
            raise OSError(49, "Fresh authentication denied")
        return [{"dn": identity}]

    directory = SimpleNamespace(
        handle=7,
        library=SimpleNamespace(ldap_get_optionW=Mock(side_effect=_read_ldap_option)),
        naming_context=lambda: _BASE,
        search=_search_directory,
    )

    @contextmanager
    def _connection(server: str, user: str, password: str) -> Any:
        state.bound = (server, user, password)
        try:
            yield directory
        finally:
            state.closed = True

    security = SimpleNamespace(
        QueryContextAttributesW=Mock(side_effect=_query_context),
        FreeContextBuffer=Mock(return_value=0),
    )
    monkeypatch.setattr(observer, "LDAPConnection", _connection)
    monkeypatch.setattr(observer, "_security_library", lambda: security)
    return SimpleNamespace(observer=observer, state=state, security=security)


def test_auth_observer_reports_actual_package_principals_and_protected_read(
    auth_observer: SimpleNamespace,
) -> None:
    result = auth_observer.observer.observe(
        "dc01.example.test", "owned-user@partner.example.test", _PASSWORD, _BASE
    )
    assert result["package"] == "Kerberos" and result["negotiation_state"] == 0
    assert result["signing"] == result["encryption"] == 1
    assert result["client_principal"] == "owned-user@PARTNER.EXAMPLE.TEST"
    assert result["service_principal"] == "ldap/dc01.example.test@EXAMPLE.TEST"
    assert result["protected_objects"] == [_BASE]
    assert result["naming_context"] == _BASE
    assert _PASSWORD not in json.dumps(result)
    assert auth_observer.state.closed and auth_observer.state.queried == [12, 13]
    assert auth_observer.security.FreeContextBuffer.call_count == 3


@pytest.mark.parametrize("failure", ["search", "context", "package"])
def test_auth_observer_closes_directory_on_native_observation_failure(
    auth_observer: SimpleNamespace, failure: str
) -> None:
    auth_observer.state.failure = failure
    with pytest.raises(OSError):
        auth_observer.observer.observe(
            "dc01.example.test", "owned-user@partner.example.test", _PASSWORD, _BASE
        )
    assert auth_observer.state.closed
    auth_observer.security.FreeContextBuffer.assert_not_called()


def test_auth_observer_does_not_invent_principals_when_the_ssp_cannot_return_them(
    auth_observer: SimpleNamespace,
) -> None:
    auth_observer.state.failure = "names"
    result = auth_observer.observer.observe(
        "dc01.example.test", "owned-user@partner.example.test", _PASSWORD, _BASE
    )
    assert result["native_names_status"] == -2146893054
    assert "client_principal" not in result and "service_principal" not in result
    assert auth_observer.state.closed
    assert auth_observer.security.FreeContextBuffer.call_count == 1


@pytest.fixture(name="forest_preparation")
def forest_preparation_fixture(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Load the fixture with independent ownership and native readiness state.

    :param monkeypatch: Scoped native boundaries, without Windows or lab access.
    :returns: Fixture, acquired directory state and native observations.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    fixture = load_module(
        ROOT / "tests/integration/fixtures/legacy_ad_trust_forest_prepare.py",
        "tested_trust_forest_preparation",
    )
    guid = uuid.UUID("084132ab-119f-4ccf-89ec-3b54de72f421")
    attributes = {
        "objectGUID": [guid.bytes_le],
        "trustDirection": [b"3"],
        "trustType": [b"2"],
        "trustAttributes": [b"8"],
    }
    state = SimpleNamespace(attributes=attributes, closed=False, reads=[])

    def _search(*arguments: Any) -> Any:
        state.reads.append(arguments)
        return [{"attributes": state.attributes}]

    @contextmanager
    def _connection(_server: str, _username: str, _password: str) -> Any:
        try:
            yield SimpleNamespace(naming_context=lambda: _BASE, search=_search)
        finally:
            state.closed = True

    channel = {
        "winerror": 0,
        "flags": 0xB0,
        "verification_status": 0,
        "channel_status": 0,
        "trusted_dc": "\\\\dc.partner.example.test",
    }
    routing = {
        "status": 0,
        "records": [
            {"kind": 0, "flags": 0, "name": _NAME},
            {"kind": 2, "flags": 0, "name": _NAME},
            {"kind": 0, "flags": 1, "name": "unrelated.example.test"},
        ],
    }
    monkeypatch.setattr(fixture, "LDAPConnection", _connection)
    monkeypatch.setattr(fixture, "_network", Mock(return_value=object()))
    monkeypatch.setattr(fixture, "_verify", Mock(return_value=channel))
    monkeypatch.setattr(fixture, "_refresh", Mock(return_value={"winerror": 0}))
    monkeypatch.setattr(fixture, "_routing", Mock(return_value=routing))
    return SimpleNamespace(
        fixture=fixture, state=state, guid=str(guid), channel=channel, routing=routing
    )


def _prepare_forest(state: SimpleNamespace) -> Any:
    return state.fixture.prepare(
        "dc01.example.test", _NAME, state.guid, "owner@example.test", _PASSWORD
    )


def test_forest_fixture_requires_verified_channel_and_enabled_owned_root_routing(
    forest_preparation: SimpleNamespace,
) -> None:
    result = _prepare_forest(forest_preparation)
    assert result["ready"] and result["object_guid"] == forest_preparation.guid
    assert forest_preparation.state.closed
    assert _PASSWORD not in json.dumps(result)
    assert forest_preparation.state.reads[0][2] == (
        "(&(objectClass=trustedDomain)(trustPartner=" + _NAME + "))"
    )
    forest_preparation.fixture._verify.assert_called_once()
    forest_preparation.fixture._refresh.assert_called_once()


@pytest.mark.parametrize(
    "field,value",
    [
        ("objectGUID", uuid.UUID(int=1).bytes_le),
        ("trustDirection", b"1"),
        ("trustType", b"1"),
        ("trustAttributes", b"24"),
    ],
)
def test_forest_fixture_rejects_unowned_or_changed_tdo_before_native_changes(
    forest_preparation: SimpleNamespace, field: str, value: bytes
) -> None:
    forest_preparation.state.attributes[field] = [value]
    with pytest.raises(ValueError, match="unowned or changed"):
        _prepare_forest(forest_preparation)
    assert forest_preparation.state.closed
    forest_preparation.fixture._network.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [
        ("winerror", 5),
        ("flags", 0x30),
        ("verification_status", 1787),
        ("channel_status", 1787),
        ("trusted_dc", ""),
    ],
)
def test_forest_fixture_does_not_treat_control_call_success_as_channel_success(
    forest_preparation: SimpleNamespace, field: str, value: Any
) -> None:
    forest_preparation.channel[field] = value
    assert not _prepare_forest(forest_preparation)["ready"]


@pytest.mark.parametrize("failure", ["refresh", "query", "disabled", "missing", "null"])
def test_forest_fixture_does_not_treat_api_success_or_record_count_as_routing(
    forest_preparation: SimpleNamespace, failure: str
) -> None:
    if failure == "refresh":
        forest_preparation.fixture._refresh.return_value = {"winerror": 1787}
    elif failure == "query":
        forest_preparation.routing["status"] = 0xC0000225
    elif failure == "disabled":
        forest_preparation.routing["records"][0]["flags"] = 1
    elif failure == "missing":
        forest_preparation.routing["records"].pop(1)
    else:
        forest_preparation.routing["records"][0]["name"] = None
    assert not _prepare_forest(forest_preparation)["ready"]


def test_native_forest_verify_owns_level_two_buffer_and_preserves_failure_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    fixture = load_module(
        ROOT / "tests/integration/fixtures/legacy_ad_trust_forest_prepare.py",
        "tested_trust_forest_native_verify",
    )
    information = fixture._ChannelInformation(0x80, 1787, "", 1787)

    def _verify(server: str, function: int, level: int, data: Any, output: Any) -> int:
        assert server == "dc01.example.test" and (function, level) == (10, 2)
        assert (
            ctypes.cast(data, ctypes.POINTER(ctypes.c_wchar_p)).contents.value == _NAME
        )
        output._obj.value = ctypes.addressof(information)
        return 0

    network = SimpleNamespace(
        I_NetLogonControl2=Mock(side_effect=_verify),
        NetApiBufferFree=Mock(return_value=0),
    )
    result = fixture._verify(network, "dc01.example.test", _NAME)
    assert result["winerror"] == 0
    assert result["verification_status"] == result["channel_status"] == 1787
    network.NetApiBufferFree.assert_called_once()
    assert network.NetApiBufferFree.call_args[0][0].value == ctypes.addressof(
        information
    )


def test_native_forest_routing_reads_enabled_names_before_freeing_lsa_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    fixture = load_module(
        ROOT / "tests/integration/fixtures/legacy_ad_trust_forest_prepare.py",
        "tested_trust_forest_native_routing",
    )
    text = ctypes.create_unicode_buffer(_NAME)
    name = fixture._UnicodeString(
        len(_NAME) * 2, (len(_NAME) + 1) * 2, ctypes.addressof(text)
    )
    top = fixture._ForestRecord()
    top.kind, top.flags, top.data.name = 0, 0, name
    domain = fixture._ForestRecord()
    domain.kind, domain.flags, domain.data.domain.dns_name = 2, 0, name
    pointers = (ctypes.POINTER(fixture._ForestRecord) * 2)(
        ctypes.pointer(top), ctypes.pointer(domain)
    )
    information = fixture._ForestInformation(2, pointers)

    def _query(_handle: Any, requested: Any, output: Any) -> int:
        assert requested._obj.length == len(_NAME) * 2
        output._obj.value = ctypes.addressof(information)
        return 0

    security = SimpleNamespace(
        LsaQueryForestTrustInformation=Mock(side_effect=_query),
        LsaFreeMemory=Mock(return_value=0),
    )

    @contextmanager
    def _policy(_server: str) -> Any:
        yield SimpleNamespace(handle=7, security=security)

    monkeypatch.setattr(fixture, "TrustPolicy", _policy)
    result = fixture._routing("dc01.example.test", _NAME)
    assert result == {
        "status": 0,
        "records": [
            {"kind": 0, "flags": 0, "name": _NAME},
            {"kind": 2, "flags": 0, "name": _NAME},
        ],
    }
    security.LsaFreeMemory.assert_called_once()
    assert security.LsaFreeMemory.call_args[0][0].value == ctypes.addressof(information)


@pytest.mark.parametrize("status", [0, 1787])
def test_native_forest_refresh_uses_update_flag_and_frees_returned_buffer(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    fixture = load_module(
        ROOT / "tests/integration/fixtures/legacy_ad_trust_forest_prepare.py",
        "tested_trust_forest_native_refresh",
    )
    information = ctypes.c_uint32(2)

    def _refresh(server: str, partner: str, flags: int, output: Any) -> int:
        assert (server, partner, flags) == ("dc01.example.test", _NAME, 1)
        output._obj.value = ctypes.addressof(information)
        return status

    network = SimpleNamespace(
        DsGetForestTrustInformationW=Mock(side_effect=_refresh),
        NetApiBufferFree=Mock(return_value=0),
    )
    assert fixture._refresh(network, "dc01.example.test", _NAME) == {"winerror": status}
    network.NetApiBufferFree.assert_called_once()
    assert network.NetApiBufferFree.call_args[0][0].value == ctypes.addressof(
        information
    )
