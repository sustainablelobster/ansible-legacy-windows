"""Exercise Certificate Services public payloads with native-boundary substitutes."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Reuse only the independently observable LDAP write fixture, not OU expectations.
# pylint: disable=protected-access,duplicate-code

import copy
import importlib
import json
import re
import struct
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable
from unittest.mock import Mock

import pytest

from tests.unit import test_ad_ou
from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module

CONFIG = "CN=Configuration," + test_ad_ou.BASE
SERVICES = "CN=Public Key Services,CN=Services," + CONFIG
TEMPLATES = "CN=Certificate Templates," + SERVICES
OIDS = "CN=OID," + SERVICES
ENROLLMENT = "CN=Enrollment Services," + SERVICES


class TemplateDirectory(test_ad_ou.Directory):
    """Model template/OID configuration objects and CA publication attributes."""

    def __enter__(self) -> "TemplateDirectory":
        return self

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def naming_context(self, name: str = "defaultNamingContext") -> str:
        """Return the independent configuration partition.

        :param name: Requested naming context.
        :returns: Fixture partition DN.
        """
        return (
            CONFIG
            if name == "configurationNamingContext"
            else super().naming_context(name)
        )

    def search(
        self,
        base: str,
        scope: int,
        ldap_filter: str,
        attributes: list[str],
        **flags: Any
    ) -> list[dict[str, Any]]:
        """Evaluate LDAP predicates against stored attributes rather than payload logic.

        :param base: Search base distinguished name.
        :param scope: Native search scope.
        :param ldap_filter: Protocol filter sent by the implementation.
        :param attributes: Requested attribute projection.
        :param flags: Native server-control options.
        :returns: Copied matching object rows.
        """
        rows = super().search(base, scope, ldap_filter, attributes, **flags)
        conditions = re.findall(r"\(([^()=]+)=([^()]*)\)", ldap_filter)
        selected = []
        for row in rows:
            if scope == 1 and row["dn"].count(",") != base.count(",") + 1:
                continue
            raw = {
                key.lower(): values for key, values in self.objects[row["dn"]].items()
            }
            matched = []
            for attribute, value in conditions:
                if value == "*":
                    matched.append(bool(raw.get(attribute.lower())))
                    continue
                text = re.sub(
                    r"\\([0-9a-fA-F]{2})",
                    lambda match: chr(int(match.group(1), 16)),
                    value,
                )
                matched.append(
                    any(
                        item.decode("utf-8", errors="replace").lower() == text.lower()
                        for item in raw.get(attribute.lower(), [])
                    )
                )
            if any(matched) if ldap_filter.startswith("(|") else all(matched):
                selected.append(row)
        return selected

    def modify(self, dn: str, changes: list[tuple[int, str, list[bytes]]]) -> None:
        """Preserve unrelated multivalues during native LDAP add/remove requests.

        :param dn: Existing directory object.
        :param changes: LDAP operation, attribute and encoded-value tuples.
        :raises OSError: If the fixture's write-failure injection is active.
        """
        self._failure("modify")
        self.writes.append(("modify", dn, copy.deepcopy(changes)))
        for operation, name, values in changes:
            existing_name = next(
                (key for key in self.objects[dn] if key.lower() == name.lower()), name
            )
            current = self.objects[dn].get(existing_name, [])
            if operation == 0:
                updated = current + [value for value in values if value not in current]
            elif operation == 1:
                updated = (
                    [value for value in current if value not in values]
                    if values
                    else []
                )
            else:
                updated = list(values)
            if updated:
                self.objects[dn][existing_name] = updated
            else:
                self.objects[dn].pop(existing_name, None)


class AuthorityState:
    """Independently observe ordered CA registry writes and injected failures."""

    def __init__(self) -> None:
        self.values = {
            "CRLPublicationURLs": [
                "65:C:\\CertEnroll\\%3%8%9.crl",
                "2:http://old.invalid/%3.crl",
            ],
            "CACertPublicationURLs": [
                "1:C:\\CertEnroll\\%1_%3%4.crt",
                "2:http://old.invalid/%3.crt",
            ],
        }
        self.writes: list[tuple[str, list[str]]] = []
        self.fail_on: str | None = None
        self.closed = False

    def __enter__(self) -> "AuthorityState":
        return self

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        self.closed = True

    def read(self, name: str) -> list[str]:
        """Read a copied native registry list.

        :param name: CA registry value name.
        :returns: Independent stored publication list.
        """
        return list(self.values[name])

    def write(self, name: str, values: list[str]) -> None:
        """Persist the requested list unless a native write failure is injected.

        :param name: CA registry value name.
        :param values: Requested ordered publication strings.
        :raises OSError: If this value's failure injection is enabled.
        """
        if name == self.fail_on:
            raise OSError(5, "Registry write denied")
        self.values[name] = list(values)
        self.writes.append((name, list(values)))


@pytest.fixture(name="directory")
def template_directory() -> TemplateDirectory:
    """Create a source template, forest OID and independent CA registry objects.

    :returns: Initialized native-operation fixture.
    """
    directory = TemplateDirectory()
    directory.add(
        OIDS,
        {
            "objectClass": [b"container"],
            "cn": [b"OID"],
            "msPKI-Cert-Template-OID": [b"1.3.6.1.4.1.311.21.8.42"],
        },
    )
    directory.add(
        "CN=WebServer," + TEMPLATES,
        {
            "objectClass": [b"pKICertificateTemplate"],
            "cn": [b"WebServer"],
            "displayName": [b"Web Server"],
            "flags": [b"32"],
            "revision": [b"100"],
            "msPKI-Minimal-Key-Size": [b"2048"],
            "msPKI-Template-Schema-Version": [b"1"],
            "pKIExtendedKeyUsage": [b"1.3.6.1.5.5.7.3.1"],
            "pKIDefaultCSPs": [b"1,Microsoft RSA SChannel Cryptographic Provider"],
            "pKIKeyUsage": [b"\xa0"],
            "pKIExpirationPeriod": [struct.pack("<q", -365 * 864000000000)],
            "pKIOverlapPeriod": [struct.pack("<q", -42 * 864000000000)],
            "msPKI-Cert-Template-OID": [b"1.2.3.4"],
            "unclonedAttribute": [b"not copied"],
        },
    )
    for name in ("FirstCA", "SecondCA"):
        directory.add(
            "CN=" + name + "," + ENROLLMENT,
            {
                "objectClass": [b"pKIEnrollmentService"],
                "cn": [name.encode()],
                "certificateTemplates": [b"WebServer", b"ExistingTemplate"],
            },
        )
    directory.writes.clear()
    return directory


@pytest.fixture(name="authority")
def authority_state() -> AuthorityState:
    """Provide fresh local CA registry state.

    :returns: Registry-state fixture.
    """
    return AuthorityState()


@pytest.fixture(name="restart")
def service_restart() -> Mock:
    """Observe the native service control boundary without contacting Windows.

    :returns: CertSvc control spy.
    """
    return Mock()


@pytest.fixture(name="payloads")
def certificate_payloads(
    monkeypatch: pytest.MonkeyPatch,
    directory: TemplateDirectory,
    authority: AuthorityState,
    restart: Mock,
) -> dict[str, ModuleType]:
    """Import public payloads while substituting only native operation boundaries.

    :param monkeypatch: Scoped native substitutions.
    :param directory: Independent LDAP object model.
    :param authority: Independent local registry model.
    :param restart: Native service control spy.
    :returns: Both public JSON payloads.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(HELPER.parent))
    templates = importlib.import_module("legacy_ad_cs_template")
    monkeypatch.setattr(templates, "LDAPConnection", Mock(return_value=directory))
    ca = importlib.import_module("legacy_ad_cs_authority")
    monkeypatch.setattr(ca, "AuthorityConfiguration", Mock(return_value=authority))
    monkeypatch.setattr(ca.services, "control", restart)
    return {
        kind: load_module(
            ROOT / "legacy_ad/plugins/modules" / (kind + ".py"), "tested_ad_" + kind
        )
        for kind in ("cs_authority", "cs_template")
    }


@pytest.fixture(name="run")
def payload_runner(
    payloads: dict[str, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[..., dict[str, Any]]:
    """Run a selected public payload through its JSON entry point.

    :param payloads: Native CS payloads.
    :param monkeypatch: Scoped argument-file substitution.
    :param tmp_path: Disposable argument-file location.
    :param capsys: Captured module output.
    :returns: Callable returning validated JSON results.
    """

    def _invoke(
        kind: str, values: dict[str, Any], failed: bool = False
    ) -> dict[str, Any]:
        path = tmp_path / "arguments.json"
        path.write_text(json.dumps(values), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", [kind + ".py", str(path)])
        status, result = invoke_payload(payloads[kind], capsys)
        assert status == (1 if failed else 0), result
        return result

    return _invoke


def test_authority_no_options_do_not_require_ca_configuration(
    run: Any, authority: AuthorityState, restart: Mock
) -> None:
    assert run("cs_authority", {})["changed"] is False
    assert authority.writes == [] and not authority.closed and not restart.called


def test_authority_public_lists_check_idempotence_flags_clear_and_restart(
    run: Any, authority: AuthorityState, restart: Mock
) -> None:
    request = {
        "cdp": [
            {
                "uri": "http://pki.invalid/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl",
                "add_to_certificate_cdp": True,
                "add_to_freshest_crl": True,
            }
        ],
        "aia": [
            {
                "uri": "http://pki.invalid/<ServerDNSName>_<CAName><CertificateName>.crt",
                "add_to_certificate_aia": True,
            },
            {"uri": "http://ocsp.invalid", "add_to_certificate_ocsp": True},
        ],
    }
    before = copy.deepcopy(authority.values)
    preview = run(
        "cs_authority", dict(request, _ansible_check_mode=True, _ansible_diff=True)
    )
    assert preview["changed"] and "diff" not in preview
    assert authority.values == before and not restart.called
    created = run("cs_authority", request)
    assert created["changed"]
    assert authority.values["CRLPublicationURLs"] == ["6:http://pki.invalid/%3%8%9.crl"]
    assert authority.values["CACertPublicationURLs"] == [
        "2:http://pki.invalid/%1_%3%4.crt",
        "32:http://ocsp.invalid",
    ]
    restart.assert_called_once_with("CertSvc", "restarted", force=True)
    assert not run("cs_authority", request)["changed"] and restart.call_count == 1
    updated = run(
        "cs_authority",
        {
            "cdp": [
                {
                    "uri": "http://pki.invalid/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl",
                    "add_to_certificate_cdp": True,
                }
            ],
            "restart_service": False,
        },
    )
    assert updated["changed"] and authority.values["CRLPublicationURLs"] == [
        "2:http://pki.invalid/%3%8%9.crl"
    ]
    assert (
        len(authority.values["CACertPublicationURLs"]) == 2 and restart.call_count == 1
    )
    assert run("cs_authority", {"cdp": [], "aia": [], "restart_service": False})[
        "changed"
    ]
    assert not run("cs_authority", {"cdp": [], "aia": []})["changed"]


def test_authority_case_insensitive_comparison_preserves_unknown_flags_and_order(
    run: Any, authority: AuthorityState
) -> None:
    authority.values["CACertPublicationURLs"] = [
        "1:C:\\CertEnroll\\%1_%3%4.crt",
        "2:http://pki.invalid/%3.crt",
    ]
    desired = [
        {"uri": "HTTP://PKI.INVALID/<caname>.CRT", "add_to_certificate_aia": True},
        {"uri": "c:\\certenroll\\<serverdnsname>_<caname><certificatename>.crt"},
    ]
    result = run("cs_authority", {"aia": desired})
    assert not result["changed"] and authority.writes == []
    assert authority.values["CACertPublicationURLs"][0].startswith("1:")


def test_authority_second_write_failure_and_restart_failure_retain_changes(
    run: Any, authority: AuthorityState, restart: Mock
) -> None:
    authority.fail_on = "CACertPublicationURLs"
    result = run("cs_authority", {"cdp": [], "aia": []}, failed=True)
    assert result["changed"] and authority.values["CRLPublicationURLs"] == []
    assert authority.values["CACertPublicationURLs"] and not restart.called
    authority.fail_on = None
    restart.side_effect = OSError(5, "Restart denied")
    result = run("cs_authority", {"aia": []}, failed=True)
    assert result["changed"] and authority.values["CACertPublicationURLs"] == []


@pytest.mark.parametrize(
    "values",
    [
        {"cdp": "not a list"},
        {"cdp": [{}]},
        {"aia": [{"uri": "http://pki", "unknown": True}]},
        {"cdp": [{"uri": "http://pki", "publish_to_server": True}]},
        {"cdp": [{"uri": "http://pki", "add_to_crl_cdp": True}]},
        {"aia": [{"uri": "http://pki", "add_to_certificate_aia": "bogus"}]},
    ],
)
def test_authority_invalid_configuration_fails_before_writes(
    run: Any, authority: AuthorityState, values: dict[str, Any]
) -> None:
    result = run("cs_authority", values, failed=True)
    assert not result["changed"] and authority.writes == [] and result["msg"]


def test_template_public_clone_preview_idempotence_native_bytes_and_cleanup(
    run: Any, directory: TemplateDirectory
) -> None:
    request = {
        "name": "Custom",
        "source_template": "Web Server",
        "display_name": "Custom Web",
        "key_size": 4096,
        "schema_version": 2,
        "key_usage": ["digital_signature", "key_encipherment"],
        "validity_period_days": 365,
        "renewal_period_days": 42,
        "extended_key_usages": ["server_authentication"],
        "publish_to_ca": ["FirstCA"],
    }
    before = copy.deepcopy(directory.objects)
    preview = run(
        "cs_template", dict(request, _ansible_check_mode=True, _ansible_diff=True)
    )
    assert (
        preview["changed"]
        and preview["distinguished_name"] is None
        and preview["template_oid"] is None
    )
    assert "diff" not in preview and directory.objects == before
    created = run("cs_template", request)
    dn = "CN=Custom," + TEMPLATES
    assert created["changed"] and created["distinguished_name"] == dn
    assert created["template_oid"].startswith("1.3.6.1.4.1.311.21.8.42.")
    native = directory.objects[dn]
    assert native["msPKI-Minimal-Key-Size"] == [b"4096"]
    assert native["pKIKeyUsage"] == [b"\xa0\0"]
    assert native["pKIExpirationPeriod"] == [struct.pack("<q", -365 * 864000000000)]
    assert (
        "unclonedAttribute" not in native
        and native["pKIDefaultCSPs"]
        == directory.objects["CN=WebServer," + TEMPLATES]["pKIDefaultCSPs"]
    )
    assert (
        b"Custom"
        in directory.objects["CN=FirstCA," + ENROLLMENT]["certificateTemplates"]
    )
    assert (
        b"Custom"
        not in directory.objects["CN=SecondCA," + ENROLLMENT]["certificateTemplates"]
    )
    assert not run("cs_template", request)["changed"]
    before = copy.deepcopy(directory.objects)
    assert run(
        "cs_template",
        {"name": "Custom", "state": "absent", "_ansible_check_mode": True},
    )["changed"]
    assert directory.objects == before
    removed = run("cs_template", {"name": "Custom", "state": "absent"})
    assert removed["changed"] and removed["template_oid"] == created["template_oid"]
    assert dn not in directory.objects
    assert not any(
        created["template_oid"].encode() in values.get("msPKI-Cert-Template-OID", [])
        for values in directory.objects.values()
    )
    assert not run("cs_template", {"name": "Custom", "state": "absent"})["changed"]


def test_template_update_flags_key_usage_eku_periods_and_publication(
    run: Any, directory: TemplateDirectory
) -> None:
    created = run("cs_template", {"name": "Custom", "source_template": "Web Server"})
    request = {
        "name": "Custom",
        "key_size": 8192,
        "extended_key_usages": ["client_authentication", "1.3.6.1.5.5.7.3.1"],
        "key_usage": ["key_agreement", "decipher_only"],
        "enrollment_flag": ["auto_enrollment", "publish_to_ds"],
        "private_key_flag": ["exportable_key", "0x100"],
        "certificate_name_flag": [
            "subject_require_directory_path",
            "enrollee_supplies_subject",
        ],
        "validity_period_days": 730,
        "renewal_period_days": 60,
        "publish_to_ca": ["SecondCA", "MissingCA"],
    }
    before = copy.deepcopy(directory.objects)
    assert run("cs_template", dict(request, _ansible_check_mode=True))["changed"]
    assert directory.objects == before
    updated = run("cs_template", request)
    native = directory.objects[created["distinguished_name"]]
    assert updated["changed"] and native["msPKI-Minimal-Key-Size"] == [b"8192"]
    assert native["msPKI-Enrollment-Flag"] == [b"40"]
    assert native["msPKI-Private-Key-Flag"] == [b"272"]
    assert native["msPKI-Certificate-Name-Flag"] == [b"-2147483647"]
    assert native["pKIKeyUsage"] == [b"\x08\x80"]
    assert updated["warnings"] == [
        "Certificate Authority 'MissingCA' was not found in Enrollment Services."
    ]
    assert not run("cs_template", request)["changed"]


@pytest.mark.parametrize(
    "values",
    [
        {"name": "Missing"},
        {"name": "Missing", "source_template": "Missing Source"},
        {"name": "Missing", "source_template": "Web Server", "key_usage": ["unknown"]},
        {
            "name": "Missing",
            "source_template": "Web Server",
            "enrollment_flag": ["unknown"],
        },
        {"name": "Missing", "source_template": "Web Server", "schema_version": 1},
    ],
)
def test_template_invalid_creation_does_not_register_an_oid(
    run: Any, directory: TemplateDirectory, values: dict[str, Any]
) -> None:
    before = copy.deepcopy(directory.objects)
    result = run("cs_template", values, failed=True)
    assert (
        not result["changed"] and directory.objects == before and directory.writes == []
    )


def test_template_filter_escaping_does_not_select_or_delete_existing_templates(
    run: Any, directory: TemplateDirectory
) -> None:
    before = copy.deepcopy(directory.objects)
    result = run("cs_template", {"name": "*)(cn=WebServer", "state": "absent"})
    assert not result["changed"] and directory.objects == before


def test_template_absent_wrong_class_object_is_untouched(
    run: Any, directory: TemplateDirectory
) -> None:
    directory.add(
        "CN=Other," + TEMPLATES, {"objectClass": [b"container"], "cn": [b"Other"]}
    )
    result = run("cs_template", {"name": "Other", "state": "absent"})
    assert not result["changed"] and "CN=Other," + TEMPLATES in directory.objects


def test_template_one_byte_key_usage_and_eku_order_are_idempotent(
    run: Any, directory: TemplateDirectory
) -> None:
    result = run(
        "cs_template",
        {
            "name": "WebServer",
            "key_usage": ["key_encipherment", "digital_signature"],
            "extended_key_usages": ["server_authentication"],
        },
    )
    assert not result["changed"] and directory.writes == []


@pytest.mark.parametrize(
    "value,wanted",
    [
        ("0x80000000", b"-2147483648"),
        ("0xffffffff", b"-1"),
        ("010", b"10"),
        ("2147483647", b"2147483647"),
    ],
)
def test_template_raw_flag_values_preserve_signed_int32_contract(
    run: Any, directory: TemplateDirectory, value: str, wanted: bytes
) -> None:
    request = {
        "name": "Custom",
        "source_template": "Web Server",
        "certificate_name_flag": [value],
    }
    result = run("cs_template", request)
    assert directory.objects[result["distinguished_name"]][
        "msPKI-Certificate-Name-Flag"
    ] == [wanted]
    assert not run("cs_template", request)["changed"]


def test_template_empty_eku_list_clears_source_and_existing_values(
    run: Any, directory: TemplateDirectory
) -> None:
    created = run(
        "cs_template",
        {"name": "Custom", "source_template": "Web Server", "extended_key_usages": []},
    )
    assert "pKIExtendedKeyUsage" not in directory.objects[created["distinguished_name"]]
    assert not run("cs_template", {"name": "Custom", "extended_key_usages": []})[
        "changed"
    ]
    assert run(
        "cs_template",
        {"name": "Custom", "extended_key_usages": ["client_authentication"]},
    )["changed"]
    assert run("cs_template", {"name": "Custom", "extended_key_usages": []})["changed"]
    assert "pKIExtendedKeyUsage" not in directory.objects[created["distinguished_name"]]


def test_authority_registry_reads_do_not_request_write_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    helper = load_module(
        ROOT / "legacy_ad/plugins/module_utils/legacy_ad_cs_authority.py",
        "tested_ca_registry",
    )
    configuration, reader, writer = Mock(), Mock(), Mock()
    for key in (configuration, reader, writer):
        key.__enter__ = Mock(return_value=key)
        key.__exit__ = Mock(return_value=False)
    registry = Mock(
        HKEY_LOCAL_MACHINE=1,
        REG_SZ=1,
        REG_MULTI_SZ=7,
        KEY_READ=0x20019,
        KEY_SET_VALUE=2,
    )
    registry.OpenKey.side_effect = [configuration, reader, writer]
    registry.QueryValueEx.side_effect = [("OwnedCA", 1), (["2:http://pki.invalid"], 7)]
    monkeypatch.setattr(helper, "winreg", registry)
    with helper.AuthorityConfiguration() as authority:
        assert authority.read("CRLPublicationURLs") == ["2:http://pki.invalid"]
        assert registry.OpenKey.call_args_list[1].args[-1] == registry.KEY_READ
        registry.SetValueEx.assert_not_called()
        authority.write("CRLPublicationURLs", [])
    assert registry.OpenKey.call_args_list[2].args[-1] == registry.KEY_SET_VALUE
    registry.SetValueEx.assert_called_once_with(writer, "CRLPublicationURLs", 0, 7, [])
    reader.Close.assert_called_once_with()


def test_template_creation_failure_retains_upstream_oid_registration(
    run: Any, directory: TemplateDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = directory.add

    def _deny_template(dn: str, values: dict[str, list[bytes]]) -> None:
        if values.get("objectClass") == [b"pKICertificateTemplate"]:
            raise OSError(5, "Template creation denied")
        original(dn, values)

    monkeypatch.setattr(directory, "add", _deny_template)
    result = run(
        "cs_template", {"name": "Custom", "source_template": "Web Server"}, failed=True
    )
    assert (
        result["changed"]
        and result["distinguished_name"] is None
        and result["template_oid"] is None
    )
    registrations = [
        dn
        for dn, values in directory.objects.items()
        if values.get("objectClass", [b""])[-1] == b"msPKI-Enterprise-Oid"
    ]
    assert len(registrations) == 1 and "CN=Custom," + TEMPLATES not in directory.objects
    # Upstream exposes no OID identity on this failure. The integration fixture
    # locates only its unique display name and removes the owned registration.
    assert directory.objects[registrations[0]]["displayName"] == [b"Custom"]
    directory.delete(registrations[0])
    assert registrations[0] not in directory.objects


def test_template_oid_delete_failure_warns_after_completed_unpublication(
    run: Any, directory: TemplateDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    created = run(
        "cs_template",
        {
            "name": "Custom",
            "source_template": "Web Server",
            "publish_to_ca": ["FirstCA"],
        },
    )
    original = directory.delete

    def _deny_registration(dn: str) -> None:
        if dn.endswith("," + OIDS):
            raise OSError(5, "OID removal denied")
        original(dn)

    monkeypatch.setattr(directory, "delete", _deny_registration)
    result = run("cs_template", {"name": "Custom", "state": "absent"})
    assert result["changed"] and "OID removal denied" in result["warnings"][0]
    assert created["distinguished_name"] not in directory.objects
    assert (
        b"Custom"
        not in directory.objects["CN=FirstCA," + ENROLLMENT]["certificateTemplates"]
    )
    assert directory.objects["CN=FirstCA," + ENROLLMENT]["certificateTemplates"] == [
        b"WebServer",
        b"ExistingTemplate",
    ]
