"""Exercise native topology public payloads against independent directory state."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Reuse only the low-level LDAP operation fixture, not its OU expected results.
# pylint: disable=protected-access,duplicate-code

import copy
import importlib
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable
from unittest.mock import Mock

import pytest

from tests.unit import test_ad_ou
from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module

CONFIG = "CN=Configuration," + test_ad_ou.BASE
SITES = "CN=Sites," + CONFIG
SUBNETS = "CN=Subnets," + SITES
IP_LINKS = "CN=IP,CN=Inter-Site Transports," + SITES
SMTP_LINKS = "CN=SMTP,CN=Inter-Site Transports," + SITES


class TopologyDirectory(test_ad_ou.Directory):
    """Model configuration-partition schema and server-maintained subtree renames."""

    def naming_context(self, name: str = "defaultNamingContext") -> str:
        """Expose configuration and schema partitions without conflating the domain.

        :param name: Requested directory naming context.
        :returns: Independent fixture partition DN.
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
        **flags: Any,
    ) -> list[dict[str, Any]]:
        """Supply topology attribute schema and otherwise use the native state model.

        :param base: Query base DN or GUID.
        :param scope: Native search scope.
        :param ldap_filter: LDAP search predicate.
        :param attributes: Requested attribute names.
        :param flags: Native server-control flags.
        :returns: Copied entries independent of payload result projection.
        """
        rows = super().search(base, scope, ldap_filter, attributes, **flags)
        if ldap_filter == "(objectClass=attributeSchema)":
            for name, syntax, single in (
                ("options", "2.5.5.9", True),
                ("cost", "2.5.5.9", True),
                ("replInterval", "2.5.5.9", True),
                ("siteList", "2.5.5.1", False),
                ("siteObject", "2.5.5.1", True),
                ("location", "2.5.5.12", True),
            ):
                rows.append(
                    {
                        "dn": "CN=" + name,
                        "attributes": {
                            "lDAPDisplayName": [name.encode()],
                            "attributeSyntax": [syntax.encode()],
                            "isSingleValued": [b"TRUE" if single else b"FALSE"],
                        },
                    }
                )
        return rows

    def rename(self, dn: str, rdn: str, parent: str) -> None:
        """Retain the child's relative DN when its parent is renamed.

        :param dn: Existing directory object.
        :param rdn: New relative distinguished name.
        :param parent: New parent container.
        :raises OSError: If the independent write-failure injection is active.
        """
        children = {
            key: copy.deepcopy(value)
            for key, value in self.objects.items()
            if key.endswith("," + dn)
        }
        super().rename(dn, rdn, parent)
        destination = rdn + "," + parent
        for key, value in children.items():
            del self.objects[key]
            self.objects[key[: -len(dn)] + destination] = value


@pytest.fixture(name="directory")
def topology_directory() -> TopologyDirectory:
    """Provide fresh observable directory state.

    :returns: Independent topology protocol fixture.
    """
    return TopologyDirectory()


@pytest.fixture(name="payloads")
def topology_payloads(
    monkeypatch: pytest.MonkeyPatch, directory: TopologyDirectory
) -> dict[str, ModuleType]:
    """Load public payloads, replacing only native directory and SDDL boundaries.

    :param monkeypatch: Scoped substitutions.
    :param directory: Independent directory state.
    :returns: Site, link and subnet JSON payloads.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(HELPER.parent))
    helper = importlib.import_module("legacy_ad_object")
    monkeypatch.setattr(helper, "LDAPConnection", Mock(return_value=directory))
    monkeypatch.setattr(
        helper, "security_descriptor_text", lambda value: value.decode()
    )
    monkeypatch.setattr(
        helper, "security_descriptor_bytes", lambda value: value.encode()
    )
    schema = importlib.import_module("legacy_ad_schema")
    monkeypatch.setattr(
        schema, "security_descriptor_text", lambda value: value.decode()
    )
    monkeypatch.setattr(
        schema, "security_descriptor_bytes", lambda value: value.encode()
    )
    return {
        kind: load_module(
            ROOT / "legacy_ad/plugins/modules" / (kind + ".py"), "tested_ad_" + kind
        )
        for kind in ("site", "site_link", "site_subnet")
    }


@pytest.fixture(name="run")
def payload_runner(
    payloads: dict[str, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[..., dict[str, Any]]:
    """Run a selected module through its public JSON process contract.

    :param payloads: Loaded target entry points.
    :param monkeypatch: Scoped argument-file substitution.
    :param tmp_path: Disposable argument-file location.
    :param capsys: Captured JSON output.
    :returns: Callable returning decoded successful or failed module results.
    """

    def _invoke(
        kind: str, values: dict[str, Any], failed: bool = False
    ) -> dict[str, Any]:
        argument_file = tmp_path / "arguments.json"
        argument_file.write_text(json.dumps(values), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", [kind + ".py", str(argument_file)])
        status, result = invoke_payload(payloads[kind], capsys)
        assert status == (1 if failed else 0), result
        return result

    return _invoke


def _sites(run: Any) -> None:
    for name in ("First", "Second", "Third"):
        run("site", {"name": name})


def test_site_public_lifecycle_children_settings_and_cleanup(
    run: Any, directory: TopologyDirectory
) -> None:
    request = {
        "name": "Branch",
        "description": "Branch office",
        "universal_group_caching_enabled": True,
        "automatic_inter_site_topology_generation_enabled": False,
        "_ansible_diff": True,
    }
    preview = run("site", dict(request, _ansible_check_mode=True))
    assert preview["changed"] and directory.objects == {}
    assert preview["distinguished_name"] == "CN=Branch," + SITES
    created = run("site", request)
    dn = created["distinguished_name"]
    assert created["changed"] and not run("site", request)["changed"]
    assert directory.objects[dn]["description"] == [b"Branch office"]
    assert (
        directory.objects["CN=Servers," + dn]["objectClass"][-1] == b"serversContainer"
    )
    assert directory.objects["CN=NTDS Site Settings," + dn]["options"] == [b"48"]
    assert created["diff"]["after"]["universal_group_caching_enabled"] is True
    writes = len(directory.writes)
    removed_preview = run(
        "site",
        {
            "identity": created["object_guid"],
            "state": "absent",
            "_ansible_check_mode": True,
        },
    )
    assert removed_preview["changed"] and len(directory.writes) == writes
    assert run("site", {"identity": created["object_guid"], "state": "absent"})[
        "changed"
    ]
    assert directory.objects == {}
    assert not run("site", {"name": "Branch", "state": "absent"})["changed"]


@pytest.mark.parametrize(
    "flag",
    [
        ("automatic_topology_generation_enabled", 1, True),
        ("automatic_inter_site_topology_generation_enabled", 16, True),
        ("universal_group_caching_enabled", 32, False),
    ],
)
@pytest.mark.parametrize("enabled", [True, False])
def test_site_flags_preserve_unrelated_bits_and_predict(
    run: Any,
    directory: TopologyDirectory,
    flag: tuple[str, int, bool],
    enabled: bool,
) -> None:
    option, mask, inverted = flag
    created = run("site", {"name": "Branch"})
    settings = "CN=NTDS Site Settings," + created["distinguished_name"]
    old = 0x800 | (0 if (not enabled if inverted else enabled) else mask)
    directory.objects[settings]["options"] = [str(old).encode()]
    wanted = (old | mask) if (not enabled if inverted else enabled) else (old & ~mask)
    request = {"name": "Branch", option: enabled, "_ansible_diff": True}
    preview = run("site", dict(request, _ansible_check_mode=True))
    assert preview["changed"] and directory.objects[settings]["options"] == [
        str(old).encode()
    ]
    changed = run("site", request)
    assert changed["changed"] and directory.objects[settings]["options"] == [
        str(wanted).encode()
    ]
    assert changed["diff"]["before"][option] is not enabled
    assert changed["diff"]["after"][option] is enabled
    assert not run("site", request)["changed"]


def test_site_guid_rename_retains_children_and_allows_options(
    run: Any, directory: TopologyDirectory
) -> None:
    created = run("site", {"name": "First"})
    updated = run(
        "site",
        {
            "identity": created["object_guid"],
            "name": "Renamed",
            "universal_group_caching_enabled": True,
        },
    )
    assert updated["changed"] and updated["object_guid"] == created["object_guid"]
    assert directory.objects["CN=NTDS Site Settings,CN=Renamed," + SITES][
        "options"
    ] == [b"32"]


def test_site_link_complete_public_lifecycle(
    run: Any, directory: TopologyDirectory
) -> None:
    _sites(run)
    request = {
        "name": "Branch Link",
        "sites_included": ["First", "Second"],
        "cost": 100,
        "replication_frequency": 15,
        "_ansible_diff": True,
    }
    writes = len(directory.writes)
    preview = run("site_link", dict(request, _ansible_check_mode=True))
    assert preview["changed"] and len(directory.writes) == writes
    assert preview["distinguished_name"] == "CN=Branch Link," + IP_LINKS
    created = run("site_link", request)
    dn = created["distinguished_name"]
    assert created["changed"] and not run("site_link", request)["changed"]
    assert directory.objects[dn]["cost"] == [b"100"]
    assert directory.objects[dn]["replInterval"] == [b"15"]
    assert set(directory.objects[dn]["siteList"]) == {
        ("CN=" + name + "," + SITES).encode() for name in ("First", "Second")
    }
    updated_request = {
        "identity": created["object_guid"],
        "cost": 200,
        "replication_frequency": 30,
        "sites_included": ["Third", "First"],
        "_ansible_diff": True,
    }
    predicted = run("site_link", dict(updated_request, _ansible_check_mode=True))
    assert predicted["changed"] and directory.objects[dn]["cost"] == [b"100"]
    updated = run("site_link", updated_request)
    assert updated["changed"] and not run("site_link", updated_request)["changed"]
    assert updated["diff"]["before"]["sites_included"] == ["First", "Second"]
    assert updated["diff"]["after"]["sites_included"] == ["First", "Third"]
    assert updated["diff"]["after"]["attributes"] == {}
    assert directory.objects[dn]["cost"] == [b"200"]
    assert run("site_link", {"identity": created["object_guid"], "state": "absent"})[
        "changed"
    ]
    assert not run("site_link", {"name": "Branch Link", "state": "absent"})["changed"]


def test_link_defaults_case_insensitive_site_membership_and_immutable_protocol(
    run: Any, directory: TopologyDirectory
) -> None:
    _sites(run)
    created = run(
        "site_link",
        {
            "name": "SMTP Link",
            "sites_included": ["First", "Second"],
            "intersite_transport_protocol": "SMTP",
        },
    )
    dn = created["distinguished_name"]
    assert dn == "CN=SMTP Link," + SMTP_LINKS
    assert directory.objects[dn]["cost"] == [b"100"]
    assert directory.objects[dn]["replInterval"] == [b"180"]
    repeated = run(
        "site_link",
        {
            "identity": created["object_guid"],
            "sites_included": ["second", "first"],
            "_ansible_diff": True,
        },
    )
    assert not repeated["changed"]
    assert repeated["warnings"] == [
        "intersite_transport_protocol cannot be changed after creation "
        "(current: SMTP, requested: IP)"
    ]
    assert repeated["diff"]["after"]["intersite_transport_protocol"] == "SMTP"


def test_link_creation_defaults_preserve_explicit_custom_numeric_attributes(
    run: Any, directory: TopologyDirectory
) -> None:
    _sites(run)
    request = {
        "name": "Custom Link",
        "sites_included": ["First", "Second"],
        "attributes": {"set": {"cost": 250, "replInterval": 45}},
        "_ansible_diff": True,
    }
    result = run("site_link", request)
    entry = directory.objects[result["distinguished_name"]]
    assert entry["cost"] == [b"250"] and entry["replInterval"] == [b"45"]
    assert result["diff"]["after"]["attributes"] == {
        "cost": [250],
        "replInterval": [45],
    }
    assert not run("site_link", request)["changed"]


@pytest.mark.parametrize(
    "sites", [None, [], ["First"], ["First", "first"], ["First", "Missing"]]
)
def test_link_invalid_membership_fails_before_writes(
    run: Any, directory: TopologyDirectory, sites: list[str] | None
) -> None:
    _sites(run)
    writes = len(directory.writes)
    result = run("site_link", {"name": "Link", "sites_included": sites}, failed=True)
    assert not result["changed"] and len(directory.writes) == writes


@pytest.mark.parametrize("name", ["10.10.0.0/16", "10.10.3.4/16", "2001:db8:1234::/48"])
def test_subnet_public_lifecycle_association_location_clear_and_cleanup(
    run: Any, directory: TopologyDirectory, name: str
) -> None:
    _sites(run)
    request = {
        "name": name,
        "site": "First",
        "location": "London",
        "description": "Subnet",
        "_ansible_diff": True,
    }
    preview = run("site_subnet", dict(request, _ansible_check_mode=True))
    dn = "CN=" + name + "," + SUBNETS
    assert preview["changed"] and dn not in directory.objects
    created = run("site_subnet", request)
    assert created["changed"] and not run("site_subnet", request)["changed"]
    assert directory.objects[dn]["siteObject"] == [("CN=First," + SITES).encode()]
    update = {
        "identity": created["object_guid"],
        "site": "Second",
        "location": "New York",
        "_ansible_diff": True,
    }
    predicted = run("site_subnet", dict(update, _ansible_check_mode=True))
    assert predicted["changed"] and directory.objects[dn]["location"] == [b"London"]
    updated = run("site_subnet", update)
    assert updated["changed"] and not run("site_subnet", update)["changed"]
    assert updated["diff"]["before"]["site"] == "First"
    assert updated["diff"]["after"]["site"] == "Second"
    assert run(
        "site_subnet", {"identity": created["object_guid"], "site": "", "location": ""}
    )["changed"]
    assert (
        "siteObject" not in directory.objects[dn]
        and "location" not in directory.objects[dn]
    )
    assert not run("site_subnet", {"name": name, "site": "", "location": ""})["changed"]
    assert run("site_subnet", {"identity": created["object_guid"], "state": "absent"})[
        "changed"
    ]
    assert not run("site_subnet", {"name": name, "state": "absent"})["changed"]


def test_subnet_omitted_site_preserves_association(
    run: Any, directory: TopologyDirectory
) -> None:
    _sites(run)
    created = run("site_subnet", {"name": "10.2.0.0/16", "site": "First"})
    run("site_subnet", {"identity": created["object_guid"], "location": "Changed"})
    assert directory.objects[created["distinguished_name"]]["siteObject"] == [
        ("CN=First," + SITES).encode()
    ]
    unassigned = run("site_subnet", {"name": "10.3.0.0/16"})
    assert "siteObject" not in directory.objects[unassigned["distinguished_name"]]
    assert not run("site_subnet", {"name": "10.3.0.0/16"})["changed"]


@pytest.mark.parametrize(
    "name,site",
    [("not-a-subnet", None), ("10.2.3.4/33", None), ("10.2.0.0/16", "Missing")],
)
def test_subnet_invalid_input_fails_before_writes(
    run: Any, directory: TopologyDirectory, name: str, site: str | None
) -> None:
    result = run("site_subnet", {"name": name, "site": site}, failed=True)
    assert not result["changed"] and directory.objects == {}


@pytest.mark.parametrize("kind", ["site", "site_link", "site_subnet"])
def test_wrong_class_identity_cannot_delete_other_object(
    run: Any, directory: TopologyDirectory, kind: str
) -> None:
    directory.add(
        "CN=Other," + test_ad_ou.BASE, {"objectClass": [b"container"], "cn": [b"Other"]}
    )
    result = run(kind, {"identity": "CN=Other," + test_ad_ou.BASE, "state": "absent"})
    assert not result["changed"] and "CN=Other," + test_ad_ou.BASE in directory.objects


def test_partial_site_child_failure_retains_completed_creation(
    run: Any, directory: TopologyDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = directory.add

    def fail_child(dn: str, values: dict[str, list[bytes]]) -> None:
        if dn.startswith("CN=Servers,"):
            raise OSError(5, "Denied Servers child creation")
        original(dn, values)

    monkeypatch.setattr(directory, "add", fail_child)
    result = run("site", {"name": "Branch"}, failed=True)
    assert (
        result["changed"]
        and result["object_guid"] != "00000000-0000-0000-0000-000000000000"
    )
    assert "CN=Branch," + SITES in directory.objects
    monkeypatch.setattr(directory, "add", original)
    recovered = run("site", {"name": "Branch"})
    assert recovered["changed"] and recovered["object_guid"] == result["object_guid"]
    assert "CN=Servers,CN=Branch," + SITES in directory.objects
    assert "CN=NTDS Site Settings,CN=Branch," + SITES in directory.objects
    assert not run("site", {"name": "Branch"})["changed"]


def test_site_child_type_collision_fails_before_modifying_the_site(
    run: Any, directory: TopologyDirectory
) -> None:
    created = run("site", {"name": "Branch", "description": "Original"})
    child_dn = "CN=NTDS Site Settings," + created["distinguished_name"]
    directory.objects[child_dn]["objectClass"] = [b"top", b"container"]
    writes = len(directory.writes)
    result = run(
        "site",
        {
            "name": "Branch",
            "description": "Changed",
            "universal_group_caching_enabled": True,
        },
        failed=True,
    )
    assert not result["changed"] and len(directory.writes) == writes
    assert directory.objects[created["distinguished_name"]]["description"] == [
        b"Original"
    ]
    assert directory.objects[child_dn]["objectClass"][-1] == b"container"


@pytest.mark.parametrize(
    "kind,values",
    [
        ("site", {"name": "Branch", "universal_group_caching_enabled": "nonsense"}),
        ("site_link", {"name": "Link", "cost": "nonsense"}),
        ("site_link", {"name": "Link", "replication_frequency": 1.5}),
        ("site_link", {"name": "Link", "intersite_transport_protocol": "HTTP"}),
        ("site_subnet", {"name": "10.0.0.0/8", "bogus": True}),
    ],
)
def test_argument_failures_are_actionable_and_write_free(
    run: Any, directory: TopologyDirectory, kind: str, values: dict[str, Any]
) -> None:
    result = run(kind, values, failed=True)
    assert result["msg"] and not result["changed"] and directory.writes == []


@pytest.mark.parametrize("kind", ["site", "site_link", "site_subnet"])
def test_common_custom_attributes_and_protection_remain_public_contracts(
    run: Any, directory: TopologyDirectory, kind: str
) -> None:
    _sites(run)
    request: dict[str, Any] = {
        "name": "10.8.0.0/16" if kind == "site_subnet" else "Custom",
        "protect_from_deletion": True,
        "attributes": {"set": {"testMultiString": ["one", "two"]}},
        "_ansible_diff": True,
    }
    if kind == "site_link":
        request["sites_included"] = ["First", "Second"]
    created = run(kind, request)
    dn = created["distinguished_name"]
    assert directory.objects[dn]["testMultiString"] == [b"one", b"two"]
    assert b"(D;;SDDT;;;WD)" in directory.objects[dn]["nTSecurityDescriptor"][0]
    assert created["diff"]["after"]["attributes"]["testMultiString"] == ["one", "two"]
    assert not run(kind, request)["changed"]
    assert run(kind, {"identity": created["object_guid"], "state": "absent"})["changed"]
    assert dn not in directory.objects


@pytest.mark.parametrize("kind", ["site", "site_link", "site_subnet"])
def test_credentials_are_redacted_everywhere_in_diff_and_invocation(
    run: Any, kind: str
) -> None:
    _sites(run)
    secret = "fixture-domain-password"
    request: dict[str, Any] = {
        "name": "10.9.0.0/16" if kind == "site_subnet" else "Secret",
        "description": secret,
        "domain_username": "fixture-user",
        "domain_password": secret,
        "_ansible_diff": True,
        "_ansible_inject_invocation": True,
    }
    if kind == "site_link":
        request["sites_included"] = ["First", "Second"]
    result = run(kind, request)
    assert secret not in json.dumps(result)
    assert (
        result["diff"]["after"]["description"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    )
    assert (
        result["invocation"]["module_args"]["domain_password"]
        == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    )


@pytest.mark.parametrize("kind", ["site", "site_link", "site_subnet"])
def test_credentials_are_redacted_on_attribute_validation_failure(
    run: Any, directory: TopologyDirectory, kind: str
) -> None:
    _sites(run)
    secret = "fixture-secret-attribute"
    request: dict[str, Any] = {
        "name": "10.9.0.0/16" if kind == "site_subnet" else "Failure",
        "attributes": {"set": {secret: "value"}},
        "domain_credentials": [{"username": "fixture-user", "password": secret}],
        "_ansible_diff": True,
    }
    if kind == "site_link":
        request["sites_included"] = ["First", "Second"]
    writes = len(directory.writes)
    result = run(kind, request, failed=True)
    assert secret not in json.dumps(result)
    assert "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER" in result["msg"]
    assert len(directory.writes) == writes
