# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage forest, child/tree, replica and demotion workflows explicitly."""

import legacy_ad_domain_native as native  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    read_arguments,
)

DOMAIN_PARAMETERS = (
    "create_dns_delegation",
    "database_path",
    "dns_domain_name",
    "domain_mode",
    "domain_netbios_name",
    "forest_mode",
    "install_dns",
    "log_path",
    "reboot",
    "reboot_timeout",
    "safe_mode_password",
    "sysvol_path",
)
CHILD_PARAMETERS = (
    "create_dns_delegation",
    "database_path",
    "dns_domain_name",
    "domain_admin_password",
    "domain_admin_user",
    "domain_mode",
    "domain_type",
    "install_dns",
    "log_path",
    "parent_domain_name",
    "reboot",
    "reboot_timeout",
    "replication_source_dc",
    "safe_mode_password",
    "site_name",
    "sysvol_path",
)
CONTROLLER_PARAMETERS = (
    "database_path",
    "dns_domain_name",
    "domain_admin_password",
    "domain_admin_user",
    "domain_log_path",
    "install_dns",
    "install_media_path",
    "local_admin_password",
    "read_only",
    "reboot",
    "reboot_timeout",
    "replication_source_dc",
    "safe_mode_password",
    "site_name",
    "state",
    "sysvol_path",
)
_PATHS = (
    "database_path",
    "log_path",
    "domain_log_path",
    "install_media_path",
    "sysvol_path",
)


def _arguments(name, parameters, required):
    values = read_arguments(parameters, "sustainablelobster.legacy_ad." + name)
    arguments = {}
    for parameter in parameters:
        value = values.get(parameter)
        if parameter in ("install_dns", "create_dns_delegation", "read_only", "reboot"):
            arguments[parameter] = None if value is None else as_bool(value, parameter)
        elif parameter in _PATHS:
            arguments[parameter] = as_path(value, parameter)
        elif parameter != "reboot_timeout":
            arguments[parameter] = as_string(value, parameter)
    for parameter in required:
        if arguments[parameter] is None:
            raise ValueError(parameter + " is required")
    arguments["check_mode"] = as_bool(
        values.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    arguments["reboot"] = arguments["reboot"] or False
    arguments["complete_legacy_levels"] = as_bool(
        values.get("_ansible_legacy_ad_complete_promotion", False),
        "_ansible_legacy_ad_complete_promotion",
    )
    return arguments


def domain_arguments():
    """Validate forest-creation parameters before any Windows operation.

    :returns: Normalized released domain options.
    :rtype: dict
    :raises ValueError: Required parameters, paths or Boolean values are invalid.
    """
    arguments = _arguments(
        "domain", DOMAIN_PARAMETERS, ("dns_domain_name", "safe_mode_password")
    )
    if arguments["domain_netbios_name"] and len(arguments["domain_netbios_name"]) > 15:
        raise ValueError(
            "The parameter 'domain_netbios_name' should not exceed 15 characters in length"
        )
    if arguments["install_dns"] is None:
        arguments["install_dns"] = True
    return arguments


def child_arguments():
    """Validate child/tree creation parameters before any Windows operation.

    :returns: Normalized released domain_child options.
    :rtype: dict
    :raises ValueError: Required parameters or domain-type combinations are invalid.
    """
    arguments = _arguments(
        "domain_child",
        CHILD_PARAMETERS,
        ("domain_admin_user", "domain_admin_password", "safe_mode_password"),
    )
    arguments["domain_type"] = (
        "child"
        if arguments["domain_type"] is None
        else arguments["domain_type"].lower()
    )
    if arguments["domain_type"] not in ("child", "tree"):
        raise ValueError("domain_type must be child or tree")
    if arguments["domain_type"] == "child" and arguments["parent_domain_name"]:
        raise ValueError("parent_domain_name must not be set when domain_type=child")
    if arguments["domain_type"] == "tree" and arguments["parent_domain_name"] is None:
        raise ValueError("parent_domain_name is required when domain_type=tree")
    return arguments


def controller_arguments():
    """Validate replica promotion/demotion parameters before role discovery.

    :returns: Normalized released domain_controller options.
    :rtype: dict
    :raises ValueError: Required parameters or the desired state are invalid.
    """
    arguments = _arguments(
        "domain_controller",
        CONTROLLER_PARAMETERS,
        ("domain_admin_user", "domain_admin_password", "state"),
    )
    arguments["state"] = arguments["state"].lower()
    if arguments["state"] not in ("domain_controller", "member_server"):
        raise ValueError("state must be domain_controller or member_server")
    required = (
        ("dns_domain_name", "safe_mode_password")
        if arguments["state"] == "domain_controller"
        else ("local_admin_password",)
    )
    for name in required:
        if arguments[name] is None:
            raise ValueError(name + " is required when state=" + arguments["state"])
    arguments["read_only"] = arguments["read_only"] or False
    return arguments


def _base_settings(engine):
    settings = {"RebootOnSuccess": "NoAndNoPromptEither"}
    if engine.supports("RebootOnCompletion"):
        settings["RebootOnCompletion"] = "No"
    return settings


def _credentials(arguments):
    username = arguments["domain_admin_user"]
    domain = None
    if "\\" in username:
        domain, username = username.split("\\", 1)
    elif "@" in username:
        username, domain = username.rsplit("@", 1)
    settings = {"UserName": username, "Password": arguments["domain_admin_password"]}
    if domain:
        settings["UserDomain"] = domain
    return settings


def _optional_settings(arguments, engine, log_name="log_path"):
    settings = {}
    for parameter, field in (
        ("database_path", "DatabasePath"),
        (log_name, "LogPath"),
        ("sysvol_path", "SYSVOLPath"),
        ("site_name", "SiteName"),
        ("replication_source_dc", "ReplicationSourceDC"),
        ("install_media_path", "ReplicationSourcePath"),
    ):
        if arguments.get(parameter):
            settings[field] = arguments[parameter]
    for parameter, field in (
        ("install_dns", "InstallDNS"),
        ("create_dns_delegation", "CreateDNSDelegation"),
    ):
        if arguments.get(parameter) is not None:
            if (
                field == "InstallDNS"
                and not engine.supports(field)
                and engine.supports("AutoConfigDNS")
            ):
                field = "AutoConfigDNS"
                if arguments[parameter] and "forest_mode" in arguments:
                    # The older new-forest workflow must request the local DNS
                    # installation rather than assume an existing DNS service.
                    settings["DNSOnNetwork"] = "No"
            settings[field] = "Yes" if arguments[parameter] else "No"
    return settings


def _domain_level(arguments, engine):
    if not engine.supports("DomainLevel"):
        for name in ("domain_mode", "forest_mode"):
            value = native.mode_value(arguments.get(name))
            if value not in (None, 2):
                raise ValueError(
                    "The installed legacy promotion engine supports only "
                    "normal Win2003 " + name + "."
                )
            if value is not None and not arguments["reboot"]:
                raise ValueError(
                    "The installed legacy promotion engine needs reboot=true "
                    "to complete the requested " + name + "."
                )
        return {}
    value = engine.functional_level(arguments.get("domain_mode"), "DomainLevel")
    return {"DomainLevel": value} if value is not None else {}


def _run_operation(engine, settings, arguments, result):
    engine.validate(settings)
    if arguments["check_mode"]:
        result.update(changed=True, reboot_required=True)
        return
    if settings.get("AutoConfigDNS") == "Yes":
        engine.ensure_dns_installed(result)
    try:
        code, output = engine.run(settings)
    except OSError as error:
        if getattr(error, "promotion_completed", False):
            result.update(changed=True, reboot_required=True)
        raise
    if code not in (1, 2, 3, 4):
        if code in (15, 19):
            result.update(reboot_required=True, _do_action_reboot=True)
        raise ValueError(
            "Failed to run DCPromo, exited with {0}: {1}".format(code, output.strip())
        )
    result.update(changed=True, reboot_required=True)
    try:
        native.start_netlogon()
    except (OSError, ValueError) as error:
        result.setdefault("warnings", []).append(
            "Failed to start the Netlogon service after changing the host role; "
            "reconnecting may require a manual reboot: " + str(error)
        )
    if code in (3, 4):
        result.setdefault("warnings", []).append(
            "The native promotion engine completed with a noncritical warning: "
            + output.strip()
        )
    if "NewDomain" in settings and not engine.supports("DomainLevel"):
        if arguments["reboot"]:
            result["_legacy_ad_complete_promotion"] = True
        else:
            default = (
                "level-0 domain and forest"
                if settings["NewDomain"] == "Forest"
                else "domain at its native functional-level default"
            )
            result.setdefault("warnings", []).append(
                "The legacy promotion engine creates its " + default + ". "
                "Use reboot=true when creating the domain to finish "
                "normal Windows 2003 functional levels automatically."
            )


def manage_domain(arguments, result):
    """Create a new forest only when the released domain test requires it.

    :param arguments: Normalized domain-module options.
    :type arguments: dict
    :param result: Mutable result retaining successful partial changes.
    :type result: dict
    :raises ValueError: The requested promotion settings are unsupported.
    :raises OSError: Native discovery, promotion or cleanup fails.
    """
    if arguments["complete_legacy_levels"]:
        native.complete_legacy_levels(arguments["dns_domain_name"], True, result)
        return
    host_is_dc = native.is_domain_controller()
    if native.forest_exists(arguments["dns_domain_name"]) and host_is_dc:
        return
    engine = native.PromotionEngine()
    settings = _base_settings(engine)
    settings.update(
        ReplicaOrNewDomain="Domain",
        NewDomain="Forest",
        NewDomainDNSName=arguments["dns_domain_name"],
        SafeModeAdminPassword=arguments["safe_mode_password"],
    )
    settings.update(_optional_settings(arguments, engine))
    settings.update(_domain_level(arguments, engine))
    if arguments["domain_netbios_name"]:
        settings["DomainNetbiosName"] = arguments["domain_netbios_name"]
    if engine.supports("ForestLevel"):
        value = engine.functional_level(arguments["forest_mode"], "ForestLevel")
        if value is not None:
            settings["ForestLevel"] = value
    elif (
        engine.supports("DomainLevel")
        and native.mode_value(arguments["forest_mode"]) is not None
    ):
        raise ValueError(
            "The installed promotion engine does not support the requested forest_mode."
        )
    if (
        "DomainLevel" in settings
        and "ForestLevel" in settings
        and int(settings["DomainLevel"]) < int(settings["ForestLevel"])
    ):
        raise ValueError("domain_mode cannot be lower than forest_mode.")
    _run_operation(engine, settings, arguments, result)


def manage_child(arguments, result):
    """Create one child or tree domain while refusing a different active DC role.

    :param arguments: Normalized domain_child options.
    :type arguments: dict
    :param result: Mutable result retaining successful partial changes.
    :type result: dict
    :raises ValueError: The host's domain or requested settings conflict.
    :raises OSError: Native discovery, promotion or cleanup fails.
    """
    if arguments["complete_legacy_levels"]:
        native.complete_legacy_levels(arguments["dns_domain_name"], False, result)
        return
    current = native.current_state()
    if current["role"] in (4, 5):
        if current["domain"].lower() != (arguments["dns_domain_name"] or "").lower():
            raise ValueError(
                "Host is already a domain controller in another domain "
                + current["domain"]
            )
        return
    dns_name = arguments["dns_domain_name"]
    if not dns_name or arguments["domain_type"] == "child" and "." not in dns_name:
        raise ValueError(
            "dns_domain_name must name a complete child or tree DNS domain."
        )
    engine = native.PromotionEngine()
    settings = _base_settings(engine)
    settings.update(_credentials(arguments))
    settings.update(
        ReplicaOrNewDomain="Domain",
        NewDomain=arguments["domain_type"].title(),
        NewDomainDNSName=dns_name,
        SafeModeAdminPassword=arguments["safe_mode_password"],
    )
    if arguments["domain_type"] == "child":
        child, parent = dns_name.split(".", 1)
        settings.update(ChildName=child, ParentDomainDNSName=parent)
    else:
        settings["ParentDomainDNSName"] = arguments["parent_domain_name"]
    settings.update(_optional_settings(arguments, engine))
    settings.update(_domain_level(arguments, engine))
    _run_operation(engine, settings, arguments, result)


def manage_controller(arguments, result):
    """Promote a replica or demote a controller after an explicit FSMO safety check.

    :param arguments: Normalized domain_controller options.
    :type arguments: dict
    :param result: Mutable result retaining successful partial changes.
    :type result: dict
    :raises ValueError: Domain identity, credentials, roles or settings conflict.
    :raises OSError: Native discovery, promotion or cleanup fails.
    """
    current = native.current_state()
    is_controller = current["role"] in (4, 5)
    if arguments["state"] == "member_server" and not is_controller:
        return
    if arguments["state"] == "domain_controller":
        if (
            "\\" not in arguments["domain_admin_user"]
            and "@" not in arguments["domain_admin_user"]
        ):
            raise ValueError(
                "domain_admin_user must be in domain\\user or user@domain.com format"
            )
        if is_controller:
            if current["domain"].lower() != arguments["dns_domain_name"].lower():
                raise ValueError(
                    "The host "
                    + current["hostname"]
                    + " is a domain controller for the domain "
                    + current["domain"]
                    + "; changing DC domains is not implemented"
                )
            return
        engine = native.PromotionEngine()
        settings = _base_settings(engine)
        settings.update(_credentials(arguments))
        settings.update(
            ReplicaOrNewDomain=(
                "ReadOnlyReplica" if arguments["read_only"] else "Replica"
            ),
            ReplicaDomainDNSName=arguments["dns_domain_name"],
            SafeModeAdminPassword=arguments["safe_mode_password"],
        )
        if arguments["read_only"] and "readonlyreplica" not in engine.help.lower():
            raise ValueError(
                "The installed promotion engine does not support a read-only replica."
            )
        settings.update(_optional_settings(arguments, engine, "domain_log_path"))
    else:
        roles = native.assigned_roles(current["hostname"])
        if roles:
            raise ValueError(
                "This domain controller has operation master role(s) ("
                + ", ".join(roles)
                + ") assigned; they must be moved to other DCs before demotion"
            )
        engine = native.PromotionEngine(demotion=True)
        settings = _base_settings(engine)
        settings.update(_credentials(arguments))
        settings.update(
            AdministratorPassword=arguments["local_admin_password"],
            IsLastDCInDomain="No",
        )
    _run_operation(engine, settings, arguments, result)
