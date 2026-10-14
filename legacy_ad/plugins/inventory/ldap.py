"""Build controller inventory from directory objects using upstream's LDAP client."""

# Copyright: (c) 2023, Ansible Project
# Copyright 2026 sustainablelobster
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

import base64
import typing as t

# Ansible does not distribute typing metadata for its controller interfaces.
from ansible.errors import AnsibleError  # type: ignore[import-untyped]
from ansible.inventory.data import InventoryData  # type: ignore[import-untyped]
from ansible.module_utils.basic import (  # type: ignore[import-untyped]
    missing_required_lib,
)
from ansible.parsing.dataloader import DataLoader  # type: ignore[import-untyped]
from ansible.plugins.inventory import (  # type: ignore[import-untyped]
    BaseInventoryPlugin,
    Constructable,
)
from ansible.template import trust_as_template  # type: ignore[import-untyped]
from ansible.utils.unsafe_proxy import wrap_var  # type: ignore[import-untyped]

_ldap_import_error: Exception | None = None
try:
    import sansldap

    from ..plugin_utils._ldap import create_ldap_connection
    from ..plugin_utils._ldap.laps import LAPSDecryptor
    from ..plugin_utils._ldap.schema import LDAPSchema

    HAS_LDAP = True
# Preserve the complete failure when an optional LDAP package cannot initialize.
except Exception as e:  # pylint: disable=broad-exception-caught
    HAS_LDAP = False
    _ldap_import_error = e

DOCUMENTATION = r"""
name: ldap
author: Jordan Borean (@jborean93)
short_description: Inventory plugin for Active Directory
version_added: "1.0.0"
description:
- Inventory plugin for Active Directory or other LDAP sources.
- Uses a YAML configuration file ending with
  C(sustainablelobster.legacy_ad.ldap.yml) or
  C(sustainablelobster.legacy_ad.ldap.yaml). The upstream
  C(microsoft.ad.ldap.yml) and C(microsoft.ad.ldap.yaml) suffixes are also
  accepted; select C(sustainablelobster.legacy_ad.ldap) as the C(plugin).
- Each host that is added will set the C(inventory_hostname) to the C(name) of
  the LDAP computer object and C(ansible_host) to the value of the
  C(dNSHostName) LDAP attribute if set. If the C(dNSHostName) attribute is not
  set on the computer object then C(ansible_host) is not set. See
  L(LDAP inventory hostname,https://docs.ansible.com/projects/ansible/latest/collections/microsoft/ad/docsite/guide_ldap_inventory.html)
  for more information on how these values are set and how to adjust them.
- The host fact C(microsoft_ad_distinguished_name) will also be set to the
  distinguished name of the host that was used to derive the host entry.
- Any other fact that is needed, needs to be defined in the I(attributes)
  option.
options:
  attributes:
    description:
    - The LDAP attributes to retrieve.
    - The keys specified are the LDAP attributes requested and the values for
      each attribute is a dictionary that reflects what host var to set it to
      and how.
    - Each key of the inner dictionary value is the host variable name to set
      and the value is the template to use to derive the value. If no value is
      explicitly set then it will use the coerced value as returned from the
      LDAP attribute.
    - Attributes that are denoted as single value in the LDAP schema are
      returned as that single value, multi valued attributes are returned as a
      list of values.
    - See L(LDAP inventory attributes,https://docs.ansible.com/projects/ansible/latest/collections/microsoft/ad/docsite/guide_ldap_inventory.html)
      for more information.
    default: {}
    type: dict
  filter:
    description:
    - The LDAP filter string used to query the computer objects.
    - By default, this will be combined with the filter
      "(objectCategory=computer)". Use I(filter_without_computer) to override
      this behavior and have I(filter) be the only filter used.
    type: str
  filter_without_computer:
    description:
    - Will not combine the I(filter) value with the default filter
      "(objectCategory=computer)".
    - In most cases this should be C(false) but can be set to C(true) to have
      the I(filter) value specified be the only filter used.
    type: bool
    default: false
    version_added: "1.0.0"
  search_base:
    description:
    - The LDAP search base to find the computer objects in.
    - Defaults to the C(defaultNamingContext) of the Active Directory server
      if not specified.
    - If searching a larger Active Directory database, it is recommended to
      narrow the search base to speed up the queries.
    type: str
  search_scope:
    description:
    - The scope of the LDAP search to perform.
    - C(base) will search only the current path or object specified by
      I(search_base). This is typically not useful for inventory plugins.
    - C(one_level) will search only the immediate child objects in
      I(search_base).
    - C(subtree) will search the immediate child objects and any nested
      objects in I(search_base).
    choices:
    - base
    - one_level
    - subtree
    default: subtree
    type: str
notes:
- See L(LDAP inventory,https://docs.ansible.com/projects/ansible/latest/collections/microsoft/ad/docsite/guide_ldap_inventory.html)
  for more details on how to use this inventory plugin.
- See L(LAPS,https://docs.ansible.com/projects/ansible/latest/collections/microsoft/ad/docsite/guide_ldap_inventory.html)
  for more details on how this plugin can retrieve the LAPS password
  information.
- This plugin is a tech preview and the module options are subject to change
  based on feedback received.
- Unless specified otherwise in the option description, the value specified in
  the config file is used as is. Only the LDAP connection options allow using
  a Jinja2 template.
extends_documentation_fragment:
- constructed
- sustainablelobster.legacy_ad.ldap_connection
"""

EXAMPLES = r"""
# Save as hosts.sustainablelobster.legacy_ad.ldap.yml.
# The original hosts.microsoft.ad.ldap.yml suffix is also accepted.
plugin: sustainablelobster.legacy_ad.ldap

server: dc01.domain.example
auth_protocol: ntlm
username: '{{ lookup("ansible.builtin.env", "LDAP_USERNAME") }}'
password: '{{ lookup("ansible.builtin.env", "LDAP_PASSWORD") }}'
encrypt: true

# Add tls_mode: ldaps and ca_cert: /path/to/ca.pem to use verified TLS.
# Set port: 3268 to query the global catalog instead of the default LDAP port.
# For Kerberos, set auth_protocol: kerberos after configuring its requirements.

search_base: OU=Workstations,DC=domain,DC=example
filter: (dNSHostName=*)
attributes:
  name:
    directory_name:
  objectSid:
    computer_sid:
  pwdLastSet:
    password_last_set: this | sustainablelobster.legacy_ad.as_datetime
  comment:
    host_comment:
  memberOf:
    computer_membership: >-
      this | sustainablelobster.legacy_ad.parse_dn | map(attribute="0.1")
  location:

compose:
  inventory_hostname: directory_name | lower
groups:
  windows: true
  production: '"Production Group" in computer_membership'
keyed_groups:
  - key: location | default(omit)
    prefix: site
    default_value: unknown
"""


# Both Ansible base classes contribute required loader and constructed behavior.
class InventoryModule(  # pylint: disable=too-many-ancestors
    BaseInventoryPlugin, Constructable  # type: ignore[misc]
):
    """Preserve the LDAP inventory interface under the legacy collection name."""

    NAME = "sustainablelobster.legacy_ad.ldap"

    def verify_file(self, path: str) -> bool:
        """Accept existing readable files with either supported inventory suffix.

        :param path: Inventory source file path.
        :returns: Whether this plugin recognizes the source file.
        """
        if super().verify_file(path):
            return path.endswith(
                (
                    "sustainablelobster.legacy_ad.ldap.yml",
                    "sustainablelobster.legacy_ad.ldap.yaml",
                    "microsoft.ad.ldap.yml",
                    "microsoft.ad.ldap.yaml",
                )
            )

        return False

    # Ansible's hook arguments and one live LDAP search account for these locals.
    def parse(  # pylint: disable=too-many-locals
        self,
        inventory: InventoryData,
        loader: DataLoader,
        path: str,
        cache: bool = True,
    ) -> None:
        """Populate Ansible hosts and groups from an LDAP directory search.

        :param inventory: Ansible inventory receiving hosts, variables, and groups.
        :param loader: Ansible loader for configuration and templating.
        :param path: Inventory YAML source path.
        :param cache: Ansible inventory cache flag.
        :raises AnsibleError: Dependencies or configured strict templates fail.
        """
        super().parse(inventory, loader, path, cache)
        self.set_options()
        self._read_config_data(path)

        if not HAS_LDAP:
            msg = missing_required_lib(
                "sansldap and pyspnego",
                url="https://pypi.org/project/sansldap/ and https://pypi.org/project/pyspnego/",
                reason="for ldap lookups",
            )
            raise AnsibleError(f"{msg}: {_ldap_import_error}") from _ldap_import_error

        custom_attributes = self._get_custom_attributes()
        attributes = {"name", "dnshostname"}.union(a.lower() for a in custom_attributes)
        inventory_hostname = self.get_option("compose").pop("inventory_hostname", None)
        if inventory_hostname:
            custom_attributes["inventory_hostname"] = {
                "inventory_hostname": inventory_hostname
            }
        connection_options = self._connection_options()
        laps_decryptor = LAPSDecryptor(**connection_options)
        with create_ldap_connection(**connection_options) as client:
            schema = LDAPSchema.load_schema(client)
            for dn, info in client.search(
                filter=self._search_filter(),
                attributes=list(attributes),
                search_base=self.get_option("search_base"),
                search_scope={
                    "base": sansldap.SearchScope.BASE,
                    "one_level": sansldap.SearchScope.ONE_LEVEL,
                    "subtree": sansldap.SearchScope.SUBTREE,
                }[self.get_option("search_scope")],
            ).items():
                host_name, host_vars = self._host_variables(
                    dn, info, custom_attributes, schema, laps_decryptor
                )
                self._add_directory_host(host_name, host_vars)

    def _search_filter(self) -> sansldap.LDAPFilter:
        computer_filter = sansldap.FilterEquality("objectCategory", b"computer")
        configured = self.get_option("filter")
        if not configured:
            return computer_filter
        custom_filter = sansldap.LDAPFilter.from_string(configured)
        if self.get_option("filter_without_computer"):
            return custom_filter
        return sansldap.FilterAnd(filters=[computer_filter, custom_filter])

    def _connection_options(self) -> t.Dict[str, t.Any]:
        connection_options: t.Dict[str, t.Any] = self.get_options()
        # Only connection fields are templatable in upstream's inventory contract.
        template_fields = {
            "auth_protocol",
            "ca_cert",
            "cert_validation",
            "certificate",
            "certificate_key",
            "certificate_password",
            "connection_timeout",
            "domain_realm",
            "encrypt",
            "password",
            "port",
            "server",
            "tls_mode",
            "username",
        }
        for option_name, option_value in connection_options.items():
            if option_name in template_fields and self.templar.is_template(
                option_value
            ):
                self.display.vvv(f"Templating option {option_name}")
                connection_options[option_name] = self.templar.template(
                    variable=option_value,
                )

        return connection_options

    # Keep the host entry, schema, decoder, and conversion locals together.
    def _host_variables(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
        self,
        dn: str,
        info: t.Dict[str, t.List[bytes]],
        custom_attributes: t.Dict[str, t.Dict[str, str]],
        schema: LDAPSchema,
        laps_decryptor: LAPSDecryptor,
    ) -> t.Tuple[str, t.Dict[str, t.Any]]:
        insensitive_info = {name.lower(): values for name, values in info.items()}
        host_name = insensitive_info["name"][0].decode("utf-8")
        host_vars: t.Dict[str, t.Any] = {"microsoft_ad_distinguished_name": dn}
        dns_host_name = insensitive_info.get("dnshostname")
        if dns_host_name:
            host_vars["ansible_host"] = dns_host_name[0].decode("utf-8")

        for name, var_info in custom_attributes.items():
            raw_values = insensitive_info.get(name.lower(), [])
            host_vars["raw"] = wrap_var(
                [base64.b64encode(raw).decode() for raw in raw_values]
            )
            if name.lower() == "mslaps-encryptedpassword" and raw_values:
                host_vars["this"] = wrap_var(laps_decryptor.decrypt(raw_values[0]))
            else:
                host_vars["this"] = wrap_var(schema.cast_object(name, raw_values))
            for var_name, expression in var_info.items():
                try:
                    host_vars[var_name] = self._compose(
                        trust_as_template(expression), host_vars
                    )
                # The strict option controls errors from arbitrary configured templates.
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    if self.get_option("strict"):
                        raise AnsibleError(
                            f"Could not set {var_name} for host {host_name}: {exc}"
                        ) from exc
            host_vars.pop("raw")
            host_vars.pop("this")
        return host_name, host_vars

    def _add_directory_host(
        self, host_name: str, host_vars: t.Dict[str, t.Any]
    ) -> None:
        actual_host_name = host_vars.get("inventory_hostname", host_name)
        self.inventory.add_host(actual_host_name)
        for name, value in host_vars.items():
            if name != "inventory_hostname":
                self.inventory.set_variable(actual_host_name, name, value)
        strict = self.get_option("strict")
        self._set_composite_vars(
            self.get_option("compose"), host_vars, actual_host_name, strict=strict
        )
        self._add_host_to_composed_groups(
            self.get_option("groups"), host_vars, actual_host_name, strict=strict
        )
        self._add_host_to_keyed_groups(
            self.get_option("keyed_groups"), host_vars, actual_host_name, strict=strict
        )

    def _get_custom_attributes(self) -> t.Dict[str, t.Dict[str, str]]:
        custom_attributes = self.get_option("attributes")

        processed_attributes: t.Dict[str, t.Dict[str, str]] = {}
        for name, info in custom_attributes.items():
            if not info:
                info = {name.replace("-", "_"): "this"}
            elif isinstance(info, str):
                info = {name.replace("-", "_"): info}
            elif not isinstance(info, dict):
                raise AnsibleError(
                    f"Attribute {name} value was {type(info).__name__} "
                    "but was expecting a dictionary"
                )

            for var_name in list(info.keys()):
                var_template = info[var_name]
                if not var_template:
                    info[var_name] = "this"

                elif not isinstance(var_template, str):
                    raise AnsibleError(
                        f"Attribute {name}.{var_name} template value was "
                        f"{type(var_template).__name__} but was expecting a string"
                    )

            processed_attributes[name] = info

        return processed_attributes
