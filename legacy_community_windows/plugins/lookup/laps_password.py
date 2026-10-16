"""Retrieve legacy LAPS passwords through the controller's maintained LDAP client."""

# (c) 2019 Ansible Project
# SPDX-License-Identifier: GPL-3.0-or-later
# Adapted from community.windows 3.3.0.
# Copyright 2026 sustainablelobster

import os
import traceback
from importlib import import_module
from typing import Any

# Ansible and python-ldap do not distribute controller typing metadata.
from ansible.errors import AnsibleLookupError  # type: ignore[import-untyped]
from ansible.module_utils.basic import (  # type: ignore[import-untyped]
    missing_required_lib,
)
from ansible.module_utils.common.text.converters import (  # type: ignore[import-untyped]
    to_bytes,
    to_native,
    to_text,
)
from ansible.plugins.lookup import LookupBase  # type: ignore[import-untyped]

_ldap_import_error: str | None = None
try:
    import ldapurl  # type: ignore[import-untyped]
    from ldap.filter import escape_filter_chars  # type: ignore[import-untyped]

    # python-ldap populates these constants dynamically from its native extension.
    ldap: Any = import_module("ldap")
    HAS_LDAP = True
except ImportError:
    _ldap_import_error = traceback.format_exc()
    HAS_LDAP = False

DOCUMENTATION = """
name: laps_password
author: Jordan Borean (@jborean93)
short_description: Retrieves the LAPS password for a server.
description:
- This lookup returns the LAPS password set for a server from the Active Directory database.
- See U(https://github.com/jborean93/ansible-lookup-laps_password) for more information around installing
  pre-requisites and testing.
deprecated:
  removed_in: '4.0.0'
  why: >-
    This plugin does not support the newer Windows LAPS implementation and using a lookup for a password is inefficient. The
    P(sustainablelobster.legacy_ad.ldap#inventory) inventory plugin can be used to retrieve the LAPS password for multiple hosts in a more
    efficient manner and supports both the legacy and newer LAPS implementation.
  alternative: Use P(sustainablelobster.legacy_ad.ldap#inventory) instead.
options:
  _terms:
    description:
    - The host name to retrieve the LAPS password for.
    - This is the C(Common Name (CN)) of the host.
    required: True
    type: str
  allow_plaintext:
    description:
    - When set to C(yes), will allow traffic to be sent unencrypted.
    - It is highly recommended to not touch this to avoid any credentials being exposed over the network.
    - Use C(scheme=ldaps), C(auth=gssapi), or C(start_tls=yes) to ensure the traffic is encrypted.
    default: no
    type: bool
  auth:
    description:
    - The type of authentication to use when connecting to the Active Directory server
    - When using C(simple), the I(username) and I(password) options must be set. If not using C(scheme=ldaps) or
      C(start_tls=True) then these credentials are exposed in plaintext in the network traffic.
    - It is recommended to use C(gssapi) as it will encrypt the traffic automatically.
    - When using C(gssapi), run C(kinit) before running Ansible to get a valid Kerberos ticket.
    - You cannot use C(gssapi) when either C(scheme=ldaps) or C(start_tls=True) is set.
    choices:
    - simple
    - gssapi
    default: gssapi
    type: str
  ca_cert:
    description:
    - The path to a CA certificate PEM file to use for certificate validation.
    - Certificate validation is used when C(scheme=ldaps) or C(start_tls=yes).
    - This may fail on hosts with an older OpenLDAP install like MacOS, this will have to be updated before
      reinstalling python-ldap to get working again.
    type: str
    aliases: [ cacert_file ]
  domain:
    description:
    - The domain to search in to retrieve the LAPS password.
    - This could either be a Windows domain name visible to the Ansible controller from DNS or a specific domain
      controller FQDN.
    - Supports either just the domain/host name or an explicit LDAP URI with the domain/host already filled in.
    - If the URI is set, I(port) and I(scheme) are ignored.
    required: True
    type: str
  password:
    description:
    - The password for C(username).
    - Required when C(username) is set.
    type: str
  port:
    description:
    - The LDAP port to communicate over.
    - If I(kdc) is already an LDAP URI then this is ignored.
    type: int
  scheme:
    description:
    - The LDAP scheme to use.
    - When using C(ldap), it is recommended to set C(auth=gssapi), or C(start_tls=yes), otherwise traffic will be in
      plaintext.
    - The Active Directory host must be configured for C(ldaps) with a certificate before it can be used.
    - If I(kdc) is already an LDAP URI then this is ignored.
    choices:
    - ldap
    - ldaps
    default: ldap
  search_base:
    description:
    - Changes the search base used when searching for the host in Active Directory.
    - Will default to search in the C(defaultNamingContext) of the Active Directory server.
    - If multiple matches are found then a more explicit search_base is required so only 1 host is found.
    - If searching a larger Active Directory database, it is recommended to narrow the search_base for performance
      reasons.
    type: str
  start_tls:
    description:
    - When C(scheme=ldap), will use the StartTLS extension to encrypt traffic sent over the wire.
    - This requires the Active Directory to be set up with a certificate that supports StartTLS.
    - This is ignored when C(scheme=ldaps) as the traffic is already encrypted.
    type: bool
    default: no
  username:
    description:
    - Required when using C(auth=simple).
    - The username to authenticate with.
    - Recommended to use the username in the UPN format, e.g. C(username@DOMAIN.COM).
    - This is required when C(auth=simple) and is not supported when C(auth=gssapi).
    - Call C(kinit) outside of Ansible if C(auth=gssapi) is required.
    type: str
  validate_certs:
    description:
    - When using C(scheme=ldaps) or C(start_tls=yes), this controls the certificate validation behaviour.
    - C(demand) will fail if no certificate or an invalid certificate is provided.
    - C(try) will fail for invalid certificates but will continue if no certificate is provided.
    - C(allow) will request and check a certificate but will continue even if it is invalid.
    - C(never) will not request a certificate from the server so no validation occurs.
    default: demand
    choices:
    - never
    - allow
    - try
    - demand
    type: str
requirements:
- python-ldap
notes:
- If a host was found but had no LAPS password attribute C(ms-Mcs-AdmPwd), the lookup will fail.
- Due to the sensitive nature of the data travelling across the network, it is highly recommended to run with either
  C(auth=gssapi), C(scheme=ldaps), or C(start_tls=yes).
- Failing to run with one of the above settings will result in the account credentials as well as the LAPS password to
  be sent in plaintext.
- Some scenarios may not work when running on a host with an older OpenLDAP install like MacOS. It is recommended to
  install the latest OpenLDAP version and build python-ldap against this, see
  U(https://keathmilligan.net/python-ldap-and-macos) for more information.
"""

EXAMPLES = """
# Optionally obtain a Kerberos ticket before calling the lookup.
- name: call kinit to retrieve Kerberos token
  expect:
    command: kinit username@ANSIBLE.COM
    responses:
      (?i)password: SecretPass1
  no_log: true

- name: Get the LAPS password using an existing Kerberos ticket
  set_fact:
    ansible_password: >-
      {{ lookup('sustainablelobster.legacy_community_windows.laps_password',
                'SERVER', domain='dc01.ansible.com') }}
  no_log: true

- name: Specify the domain host using an explicit LDAP URI
  set_fact:
    ansible_password: >-
      {{ lookup('sustainablelobster.legacy_community_windows.laps_password',
                'SERVER', domain='ldap://ansible.com:389') }}
  no_log: true

- name: Use Simple auth over LDAPS
  set_fact:
    ansible_password: >-
      {{ lookup('sustainablelobster.legacy_community_windows.laps_password',
                'server', domain='dc01.ansible.com', auth='simple',
                scheme='ldaps', username='username@ANSIBLE.COM',
                password='SuperSecret123') }}
  no_log: true

- name: Use Simple auth with LDAP and StartTLS
  set_fact:
    ansible_password: >-
      {{ lookup('sustainablelobster.legacy_community_windows.laps_password',
                'app01', domain='dc01.ansible.com', auth='simple',
                start_tls=True, username='username@ANSIBLE.COM',
                password='SuperSecret123') }}
  no_log: true

- name: Narrow down the search base to a an OU
  set_fact:
    ansible_password: >-
      {{ lookup('sustainablelobster.legacy_community_windows.laps_password',
                'sql10', domain='dc01.ansible.com',
                search_base='OU=Databases,DC=ansible,DC=com') }}
  no_log: true

- name: Set certificate file to use when validating the TLS certificate
  set_fact:
    ansible_password: >-
      {{ lookup('sustainablelobster.legacy_community_windows.laps_password',
                'windows-pc', domain='dc01.ansible.com', start_tls=True,
                ca_cert='/usr/local/share/certs/ad.pem') }}
  no_log: true
"""

RETURN = """
_raw:
  description:
  - The LAPS password(s) for the host(s) requested.
  type: str
"""


def get_laps_password(connection: Any, cn: str, search_base: str) -> str:
    """Return one computer's password, rejecting absent or ambiguous results.

    :param connection: Bound python-ldap connection.
    :param cn: Literal computer common name.
    :param search_base: Directory subtree to search.
    :returns: The readable legacy LAPS password.
    :raises AnsibleTemplatePluginError: No unique computer or readable password exists.
    """
    search_filter = f"(&(objectClass=computer)(CN={escape_filter_chars(to_text(cn))}))"
    rows = connection.search_s(
        to_text(search_base),
        ldap.SCOPE_SUBTREE,
        search_filter,
        attrlist=["distinguishedName", "ms-Mcs-AdmPwd"],
    )
    # LDAP referrals have no entry DN and are not computer search results.
    matches = [attributes for dn, attributes in rows if dn]
    if not matches:
        raise AnsibleLookupError(
            f"Failed to find the server '{cn}' in the base '{search_base}'"
        )
    if len(matches) > 1:
        names = "', '".join(to_native(row["distinguishedName"][0]) for row in matches)
        raise AnsibleLookupError(
            f"Found too many results for the server '{cn}' in the base '{search_base}'. "
            f"Specify a more explicit search base for the server required. Found servers '{names}'"
        )
    password = matches[0].get("ms-Mcs-AdmPwd")
    if not password:
        name = to_native(matches[0]["distinguishedName"][0])
        raise AnsibleLookupError(
            f"The server '{name}' did not have the LAPS attribute 'ms-Mcs-AdmPwd'"
        )
    return str(to_native(password[0]))


def _connection_url(options: dict[str, Any]) -> Any:
    auth = options["auth"]
    if auth == "gssapi":
        if not ldap.SASL_AVAIL:
            raise AnsibleLookupError(
                "Cannot use auth=gssapi when SASL is not configured with the local LDAP install"
            )
        if options["username"] or options["password"]:
            raise AnsibleLookupError(
                "Explicit credentials are not supported when auth='gssapi'. "
                "Call kinit outside of Ansible"
            )
    elif auth == "simple":
        if not (options["username"] and options["password"]):
            raise AnsibleLookupError(
                "The username and password values are required when auth=simple"
            )
    else:
        raise AnsibleLookupError(
            f"Invalid auth value '{auth}': expecting either 'gssapi', or 'simple'"
        )
    domain = options["domain"]
    if ldapurl.isLDAPUrl(domain):
        url = ldapurl.LDAPUrl(ldapUrl=domain)
    else:
        port = options["port"] or (389 if options["scheme"] == "ldap" else 636)
        url = ldapurl.LDAPUrl(hostport=f"{domain}:{port}", urlscheme=options["scheme"])
    encrypted = url.urlscheme == "ldaps" or options["start_tls"] or auth == "gssapi"
    if not encrypted and not options["allow_plaintext"]:
        raise AnsibleLookupError(
            "Current configuration will result in plaintext traffic exposing credentials. "
            "Set auth=gssapi, scheme=ldaps, start_tls=True, or allow_plaintext=True to continue"
        )
    return url


def _configure_tls(options: dict[str, Any], url: Any) -> None:
    if url.urlscheme != "ldaps" and not options["start_tls"]:
        return
    if not ldap.TLS_AVAIL:
        raise AnsibleLookupError(
            "Cannot use TLS as the local LDAP installed has not been configured to support it"
        )
    validation = {
        "never": ldap.OPT_X_TLS_NEVER,
        "allow": ldap.OPT_X_TLS_ALLOW,
        "try": ldap.OPT_X_TLS_TRY,
        "demand": ldap.OPT_X_TLS_DEMAND,
    }
    mode = options["validate_certs"]
    if mode not in validation:
        raise AnsibleLookupError(f"Invalid validate_certs value '{mode}'")
    # Library-global configuration retains compatibility with older OpenLDAP
    # implementations that cannot refresh a connection-local TLS context.
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, validation[mode])
    if options["ca_cert"]:
        path = os.path.expanduser(os.path.expandvars(options["ca_cert"]))
        if not os.path.exists(to_bytes(path)):
            raise AnsibleLookupError(
                f"The cacert_file specified '{path}' does not exist"
            )
        try:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, to_text(path))
        except ValueError as error:
            raise AnsibleLookupError(
                "Failed to set path to cacert file. Update OpenLDAP and reinstall "
                "python-ldap to continue"
            ) from error


def _bind(connection: Any, options: dict[str, Any], url: str) -> None:
    if options["start_tls"]:
        try:
            connection.start_tls_s()
        except ldap.LDAPError as error:
            raise AnsibleLookupError(
                f"Failed to send StartTLS to LDAP host '{url}': {to_native(error)}"
            ) from error
    try:
        if options["auth"] == "simple":
            connection.bind_s(
                to_text(options["username"]), to_text(options["password"])
            )
        else:
            connection.sasl_gssapi_bind_s()
    except ldap.AUTH_UNKNOWN as error:
        raise AnsibleLookupError(
            f"Failed to bind against LDAP host '{url}', the GSSAPI mech is not installed: "
            f"{to_native(error)}"
        ) from error
    except ldap.LDAPError as error:
        raise AnsibleLookupError(
            f"Failed to {options['auth']} bind against LDAP host '{url}': {to_native(error)}"
        ) from error


# Ansible supplies the untyped base class through its controller plugin loader.
class LookupModule(LookupBase):  # type: ignore[misc]
    """Read legacy LAPS attributes with the released lookup options."""

    def run(
        self, terms: list[str], variables: dict[str, Any] | None = None, **kwargs: Any
    ) -> list[str]:
        """Return passwords in term order without logging secret directory data.

        :param terms: Computer common names to resolve.
        :param variables: Ansible variable context for plugin options.
        :param kwargs: Direct lookup options.
        :returns: One legacy LAPS password for each supplied term.
        :raises AnsibleTemplatePluginError: Dependencies, configuration or lookup fail.
        """
        if not HAS_LDAP:
            message = missing_required_lib(
                "python-ldap", url="https://pypi.org/project/python-ldap/"
            )
            raise AnsibleLookupError(f"{message}. Import Error: {_ldap_import_error}")
        self.set_options(var_options=variables, direct=kwargs)
        options = {
            name: self.get_option(name)
            for name in (
                "domain",
                "port",
                "scheme",
                "start_tls",
                "validate_certs",
                "ca_cert",
                "search_base",
                "username",
                "password",
                "auth",
                "allow_plaintext",
            )
        }
        url = _connection_url(options)
        _configure_tls(options, url)
        address = str(url.initializeUrl())
        connection = ldap.initialize(address, bytes_mode=False)
        try:
            connection.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            connection.set_option(ldap.OPT_REFERRALS, 0)
            _bind(connection, options, address)
            search_base = options["search_base"]
            if not search_base:
                search_base = connection.read_rootdse_s()["defaultNamingContext"][0]
            return [get_laps_password(connection, term, search_base) for term in terms]
        finally:
            connection.unbind_s()
