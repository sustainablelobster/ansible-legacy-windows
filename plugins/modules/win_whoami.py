#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read current Windows token and logon information using Python 3.4.4."""

# WANT_JSON

import legacy_windows_logon as logon  # pylint: disable=import-error
import legacy_windows_token as token  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_whoami
short_description: Read the current Windows token and logon session
version_added: '1.0.0'
description:
  - Reports the current process's account, token groups, privileges, and logon-session metadata.
  - Uses Python 3.4.4 and native Windows APIs.
options: {}
attributes:
  check_mode:
    support: full
    description: Reads the same information as a normal invocation.
  diff_mode:
    support: none
notes:
  - The reader does not adjust token privileges, group memberships, or account rights.
  - Reports the account and token of the payload process, as selected by the connection and execution context.
  - Runtime initialization can enable process privileges before the reader runs. Python 3.4.4 attempts to enable C(SeCreateSymbolicLinkPrivilege), so privilege states can differ from an upstream PowerShell process.
  - Non-administrator tokens return an empty RV(rights) list, following upstream behavior.
  - For administrator tokens, RV(rights) contains distinct logon-right names queried for enabled token groups, in discovery order.
  - Logon SID groups are excluded from RV(groups) but still participate in the upstream rights query.
  - XP and Server 2003 return null for RV(label) and RV(user_flags), with warnings naming those unavailable fields.
  - Passwordless named-account runas requires permission to impersonate an accessible SYSTEM token. It reuses a matching non-network token, or requests a native S4U logon when no eligible process token exists.
  - A fresh S4U logon uses Batch unless runas requests Network; it supplies no password-derived outbound network credentials. Existing-token reuse retains that token's logon context. Systems without the required S4U authentication package need an eligible existing token or a become password.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Inspect the account and token used for Windows tasks
  sustainablelobster.legacy_windows.win_whoami:
  register: identity

- name: Show the account and available token privileges
  ansible.builtin.debug:
    msg:
      account: '{{ identity.account }}'
      privileges: '{{ identity.privileges }}'
"""

RETURN = r"""
account:
  description: Identity associated with the process's authentication session.
  returned: success
  type: dict
  contains:
    sid:
      description: Canonical SID text.
      type: str
    account_name:
      description: Resolved account name, or null when unmapped.
      type: str
    domain_name:
      description: Resolved domain name, or null when unmapped.
      type: str
    type:
      description: Native SID type name, such as C(User), C(Group), or C(Unknown).
      type: str
groups:
  description: Token groups other than the logon SID, in native enumeration order.
  returned: success
  type: list
  elements: dict
  contains:
    sid:
      description: Canonical group SID text.
      type: str
    account_name:
      description: Resolved group name, or null when unmapped.
      type: str
    domain_name:
      description: Resolved domain name, or null when unmapped.
      type: str
    type:
      description: Native SID type name.
      type: str
    attributes:
      description: Named group flags in upstream numeric-flag order.
      type: list
      elements: str
privileges:
  description: Maps privilege names to C(disabled), C(enabled), or C(enabled-by-default).
  returned: success
  type: dict
rights:
  description: Distinct logon rights found on enabled token groups, or an empty list for non-administrator tokens.
  returned: success
  type: list
  elements: str
label:
  description: Integrity SID details with the same fields as RV(account), or null when the OS lacks integrity labels.
  returned: success
  type: dict
token_type:
  description: Native token type, normally C(TokenPrimary) or C(TokenImpersonation).
  returned: success
  type: str
impersonation_level:
  description: Native impersonation level name; meaningful for impersonation tokens.
  returned: success
  type: str
logon_id:
  description: Unsigned 64-bit identifier of the authentication session.
  returned: success
  type: int
logon_type:
  description: Native logon type name, such as C(Interactive) or C(Network).
  returned: success
  type: str
login_time:
  description: Local logon timestamp with seven fractional digits and a numeric UTC offset, or null for an absent or out-of-range time.
  returned: success
  type: str
login_domain:
  description: Domain used for authentication, retaining an empty string or null as supplied by Windows.
  returned: success
  type: str
authentication_package:
  description: Name of the authentication package used for this session.
  returned: success
  type: str
logon_server:
  description: Server used to authenticate the session, retaining an empty string or null.
  returned: success
  type: str
dns_domain_name:
  description: Session DNS domain, retaining an empty string or null.
  returned: success
  type: str
upn:
  description: Session user principal name, retaining an empty string or null.
  returned: success
  type: str
user_flags:
  description: Named session flags in upstream numeric-flag order, or null when absent from the native record.
  returned: success
  type: list
  elements: str
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_whoami"


def _response():
    arguments = read_arguments((), _MODULE_NAME)
    warnings = []
    token_data, authentication_id, enabled_groups, is_admin = token.token_information(
        warnings
    )
    result = {"changed": False}
    result.update(logon.logon_session(authentication_id, warnings))
    result.update(token_data)
    result["rights"] = logon.logon_rights(enabled_groups) if is_admin else []
    if warnings:
        result["warnings"] = warnings
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        result["invocation"] = {"module_args": {}}
    return result


def main():
    """Emit current token and logon information as an Ansible JSON result.

    :raises SystemExit: After reporting success or failure.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
