#!/usr/bin/python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later

"""Document the controller action for native Windows fact gathering."""

DOCUMENTATION = r"""
---
module: gather_facts
short_description: Gather native Windows facts through Ansible
version_added: '1.0.0'
description:
  - Uses Ansible's configured fact modules and fact merging behavior.
  - Runs this collection's native fact actions so their Python helpers reach the target.
  - Fact modules from other collections retain Ansible's normal execution.
options:
  parallel:
    description:
      - Controls concurrent execution of configured fact modules.
      - Native parallel jobs use this collection's asynchronous launcher and status action.
      - Native parallel gathering preserves the requested Runas account through collection, polling and cleanup.
      - Ansible defaults to serial execution for one fact module and parallel for several.
    type: bool
  gather_subset:
    description: Subsets forwarded to the configured fact modules.
    type: list
    elements: str
  gather_timeout:
    description:
      - Collector timeout forwarded to the configured fact modules.
      - Native parallel gathering also uses this value as the job execution limit.
      - Set an explicit positive value for native parallel gathering; omitted, zero or negative values fail before staging.
    type: int
  fact_path:
    description: Custom-facts directory forwarded to the configured fact modules.
    type: path
attributes:
  action:
    support: full
  check_mode:
    support: full
  diff_mode:
    support: none
notes:
  - Set C(ansible_facts_modules) to C([sustainablelobster.legacy_windows.setup]).
  - For implicit playbook gathering, include this collection in the play's C(collections) list.
  - An explicitly selected C(ansible.builtin.gather_facts) action does not use this adapter.
  - Native Setup retains its documented transport, interpreter and script prerequisites.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Gather native Windows facts
  sustainablelobster.legacy_windows.gather_facts:
    parallel: false
  vars:
    ansible_facts_modules: [sustainablelobster.legacy_windows.setup]

- name: Gather selected facts explicitly
  sustainablelobster.legacy_windows.gather_facts:
    gather_subset: ['!all', '!min', distribution]
    parallel: false
  vars:
    ansible_facts_modules: [sustainablelobster.legacy_windows.setup]
"""

RETURN = r"""
ansible_facts:
  description: Merged facts from the configured fact modules.
  returned: success
  type: dict
"""
