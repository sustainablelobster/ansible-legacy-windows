#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Document controller-side template rendering and Windows file delivery."""

DOCUMENTATION = r"""
---
module: win_template
short_description: Render a controller template to a Windows file
version_added: '1.0.0'
description:
  - Renders a UTF-8 source file with the controller's Ansible and Jinja environment.
  - Delivers the rendered bytes with M(sustainablelobster.legacy_windows.win_copy).
  - Rendering does not run on Windows. File delivery uses Python 3.4.4 or newer and native Windows APIs.
options:
  src:
    description:
      - Jinja template path on the controller, either absolute or relative to Ansible's template search paths.
      - The source must use UTF-8. O(output_encoding) controls the rendered file's encoding, not the source encoding.
      - Ansible Vault-encrypted sources are decrypted by the controller's loader.
    type: path
    required: true
  dest:
    description:
      - Literal Windows destination path. Use an absolute path to avoid depending on the remote working directory.
      - An existing directory or trailing slash retains the source template's basename, including its extension.
      - The parent must exist for a file destination. A destination ending in a slash creates missing directories.
    type: path
    required: true
  backup:
    description:
      - Preserve the previous destination file beside it when changed content replaces it.
      - The backup filename includes a process ID and timestamp.
    type: bool
    default: false
  force:
    description:
      - Replace a destination whose contents differ from the rendered bytes when V(true).
      - Leave an existing destination unchanged and create only missing files when V(false).
    type: bool
    default: true
  block_start_string:
    description: Opening delimiter for a Jinja control block.
    type: str
    default: '{%'
  block_end_string:
    description: Closing delimiter for a Jinja control block.
    type: str
    default: '%}'
  variable_start_string:
    description: Opening delimiter for a Jinja expression.
    type: str
    default: '{{'
  variable_end_string:
    description: Closing delimiter for a Jinja expression.
    type: str
    default: '}}'
  comment_start_string:
    description: Opening delimiter for a Jinja comment.
    type: str
    default: '{#'
  comment_end_string:
    description: Closing delimiter for a Jinja comment.
    type: str
    default: '#}'
  trim_blocks:
    description: Remove the first newline following a Jinja control block, but not an expression, when V(true).
    type: bool
    default: true
  lstrip_blocks:
    description: Remove spaces and tabs before a Jinja control block at the beginning of a line when V(true).
    type: bool
    default: false
  newline_sequence:
    description:
      - Newline sequence used when rendering the template. The default is Windows CRLF.
      - Accepts either actual newline characters or their literal backslash spellings.
    type: str
    choices: ['\n', '\r', '\r\n']
    default: '\r\n'
  output_encoding:
    description:
      - Encoding used on the controller to convert rendered text to destination bytes.
      - Codec names are resolved by the controller's Python, not by the Windows target's Python.
    type: str
    default: utf-8
attributes:
  async:
    support: none
    description: Background jobs are rejected before rendering or target staging.
  action:
    support: full
    description: The action plugin renders locally and delegates file delivery to this collection's copy action.
  check_mode:
    support: full
    description: Renders the template and predicts destination changes without writing the destination file.
  diff_mode:
    support: full
    description: Uses the copy action's content diff; binary files and Ansible's diff limits can suppress content output.
notes:
  - >-
    A first-line C(#jinja2:) header can override rendering settings for that source.
    For example, C(#jinja2:variable_start_string:'[%', variable_end_string:'%]', trim_blocks: False)
    selects C([% value %]) expression delimiters and retains newlines after blocks.
  - Trailing newlines from the source are preserved during rendering.
  - Sources without Jinja syntax are returned unchanged by Ansible; O(newline_sequence) does not rewrite their line endings.
  - >-
    Templates receive C(template_host), the controller node name; C(template_path), the supplied source path;
    C(template_fullpath), its resolved absolute path; and C(template_destpath), the requested destination.
  - >-
    C(template_uid) identifies the source owner by account name when available, otherwise by numeric user ID.
    C(template_mtime) is the source modification time, and C(template_run_date) is the rendering time.
  - >-
    C(ansible_managed) uses the caller's variable when supplied; otherwise Ansible generates its configured management message.
    These metadata variables describe the controller source and rendering, not the Windows destination.
  - Including a rendering timestamp or another changing value in the output makes subsequent runs report a change.
  - Check and diff modes still render the source on the controller. Avoid exposing secrets through diffs; use C(diff=false) when needed.
seealso:
  - module: sustainablelobster.legacy_windows.win_copy
  - module: ansible.builtin.template
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Render an application configuration with Windows newlines
  sustainablelobster.legacy_windows.win_template:
    src: application.ini.j2
    dest: C:\Application\application.ini
    backup: true

- name: Render a file for a program that requires LF newlines
  sustainablelobster.legacy_windows.win_template:
    src: service.conf.j2
    dest: C:\Application\service.conf
    newline_sequence: '\n'

- name: Use expression delimiters that do not conflict with the output format
  sustainablelobster.legacy_windows.win_template:
    src: custom.conf.j2
    dest: C:\Application\custom.conf
    variable_start_string: '[%'
    variable_end_string: '%]'

- name: Seed a UTF-16 configuration without replacing an existing file
  sustainablelobster.legacy_windows.win_template:
    src: initial.ini.j2
    dest: C:\Application\initial.ini
    output_encoding: utf-16
    force: false
"""

RETURN = r"""
backup_file:
  description: Backup filename, or null when there was no previous file. Check mode can return a placeholder instead of creating a backup.
  returned: backup requested for a changed file
  type: str
dest:
  description: Destination path reported by file delivery.
  returned: success
  type: str
src:
  description: Temporary controller file containing the rendered bytes. This file is removed before the action returns.
  returned: success
  type: str
checksum:
  description: SHA1 digest of the rendered bytes, or null with O(force=false).
  returned: success
  type: str
size:
  description: Size of the rendered file in bytes.
  returned: success
  type: int
operation:
  description: The delegated copy operation, V(file_copy).
  returned: success
  type: str
original_basename:
  description: Source template basename, including its extension.
  returned: success
  type: str
"""
