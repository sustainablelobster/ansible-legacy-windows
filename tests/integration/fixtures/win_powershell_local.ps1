# SPDX-License-Identifier: GPL-3.0-or-later
param([string]$Text = 'local défaut λ')
$Ansible.Changed = $false
$Ansible.Result = @{text=$Text;path=$PSCommandPath;root=$PSScriptRoot}
'local λ'
