# SPDX-License-Identifier: GPL-3.0-or-later
param([string]$Text, [string]$MarkerPath, [string]$ReleasePath)
[IO.File]::WriteAllText($MarkerPath, [string]$PID)
$timer = [Diagnostics.Stopwatch]::StartNew()
while (-not [IO.File]::Exists($ReleasePath)) {
    if ($timer.Elapsed.TotalSeconds -gt 90) { throw 'owned async release missing' }
    Start-Sleep -Milliseconds 100
}
$Ansible.Changed = $false
$Ansible.Result = @{text=$Text;path=$PSCommandPath;root=$PSScriptRoot}
'file λ'
