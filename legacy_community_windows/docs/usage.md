# Usage

Configure the connection and Python interpreter using the
[Windows usage guide](https://github.com/sustainablelobster/ansible-legacy-windows/blob/main/legacy_windows/docs/usage.md).
Use fully qualified `sustainablelobster.legacy_community_windows` names.

Windows payloads require Python 3.4.4 or newer. Individual operations require
their actual Windows service, API or installed vendor tool; successful packaging
does not establish runtime support. See [Coverage](coverage.md) for execution
evidence and current implementation status.

## Behavior corrections

Disk facts preserve available metadata when a driver returns an unusable
optional device string. The affected field uses an available WMI value or null,
with a warning identifying the device and field. Required disk-query failures
still fail the task.

Robocopy reports purge-only deletions as changes, including their prediction in
check mode. This corrects upstream 3.3.0's unchanged result for that case.
Explicit `flags` still replace the `purge` and `recurse` booleans; merely finding
extra destination entries without an effective deletion request is unchanged.
Custom selection filters such as `/XF` and `/XD` retain upstream change
reporting: Robocopy can return the same status for excluded entries as for
deleted entries, so deletion-only changes with those filters are not reliably
reported. Prefer the documented booleans or ordinary `/PURGE`/`/MIR` flags when
handlers depend on deletion reporting.

## Controller integrations

The `psexec` module executes on the controller or another delegated Python
executor, not through the staged Windows payload runtime. Install `pypsexec`
and its `smbprotocol` dependency on that executor; Kerberos also needs
`gssapi` and a suitable ticket. Use `encrypt: false` for Windows 7/Server
2008 R2 SMB servers without SMB 3 encryption. This does not make SMB 1 servers
compatible with an SMB 2/3 client.

The `laps_password` lookup executes on the controller and needs
`python-ldap`. It reads legacy LAPS `ms-Mcs-AdmPwd`, not modern Windows LAPS.
Use LDAPS, StartTLS or GSSAPI; plaintext simple binds require explicit opt-in.
Keep passwords in Ansible Vault and protect lookup output with `no_log`.

## Redirects and removed interfaces

The baseline's Windows-module redirects target
`sustainablelobster.legacy_windows` rather than loading upstream PowerShell
payloads. Its six removed Active Directory interfaces remain removed; use
the corresponding `sustainablelobster.legacy_ad` modules.
