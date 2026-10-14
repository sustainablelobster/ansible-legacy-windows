# Usage

Use [Coverage](coverage.md) to distinguish verified workflows from untested
environments. Local installation alone does not establish Windows support.

## Windows execution

Windows payloads require Python 3.4.4 or newer and the
`sustainablelobster.legacy_windows` execution runtime. Keep the same connection,
Command Prompt shell and Python interpreter settings used for that collection.
Directory capabilities depend on the contacted directory's schema and
functional level, not merely on the Windows host executing the payload.

Domain membership requires a Windows edition that permits joining Active
Directory. An available native API alone does not establish that capability;
Home editions can reject the join. When `membership` uses `domain_ou_path`,
it must identify an organizational unit. A generic container such as
`CN=Computers` is not a valid OU for the native join operation.
Joining a domain can activate a different firewall profile; permit the
management connection in that profile before joining. When leaving a domain,
connect with a local account that remains available in the workgroup.

### Native domain creation

Domain creation uses the installed unattended `dcpromo.exe` answer-file
interface. The older GUI engine can create a forest, but cannot select normal
Windows 2003 functional levels until the new controller has rebooted.

When the older engine requests DNS and that service is absent, the collection
installs DNS first using Windows' [quiet, no-reboot component installer](https://learn.microsoft.com/en-us/previous-versions/orphan-topics/ws.10/cc773290(v=ws.10)).
Provide matching Windows installation media or a usable cached setup source.
This avoids a hidden DNS-setup warning on DHCP hosts; it does not disable DHCP
or assign a static address. Existing DNS installations and check mode do not
run that installer. If DNS installation succeeds but later promotion fails,
DNS remains installed and the failed result reports `changed: true`.

Use `reboot: true` with `domain` or `domain_child` to complete those levels in
the same task. Explicit level requests require this setting on that engine;
unsupported higher levels fail before promotion. The child-domain workflow
does not raise the parent forest's level.

With `domain`'s default `reboot: false` and no explicit levels, the older engine
creates its level-0 domain and forest and returns a warning and
`reboot_required: true`. This differs from upstream's highest-supported default.
The collection never reboots implicitly, and an ordinary rerun does not raise
the levels of an existing forest. Non-ASCII answer-file values use UTF-16 with
a byte-order marker; Unicode passwords were accepted by native Server 2003
promotion. The installed engine still validates individual fields: Server
2003 rejected non-ASCII database directory names in the measured run.
Secrets are kept in restricted temporary files that are removed after execution.

During native promotion, the new controller can reject fresh logons until its
first reboot. Keep an authenticated connection available to request that reboot;
normal Ansible SSH connection reuse does this. Disabling reuse can interrupt
result cleanup or reboot initiation after Windows has already created the domain.

### Forest trust preparation

`domain_trust` manages one local side, as in the recorded upstream release.
Create both sides with the same shared secret. The forest-root controllers need
peer DNS resolution and access to the directory, Kerberos and trust services.
Creating the trusted-domain objects alone does not prove usable authentication.

Windows trust verification and namespace-routing initialization are separate
configuration steps; the module does not initialize name-suffix routing.
Complete those native steps on both sides and verify fresh cross-forest
authentication before relying on the relationship. For these preparation calls,
the integration fixture targets each forest-root PDC. It prepares only its
acquired, GUID-owned pair and checks the actual protocol, principals, signing,
encryption and protected reads.

## Controller LDAP plugins

LDAP inventory requires `sansldap` and `pyspnego` on the controller. DNS-based
server discovery additionally uses `dnspython`; Kerberos discovery uses `krb5`.
Certificate and PFX handling uses `cryptography`. These libraries are not sent
to Windows and do not change its Python 3.4.4 minimum.

The inventory plugin and filters use the new collection namespace. Existing
inventory output variables retain upstream names. Both upstream and new
collection-specific LDAP inventory filename suffixes are accepted.

## Directory and service capabilities

KDS and gMSA workflows depend on the contacted directory's schema and service
capabilities, not simply the Windows version executing Python. Managing a gMSA
directory object does not establish that the execution host can run a service
as that account. AD FS management requires the installed federation service's
management interface; available operations depend on its capabilities.

Options requiring a capability absent from the contacted directory or native
Windows API must fail before changes, with the reason documented in that
module. Do not infer support from a successful local installation.
