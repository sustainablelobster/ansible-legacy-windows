# Usage

Use the module reference for arguments, return values and operation-specific
permissions:

```console
ansible-doc sustainablelobster.legacy_windows.win_service
```

Configure your connection to execute the Python interpreter and transfer files.
See the [SSH example](../README.md#connect-and-run-a-task) to get started.

## Commands and shells

Use `win_command` for an executable without shell expansion. Its `argv`
option avoids assembling a quoted command line yourself:

```yaml
- name: Check Python
  sustainablelobster.legacy_windows.win_command:
    argv:
      - C:\Python34\python.exe
      - --version
```

Use `win_shell` for shell operators or expansion. It defaults to
`powershell.exe`; select `executable: cmd` on systems without PowerShell.
Task `environment` values affect the child process, not persistent Windows
environment settings.

The Command Prompt shell plugin needs an absolute, unquoted
`ansible_python_interpreter` path. It does not discover Python or accept
interpreter command-line arguments.

## Facts

Select this collection's gathering action and Setup module:

```yaml
- name: Inspect Windows
  hosts: windows
  collections:
    - sustainablelobster.legacy_windows
  gather_facts: true
  gather_subset: ['!all', '!min', distribution]
  vars:
    ansible_facts_modules: [sustainablelobster.legacy_windows.setup]
  tasks:
    - name: Show the Windows version
      ansible.builtin.debug:
        var: ansible_facts.distribution_version
```

For an explicit task, use `sustainablelobster.legacy_windows.gather_facts`
with the same `ansible_facts_modules` setting. Selecting
`ansible.builtin.gather_facts` explicitly bypasses the native helper-staging
action. Native parallel gathering honors Setup module defaults;
`gather_timeout` limits each Setup collector, not the whole gathering job.
Parallel and serial gathering use the same `runas` options. On systems without
nested process jobs, fact collectors also require native WMI process creation
when the connection's job policy forbids breakaway. If a collector cannot
start, Setup warns and omits its facts rather than silently using another
account.

## Privilege escalation

Native actions support Ansible's `runas` options:

```yaml
- name: Inspect an administrator token
  become: true
  become_method: runas
  become_user: Administrator
  sustainablelobster.legacy_windows.win_whoami:
```

Supply `ansible_become_password` securely for normal named-account logons.
Without a become password, native `runas` reuses an eligible token for the
requested identity or asks Windows for a passwordless S4U logon. This depends on
available Windows facilities; both paths require permission to impersonate an
accessible SYSTEM token. A fresh S4U logon uses Batch even for the default
Interactive request, so the account needs **Log on as a batch job**
(`SeBatchLogonRight`). An explicit Network request instead uses Network logon;
existing-token reuse retains that token's logon context. An explicitly empty
password still requests password-based logon. S4U does not supply password-based
remote-network credentials; loopback access can still work. The account must
have the permissions and logon rights needed by the operation. Other become
methods are rejected.

Native `runas` first tries an existing SYSTEM token. If its permissions prevent
acquisition, a temporary native LocalSystem service obtains its own token.
This fallback requires service-creation permission and a held
`SeImpersonatePrivilege`; it does not grant new rights or change existing token
permissions. The service and its private files are removed before launching the
requested operation. XP and Server 2003 support this SYSTEM path but lack fresh
named-account S4U logons. A named account with a password remains an alternative
when it has the operation's required permissions. Reboot applies the requested
account throughout boot checks,
shutdown and readiness, including after reconnecting; upstream ignores become
for this action.

## Background jobs

Launch a supported task with `poll: 0`, then use the collection's status
module to wait for it:

```yaml
- name: Run a maintenance program
  sustainablelobster.legacy_windows.win_command:
    argv: ['C:\Application\maintenance.exe']
  async: 300
  poll: 0
  register: maintenance

- name: Wait for maintenance
  sustainablelobster.legacy_windows.async_status:
    jid: "{{ maintenance.ansible_job_id }}"
  register: maintenance_status
  until: maintenance_status.finished
  retries: 60
  delay: 5

- name: Remove the completed job cache
  sustainablelobster.legacy_windows.async_status:
    jid: "{{ maintenance.ansible_job_id }}"
    mode: cleanup
```

Cleanup removes the job cache; it does not cancel a running job.
General background jobs launch directly when they can escape the connection's
process-job restrictions. Restricted contexts instead require native WMI
process-creation permissions. Windows Update uses a separate worker that always
requires WMI process creation.
Not every action supports async: Copy and Template reject it, as do some
privilege-escalation combinations. Consult the module reference.

Automatic polling (`poll` greater than zero) requires the native polling
adapter. Find the installed collection path with
`ansible-galaxy collection list sustainablelobster.legacy_windows`, then add
its adapter directory to the project's `ansible.cfg`:

```ini
[defaults]
action_plugins = /path/to/ansible_collections/sustainablelobster/legacy_windows/plugins/action/_native_async_polling
```

The path is the installed collection's `plugins/action/_native_async_polling`
directory. The [configuration example](examples/async-polling.cfg) assumes
a project-local collection installation; adjust it to your installed path.
No per-invocation environment override is needed. Installing the collection
alone does not activate the adapter. Without this configuration, use `poll: 0`
and manual polling as above. The adapter
routes this collection's Command Prompt shell to native status and leaves
other shells using Ansible's builtin status action.

In the verified Ansible-core 2.21.1 integration, automatic polling and cleanup
select `ansible.legacy.async_status` directly. Collection module routing does
not replace that action or stage this collection's native reader and Runas
helpers. Configuration-free integration would need a supported
way to select the host's status action for both polling and cleanup; the
inspected core extension points do not provide one. The adapter above supplies
that selection without modifying Ansible core.

`win_updates` supports both polling modes, but async cannot be combined with
`reboot: true`.

## Prerequisites and known issues

A module cannot manage a feature absent from its operating system: for example,
DISM servicing, advanced audit policy,
DNS/DHCP server management, and modern service settings need their corresponding
Windows facilities. Unsupported requests fail rather than report success.

Additional module requirements:

- `win_powershell`: PowerShell 5.1 or newer.
- `win_dsc`: Windows PowerShell 5.0 or newer, the requested DSC resources,
  and the default HTTP WSMan listener.
- `dsc3`: the DSC v3 executable and requested resources.

DHCP management can use the installed classic server RPC API when the modern
provider is unavailable. That API does not expose per-lease DNS registration
controls: default `aptr` leaves server DNS policy unchanged; changes requesting
`a` or `noreg` fail before writes, including in check mode.

Optional-feature management uses the installed DISM command's capabilities.
If its enable command lacks `/All` or `/Source`, an enable request needing
`include_parent: true` or `source` fails before servicing, including check mode.
Already-satisfied and absent requests do not need those switches. Feature names
are resolved against the installed catalogue when the tool requires exact casing.

HTTP/HTTPS requests require a positive `url_timeout` (default 30 seconds).
Nonpositive values fail before networking. File and FTP requests have their
own documented behavior. FTP uploads commonly need `status_code: [226]`.
File URI requests fail status validation like upstream. Requests with a body
are rejected before writing, including in check mode; use `win_copy` to write
files. URI dictionary/list bodies use
standard JSON and preserve case-distinct keys such as `name` and `Name`;
upstream's PowerShell argument parser can reject those keys.
Object key order is not guaranteed;
use a string body when an endpoint requires an exact representation.
HTTPS enables available TLS 1.1/1.2 on older WinHTTP implementations without
changing machine-wide settings. Modern protocol defaults and explicitly
configured `DefaultSecureProtocols` settings are left unchanged. Windows
security policy and cipher support still apply; `validate_certs: false` skips
certificate checks, not protocol negotiation.

Proxy-only authentication rejects localhost and IP-address destinations before
connecting, including redirected requests. WinHTTP cannot reliably prevent
those destinations from using the current login as unsolicited origin
credentials. Use a DNS machine name or fully qualified hostname, or explicitly
provide the intended origin credentials.

PFX-file client certificates require Windows Vista or newer for temporary
private-key inspection. An installed `Cert:\CurrentUser\My\thumbprint`
certificate is not a verified XP workaround. The tested TLS 1.0 endpoint
accepted the client certificate, but collection and native synchronous WinHTTP
requests both timed out receiving HTTP. This does not establish that every XP
HTTPS endpoint fails; installed-certificate authentication on Server 2003
also remains unverified.

For registry package removal without an explicit `path`, `win_package` prefers
`QuietUninstallString`, expands a leading environment-variable reference, and
recovers the first existing executable path from unquoted strings containing
spaces. Parsed arguments are retained. If no candidate file exists, the unchanged
command uses normal executable resolution, including PATH and the working
directory. Unresolved executables still fail to launch. An explicit `path`
bypasses this registry-command recovery.

Ordinary `win_acl` insertion preserves unrelated object and callback permission
entries and their canonical ordering. File, registry and certificate requests
match common callback allow/deny entries, including conditional entries, by
their ordinary rule fields. An existing match prevents an unconditional grant
from being inserted. Removal subtracts matched rights from overlapping entries;
remaining callback entries retain their conditions, and inherited entries are
unchanged.
Certificate matching includes the requested native rights: an existing Read
grant does not satisfy FullControl, unlike upstream's rights-blind comparison.
CAPI supports complete Read and FullControl rules; partial removals that it
would round back to FullControl are rejected before writing. CNG supports
granular removal. Remaining rules keep their conditions and GUID data.
Object and callback-object access entries remain stored but do not match
ordinary rules. Inserting an ordinary rule for their principal and allow/deny
type is rejected before writing, rather than bypassing their restrictions.
Unmatched conditional certificate rules receive the same protection. Use a
condition-aware tool to change those restricted rules.
`win_audit_rule` reports and matches common callback audit entries without
exposing or rebuilding their conditions.
Object and callback-object audit entries remain stored but are omitted from
the returned rules, like upstream. When removal finds a matching explicit audit
rule, it purges that identity's explicit audit entries, including opaque entries,
but leaves inherited entries unchanged. Neither module constructs or edits
object GUID restrictions or callback conditions. Unsafe unknown explicit types
and malformed entries are rejected before writes.

Find, Wait and Updates regex searches use Python's `re` engine with limited
.NET syntax translations. Matching operates on UTF-16 code units: a dot can
consume one surrogate of an emoji. Unicode category escapes, word/digit/space
classes and word boundaries use fixed Unicode 8 data; case-insensitive
matching uses Python's rules and can differ from .NET culture-dependent matching.
Atomic or balancing groups, class subtraction, scoped inline options and
variable-width lookbehind are unsupported. Put inline options at the pattern
prefix; options later in a pattern are rejected because Python 3.4 applies
them differently. `\Z` matches at the end or before one final LF; `\z` requires
the strict end. Numeric backreferences combined with named groups are
unsupported; use named references such as `\k<name>` instead. Unicode general
categories such as `\p{L}` are supported, but Unicode block names such as
`\p{IsBasicLatin}` are not.
Dates, wildcard matching and decoding can also differ; consult the affected
module's notes rather than assuming identical runtime behavior.

On Vista, `win_product_facts` requires the Software Licensing service (`slsvc`)
to be running. The module is read-only and does not start it. If the licensing
provider lacks `ProductKeyChannel`, it returns null channels with a named
warning while retaining available edition and status information. Permission
and service failures while enumerating licenses fail without partial facts.

Known issues:

- A Windows 11 File test failed to preserve a path's access time. Its cause
  is unresolved; successful metadata reads do not establish that File case.

Windows Update workers first use the task's effective account. A conclusive
native startup rejection, before any worker exists, permits one SYSTEM attempt
when native token acquisition is available. Uncertain launches and failures
after work starts are not retried under another account. A functioning update
source and administrative WUA access are still required; selecting SYSTEM does
not guarantee successful servicing. Use the `runas` options above to select an
account explicitly. Search can update the local catalogue; installation and
removal can require reboots. Do not treat successful access checks as proof that
servicing will work.

Older installations may need signed servicing-stack, SHA-2 support and Windows
Update Agent updates installed separately before their configured source can
search successfully. `win_updates` uses the installed agent; it does not
bootstrap or replace Windows Update infrastructure.

Update failures retain their numeric HRESULT. Synchronous failures also include
a localized Windows description when one is available; otherwise the message
contains the hexadecimal code alone. This differs from upstream's fixed English
descriptions and symbolic names. Async top-level failures also include available
descriptions; per-update results retain the numeric code without the synchronous
`failure_msg` field.
