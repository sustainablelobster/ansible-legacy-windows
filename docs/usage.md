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

### Windows features and engines

A module needs the Windows facilities it manages, such as DISM servicing,
advanced audit policy, DNS/DHCP server management or modern service settings.
Unsupported requests fail rather than report success.

Some modules also need an installed execution engine:

- `win_powershell`: PowerShell 5.1 or newer.
- `win_dsc`: Windows PowerShell 5.0 or newer, the requested DSC resources,
  and the default HTTP WSMan listener.
- `dsc3`: the DSC v3 executable and requested resources.

Other capability-specific limits:

- **DHCP:** the classic server RPC API can be used when the modern provider is
  unavailable. It lacks per-lease DNS registration controls: default `aptr`
  leaves server DNS policy unchanged; `a` or `noreg` changes fail before writes,
  including in check mode.
- **Optional features:** enabling a feature with `include_parent: true` or
  `source` needs DISM's `/All` or `/Source` switch respectively. If the installed
  command lacks a required switch, the request fails before servicing, including
  in check mode. Already-satisfied and absent requests do not need the switches.
  Names are resolved against the installed catalogue when exact casing is needed.

### Event logs and DNS

Configured event-log creation supports check mode without creating the log or
its sources. Unlike `ansible.windows` 3.8.0, prediction does not fail because
the new log is absent. Normal execution can still leave earlier source changes
in place if later configuration validation fails, as described in `win_eventlog`.

DNS SRV creation applies the requested `ttl` immediately. Unlike
`ansible.windows` 3.8.0, a nondefault lifetime does not need an identical repeat
to correct it. Classic DNS providers can expose the SRV target as either
`DomainName` or `SRVDomainName`; the collection uses the installed provider's
metadata for both reading and creation.

### HTTP requests

- **Timeouts:** HTTP/HTTPS requires a positive `url_timeout` (default 30 seconds).
  Nonpositive values fail before networking.
- **File and FTP URLs:** FTP uploads commonly need `status_code: [226]`. File
  URI requests fail status validation like upstream; requests with a body are
  rejected before writing, including in check mode. Use `win_copy` to write files.
- **JSON bodies:** dictionary/list bodies preserve case-distinct keys such as
  `name` and `Name`, which upstream's PowerShell parser can reject. Object key
  order is not guaranteed; use a string body for an exact representation.

#### TLS and client certificates

HTTPS enables available TLS 1.1/1.2 on older WinHTTP implementations without
changing machine-wide settings. Modern protocol defaults and explicitly
configured `DefaultSecureProtocols` settings are left unchanged. Windows
security policy and cipher support still apply; `validate_certs: false` skips
certificate checks, not protocol negotiation.

PFX-file client certificates require Windows Vista or newer for temporary
private-key inspection and writable current-user key storage. The collection
selects a certificate with a private key from the bundle and keeps it usable
through an owned temporary key container. The container is removed after native
request handles close, including on failure. Existing keys and system
certificate stores are unchanged.

An installed `Cert:\CurrentUser\My\thumbprint` certificate is **not a verified
XP workaround**. The tested TLS 1.0 endpoint accepted the certificate, but both
collection and native synchronous WinHTTP requests timed out receiving HTTP.
This does not establish that every XP HTTPS endpoint fails. Installed-certificate
authentication on Server 2003 also remains unverified.

#### Proxy authentication

Proxy-only authentication rejects localhost and IP-address destinations before
connecting, including redirects. WinHTTP cannot reliably prevent those
destinations from using the current login as unsolicited origin credentials.
Use a DNS machine name or fully qualified hostname, or explicitly provide the
intended origin credentials.

### Package uninstallation

For registry package removal without an explicit `path`, `win_package` prefers
`QuietUninstallString`, expands a leading environment-variable reference, and
recovers the first existing executable path from unquoted strings containing
spaces. Parsed arguments are retained. If no candidate file exists, the unchanged
command uses normal executable resolution, including PATH and the working
directory. Unresolved executables still fail to launch. An explicit `path`
bypasses this registry-command recovery.

### Permissions and audit rules

Neither `win_acl` nor `win_audit_rule` constructs or edits object GUID
restrictions or callback conditions. Unsafe unknown explicit types and malformed
entries are rejected before writes. Inherited entries are unchanged.

#### Access permissions (`win_acl`)

- **Existing rules:** ordinary insertion preserves unrelated object and callback
  entries and canonical ordering. File, registry and certificate requests match
  common callback allow/deny entries, including conditional entries, by ordinary
  rule fields. A match prevents an unconditional grant from being inserted.
  Removal subtracts matched rights from overlapping entries; remaining callback
  entries retain their conditions.
- **Certificate rights:** an existing Read grant does not satisfy FullControl,
  unlike upstream's rights-blind comparison. CAPI supports complete Read and
  FullControl rules; partial removals that would round back to FullControl are
  rejected before writing. CNG supports granular removal. Remaining rules keep
  their conditions and GUID data.
- **Restricted rules:** object and callback-object access entries remain stored
  but do not match ordinary rules. Inserting an ordinary rule for their principal
  and allow/deny type fails before writing. Unmatched conditional certificate
  rules receive the same protection. Use a condition-aware tool to change them.

#### Audit permissions (`win_audit_rule`)

- Common callback audit entries are reported and matched without exposing or
  rebuilding their conditions. Object and callback-object entries remain stored
  but are omitted from returned rules, like upstream.
- When removal finds a matching explicit rule, it purges that identity's explicit
  audit entries, including opaque entries, but leaves inherited entries unchanged.

### Regular expressions and text handling

Find, Wait and Updates regex searches use Python's `re` engine with limited
.NET syntax translations:

- **Unicode:** matching operates on UTF-16 code units; a dot can consume one
  surrogate of an emoji. Category escapes, word/digit/space classes and word
  boundaries use fixed Unicode 8 data. Case-insensitive matching uses Python's
  rules and can differ from .NET culture-dependent matching. General categories
  such as `\p{L}` work; block names such as `\p{IsBasicLatin}` do not.
- **Unsupported syntax:** atomic or balancing groups, class subtraction, scoped
  inline options and variable-width lookbehind.
- **Inline options:** put them at the pattern prefix. Options later in a pattern
  are rejected because Python 3.4 applies them differently.
- **End matching:** `\Z` matches at the end or before one final LF; `\z` requires
  the strict end.
- **Backreferences:** numeric references combined with named groups are
  unsupported. Use named references such as `\k<name>` instead.

Dates, wildcard matching and decoding can also differ; consult the affected
module's notes rather than assuming identical runtime behavior.

### Product facts

On Vista, `win_product_facts` requires the Software Licensing service (`slsvc`)
to be running. The module is read-only and does not start it. If the licensing
provider lacks `ProductKeyChannel`, it returns null channels with a named
warning while retaining available edition and status information. Permission
and service failures while enumerating licenses fail without partial facts.

### Windows Update

Windows Update workers first use the task's effective account. A conclusive
native startup rejection before any worker exists permits one SYSTEM attempt,
when native token acquisition is available. Uncertain launches and failures after
work starts are not retried under another account. Use the `runas` options above
to select an account explicitly.

- **Infrastructure:** a functioning update source and administrative WUA access
  are required. Older installations may need signed servicing-stack, SHA-2
  support and Windows Update Agent updates installed separately. `win_updates`
  uses the installed agent; it does not bootstrap or replace the infrastructure.
  Selecting SYSTEM or passing access checks does not prove servicing will work.
- **Side effects:** search can update the local catalogue; installation and
  removal can require reboots.
- **Failures:** numeric HRESULTs are retained. Synchronous failures include a
  localized Windows description when available, otherwise only the hexadecimal
  code. This differs from upstream's fixed English text and symbolic names.
  Async top-level failures also include available descriptions; per-update
  results retain the numeric code without the synchronous `failure_msg` field.

### Unresolved issues

- A Windows 11 File test failed to preserve a path's access time. Its cause
  is unresolved; successful metadata reads do not establish that File case.
