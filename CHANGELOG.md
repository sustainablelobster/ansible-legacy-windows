# Changelog

## 1.0.1

- Predict configured creation of a fresh event log in check mode without
  requiring the log to exist or writing its sources or configuration.
- Use the installed classic DNS provider's SRV target property and creation
  parameter names, including `DomainName` on Server 2003.
- Correct the older provider's SRV update identity while preserving the target
  and unrelated record fields.
- Apply the requested SRV lifetime during creation so the first identical
  repeat is unchanged, including on the modern DNS provider.
- Preserve native HTTPS errors with high-bit Windows error codes on
  Python 3.4 instead of replacing them with an integer overflow.
- Select a certificate with a private key from PFX client-certificate bundles
  and keep it usable by native TLS through an owned temporary key container,
  removed when the request closes without changing existing keys or system
  certificate stores.

## 1.0.0

- License the collection and original contributions under GPL-3.0-or-later,
  matching the upstream baseline, and include its license and attribution.
- Add Python 3.4.4-compatible Windows management modules with familiar
  `ansible.windows` interfaces.
- Add native file, account, registry, service, permission, networking,
  certificate, package, feature, and Windows Update operations.
- Add fact gathering, Runas privilege escalation, background jobs, and Windows
  argument quoting.
- Honor Runas during native reboots and readiness checks.
- Support PowerShell and DSC tasks.
- Use standard JSON for URI bodies and require positive HTTP/HTTPS timeouts.
- Include available native Windows descriptions in update failure messages.
- Match service-name patterns in package installation guards.
- Support FTP request bodies and reject file URI bodies before writing.
- Launch background jobs directly when process-job restrictions permit it.
- Enable available TLS 1.1/1.2 for legacy HTTPS requests and report native TLS
  failure reasons.
- Recover executable paths in unquoted registry uninstall commands while
  preserving their arguments.
- Match final-newline regex anchors and reject positional inline options
  whose behavior differs on Python 3.4.
- Provide project-local configuration for automatic native async polling.
- Preserve ordinary permission insertion beside mixed ACL entries, report
  common callback audit rules and retain upstream's identity-wide audit removal.
- Match common conditional file and registry permissions before insertion and
  remove matched rights without rewriting retained callback conditions.
- Remove obsolete passwordless Runas and asynchronous escalation restrictions
  from module help.
- Gather native facts in parallel with Runas and isolate fact collectors in
  restricted legacy process jobs without changing connection job policy.
- Support passwordless named-user Runas through eligible token reuse and native
  S4U logon where available.
- Retry conclusive, pre-work Windows Update worker startup rejections once as
  SYSTEM, preserving ownership and avoiding retries of uncertain or started work.
- Preserve space-containing interpreter paths in CMD housekeeping, payloads and
  native Runas commands.
- Honor resolved module defaults during parallel fact gathering.
- Acquire SYSTEM tokens on older Windows without persistent privilege grants.
- Use installed classic DNS, DHCP, routing, firewall and servicing facilities
  when their modern management providers are unavailable.
- Support native HTTP origin and proxy authentication, certificate trust and
  client certificates, with documented legacy limitations.
- Preserve supplied service and DSC credentials through native execution.
