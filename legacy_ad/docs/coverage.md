# Implementation and execution coverage

Reference: `microsoft.ad` 1.12.1, commit
`0449b870af3054ea8b02c5d5b70764138ce34bb7`.

Version 1.0.0 implements all 25 first-party modules, six filters and LDAP
inventory in the recorded upstream release. Implementations check actual
directory and service capabilities rather than excluding whole modules by
Windows version. Shared
alias/credential/default-application fixes and Unicode promotion passwords have
actual Python 3.4.4 execution evidence. Earlier reviewed evidence is retained
where the tested behavior and its dependencies are unchanged. Controller tests
and packaging are not substitutes for Windows execution evidence.

Installed directory lifecycles and online/offline membership workflows ran on
isolated Server 2008 R2 guests using Python 3.4.4. Online membership also ran on
XP; read-only directory queries ran on XP and Windows 7. The computer lifecycle,
including DES encryption flags, ran on Windows 7. New-domain promotion and
functional-level completion ran on Server 2003. Replica, child and tree-domain
lifecycles and certificate authority/template lifecycles ran on Server 2008 R2.
Paired Server 2003/R2 forests passed fresh bilateral Kerberos authentication.
These environments are execution observations, not an allowlist or a claim
that every option works on every Windows version or directory schema.

| Family                 | Interfaces                                                              | Current status                                                                                   |
| ---------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Directory objects      | `object_info`, `object`, `ou`, `user`, `group`, `computer`              | Installed Windows lifecycles passed; increments reviewed                                         |
| Topology               | `site`, `site_link`, `site_subnet`                                      | Installed Windows lifecycle passed; increment reviewed                                           |
| Policy                 | `pso`, `gpo`                                                            | Installed Windows lifecycles passed; increments reviewed                                         |
| Membership             | `membership`, `offline_join`                                            | R2 online/offline and XP combined join/rename, reboot and restoration passed; increment reviewed |
| Domains                | `domain`, `domain_child`, `domain_controller`                           | Server 2003 DHCP promotion/reboot and R2 replica/child/tree lifecycles passed                    |
| Trusts                 | `domain_trust`                                                          | Paired forest lifecycle and fresh bilateral Kerberos passed twice; increment reviewed            |
| Certificate services   | `cs_authority`, `cs_template`                                           | R2 authority/template lifecycles, vendor readback and restoration passed; increment reviewed     |
| Controller diagnostics | `debug_ldap_client`                                                     | Installed controller action and check mode passed; implementation reviewed                       |
| Controller filters     | `as_datetime`, `as_guid`, `as_sid`, `dn_escape`, `parse_dn`, `split_dn` | Controller tests passed; implementation reviewed                                                 |
| Controller inventory   | `ldap`                                                                  | Encrypted NTLM inventory passed against the real directory; implementation reviewed              |
| KDS                    | `kds_root_key`, `kds_root_key_info`                                     | Capable-DC and R2 executor lifecycle, vendor acceptance and cleanup passed; increment reviewed   |
| Managed accounts       | `service_account`                                                       | R2 lifecycle, password retrieval, permission revocation and cleanup passed; increment reviewed   |
| Federation             | `fs_trust`, `fs_claim_rule`                                             | AD FS 2.0 trust, claims, HTTPS metadata and cleanup passed; increment reviewed                   |

Online membership evidence includes combined join-and-rename workflows on XP
and R2. Offline provisioning and blob consumption were exercised on R2.
The tests independently checked active and pending hostnames, restored the
original workgroups and removed acquired directory accounts. Offline evidence
also includes the native secure-channel utility's reported status, not a fresh
active-authentication probe.

Trust evidence includes independently absent initial relationships, distinct
unique users, home-forest Kerberos qualification, denied foreign authentication
before creation, both local-side creations and native routing preparation.
Both repeated runs checked the actual foreign principals, negotiated Kerberos,
signing, encryption and protected directory reads, followed by option previews,
idempotence and normal acquired-resource removal. Native preparation requires
the forest-root PDCs and is separate from the public local-side module.

Role tests verified requested reboots, fresh native roles and directory
identities, functional levels, normal/check repeats and preservation of the
original forest. Cleanup and recovery are recorded separately from public task
results: initial child cleanup required an owned-guest reset after normal
demotion; tree cleanup required bounded DNS preparation and a normal retry.
Child/tree cleanup used no rollback or forced controller removal. Disposable
lab clones were removed after the proofs; original guests and host networking
were preserved.

An independent black-box audit exposed a Server 2003 promotion stall: native
DNS setup waited on a hidden DHCP/static-address warning after the directory
operation completed. The correction installs missing requested DNS quietly
before promotion, without rebooting or disabling DHCP. Fresh packaged runs on
Server 2003 with Python 3.4.4 passed with default paths and an ASCII password,
and with custom ASCII paths and a Unicode password. Both runs verified check
mode, requested reboot, native DC role, domain and forest levels of `2`, running
DNS, unchanged repetition and temporary-file/process cleanup. The default-path
run also verified that DHCP remained enabled. A separate fresh-host run with
`reboot: false` returned `reboot_required: true` with DNS running, unchanged boot
time, the native pending-controller role and no remaining temporary files.

## Independent black-box retest

The corrected 1.0.0 archive passed an independent black-box retest without
reading the implementation or repository tests. Fresh Server 2003 promotion
completed with automatic reboot, native DC-role readback, domain and forest
levels of `2`, and an unchanged repeat. A second fresh promotion with
`reboot: false` preserved the boot identity, reported the pending reboot and
left no answer files or DCPromo processes. After an explicitly requested reboot,
native reads confirmed the usable controller and documented default levels of
`0`. The previous promotion timeout did not recur.

The targeted regression audit exercised 18 module interfaces, LDAP inventory
and all six filters on XP, Server 2003 R2 and Server 2025. Its selected suites
recorded 147 successful task results and 10 intentional invalid-input or
missing-prerequisite rejections checked by subsequent assertions. These are
task outcomes, not 157 independent tests. Native reads verified directory
lifecycle state, topology, policy, managed accounts, KDS and inventory data.
No new product defects were found in the retested paths.

This was targeted regression coverage, not full acceptance of every module,
option or platform. Child/tree and replica promotion, non-FSMO demotion, trusts,
membership/offline join, certificate services and federation were not rerun in
this patch audit. Nor were the Vista/Windows 7/Server 2008 R2 execution matrix,
managed-password authentication, large-directory paging or all inventory
authentication/TLS variants. Earlier evidence remains separate. A supplementary
fresh-SSH cleanup probe timed out; accepted pre-reboot native reads independently
verified answer-file and process cleanup. The audit restored its disposable
fixtures and reported no new product defect from these harness observations.

## Retained execution and controller checks

Recovery additionally verified conflicting and explicit-null account aliases,
cross-forest ambient/named credential precedence, Unicode promotion passwords,
native functional-level/path readback, and nonmutating failures for missing
KDS/gMSA schemas and the federation engine. The earlier reviewed workflows above
remain applicable where their tested behavior and dependencies are unchanged;
new argument-validation corrections have also passed independent review.

At the AD 1.0.0 verification checkpoint, the combined controller suite passed
15,419 tests. Two datetime cases were skipped because their reference timezone
conversion underflows or overflows outside the parser contract; two TLS-fixture
deprecation warnings were also recorded. Full lint and offline-package checks
passed at that checkpoint. Later focused correction checks passed without
rerunning unchanged workflows. These retained results are not a count of the
current repository suite and complement, rather than replace, actual
Python 3.4.4 execution on Windows.

The five upstream actions belong to `debug_ldap_client`, `domain`,
`domain_child`, `domain_controller`, and `membership`; their public behavior is
covered with the corresponding module. Helpers and documentation fragments
are part of those increments, not separately claimed features.
