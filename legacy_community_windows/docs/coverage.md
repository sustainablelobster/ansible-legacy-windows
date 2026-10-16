# Implementation and execution coverage

Reference: `community.windows` 3.3.0, commit
`20464e72482c5d4c75af13a2fd62966339cf5ffc`.

Version 1.0.0 implements 55 module interfaces, one LAPS lookup,
session-configuration action behavior, 24 redirects and six removed-module
tombstones. The maintained contract inventory checks this scope against the
recorded release.

Every Windows demonstration below uses the installed collection through Ansible
and the actual Python 3.4.4 interpreter. These observations cover the named
workflows, not every option or every Windows environment. Controller checks
and package installation are not substitutes for target execution. Reviews
cover implementation, tests and documentation; they do not imply independent
repetition of every lab demonstration.

| Module                        | Implementation and evidence                                    |
| ----------------------------- | -------------------------------------------------------------- |
| `psexec`                      | SMB demo on Server 2025; review passed                         |
| `win_data_deduplication`      | Native volume lifecycle on Server 2025; review passed          |
| `win_defrag`                  | Owned-volume demo on Windows 7; review passed                  |
| `win_disk_facts`              | Native facts on XP/2003/Vista/7/2008 R2/2025; review passed    |
| `win_disk_image`              | VHD on Windows 7; ISO/VHDX on Server 2025; review passed       |
| `win_dotnet_ngen`             | NGen32/64 demo on Server 2025; review passed                   |
| `win_eventlog_entry`          | Demo on XP/2003/7; core review passed                          |
| `win_file_version`            | Demo on XP/2003/7; core review passed                          |
| `win_firewall_rule`           | Port/application demos on XP/7; review passed                  |
| `win_format`                  | Native NTFS format demo on Windows 7; review passed            |
| `win_iis_virtualdirectory`    | IIS 6/7.5 demos on Server 2003/2008 R2; review passed          |
| `win_iis_webapplication`      | IIS 6/7.5 demos on Server 2003/2008 R2; review passed          |
| `win_iis_webapppool`          | IIS 6/7.5 demos on Server 2003/2008 R2; review passed          |
| `win_iis_webbinding`          | IIS 7.5 HTTPS demo on Server 2008 R2; review passed            |
| `win_iis_website`             | IIS 6/7.5 demos on Server 2003/2008 R2; review passed          |
| `win_initialize_disk`         | Native MBR/GPT demo on Windows 7; review passed                |
| `win_lineinfile`              | Demo on XP/2003/7; core review passed                          |
| `win_msg`                     | Demo on XP/2003/2025; review passed                            |
| `win_net_adapter_feature`     | Native binding change and restore on XP/7; review passed       |
| `win_netbios`                 | Demo on XP/2003/7; review passed                               |
| `win_nssm`                    | Service demo on XP/2003/7/2025; review passed                  |
| `win_pagefile`                | Size/global-mode demos on XP/7; review passed                  |
| `win_partition`               | Native partition lifecycle on Windows 7; review passed         |
| `win_pester`                  | Pester 3.4 demo on Windows 7/Server 2025; review passed        |
| `win_power_plan`              | Demo on XP/2003/7; review passed                               |
| `win_psexec`                  | Real child output/status demo on Server 2025; review passed    |
| `win_psmodule`                | Local repository lifecycle demo on Server 2025; review passed  |
| `win_psmodule_info`           | Metadata demo on Server 2025; review passed                    |
| `win_psrepository`            | Local repository lifecycle demo on Server 2025; review passed  |
| `win_psrepository_copy`       | Native serializer demo on Windows 7/Server 2025; review passed |
| `win_psrepository_info`       | Query demo on Server 2025; review passed                       |
| `win_psscript`                | Local repository lifecycle demo on Server 2025; review passed  |
| `win_psscript_info`           | Installed-script query on Server 2025; review passed           |
| `win_pssession_configuration` | Endpoint lifecycle on Server 2025; review passed               |
| `win_rabbitmq_plugin`         | Real RabbitMQ/Erlang lifecycle on Server 2025; review passed   |
| `win_rds_cap`                 | Native gateway policies on Server 2008 R2; review passed       |
| `win_rds_rap`                 | Native gateway policies on Server 2008 R2; review passed       |
| `win_rds_settings`            | Gateway settings/certificate on Server 2008 R2; review passed  |
| `win_regmerge`                | Demo on XP/2003/7; review passed                               |
| `win_robocopy`                | Copy/purge demos on Vista/7/2008 R2/2025; review passed        |
| `win_say`                     | Speech and WAV demo on Windows 7; review passed                |
| `win_scheduled_task`          | Task execution on XP/2003/7; review passed                     |
| `win_scheduled_task_stat`     | Task metadata on XP/2003/7; review passed                      |
| `win_scoop`                   | Real Scoop package lifecycle on Server 2025; review passed     |
| `win_scoop_bucket`            | Real Scoop bucket lifecycle on Server 2025; review passed      |
| `win_security_policy`         | Policy change and restore on XP; review passed                 |
| `win_shortcut`                | Demo on XP/2003/7; review passed                               |
| `win_snmp`                    | Demo on Server 2008 R2; review passed                          |
| `win_toast`                   | Native notification API on Server 2025; review passed          |
| `win_unzip`                   | ZIP/GZip on XP/2003/7; TAR/BZ2/CAB on XP/7; review passed      |
| `win_wait_for_process`        | Demo on XP/2003/7; core review passed                          |
| `win_wakeonlan`               | Demo on XP/2003/7; core review passed                          |
| `win_webpicmd`                | Real CLI failure on retired feed; install positive unavailable |
| `win_xml`                     | Demo on XP/2003/7; review passed                               |
| `win_zip`                     | Demo on XP/2003/7; review passed                               |

The `laps_password` lookup has real authenticated LDAPS and StartTLS evidence
against an installed legacy LAPS schema. Default trust rejected the disposable
self-signed certificate. Independent implementation review passed.

## Demonstrated workflows

- Line editing: UTF-16 and Unicode, aliases, backreferences, backups, unchanged
  repetition, validator failure preserving the original, preview without
  creation, removal, insertion precedence and cleanup. Preview does not create
  a missing file, and `insertbefore` correctly takes precedence when both
  insertion selectors are supplied; these correct released upstream defects.
- Wake-on-LAN: captured 102-byte magic packet and a nonmutating preview. This
  proves sending, not that another machine actually woke.
- Event entries: native readback of Unicode message, identifier, warning type,
  category and raw bytes; nonmutating preview and missing-source rejection.
- Process waiting: check-mode presence, bounded timeout, native waiting on the
  initial PID, owner filtering, unchanged results and child/async-state cleanup.
  Waiting remains read-only, matching released behavior rather than conflicting
  upstream prose.
- File version: native version-resource lookup, unchanged check mode and
  missing-file failure.
- Disk images: a uniquely owned VHD, native persistent attachment, independent
  sentinel-file readback through the returned drive path, nonmutating previews,
  unchanged repeats, detachment and fixture cleanup. ISO and VHDX passed the
  same public-module lifecycle and independent file readback on Server 2025.
- Volume optimization: analysis-only preview, actual optimization and repeated
  analysis of the owned VHD volume, native status and preservation of its data.
  The released module reports `changed` even for analysis and returns nonzero
  utility exit codes without converting them into an Ansible failure.
- Formatting: native NTFS formatting of only the disposable volume, unchanged
  repetition, a preview preserving its sentinel, independent filesystem label
  and 4096-byte cluster readback, and removal of the owned image and runner.
- Disk initialization: a uniquely owned raw VHD, GPT and MBR creation,
  independent on-disk signature readback, unchanged repeats, nonmutating
  preview, an explicit force guard, clearing without reinitialization, and
  cleanup. A legacy driver reporting a raw disk as an empty MBR record with
  no signature is recognized without overwriting an existing initialized layout.
- Disk facts: real legacy disk layout, volume GUID and cluster-size readback;
  modern Storage-provider groups, native integer arrays, enum values and
  filtering. Repeated and check-mode queries remain unchanged. Missing legacy
  provider fields return nulls with warnings, not invented modern metadata.
  Default, empty-filter and individual-group reads additionally passed on XP,
  Server 2003, Vista, Windows 7, Server 2008 R2 and Server 2025. Invalid optional
  descriptor strings preserve usable metadata and identify the affected fields
  in warnings. Drivers rejecting the optional alignment query use the documented
  logical-sector fallback. Native descriptor readback used Python 3.4.4.
- Partitions: creation, NTFS growth and shrink, active/read-only/hidden/offline
  changes, drive-letter changes, repeats and deletion on a disposable VHD.
  A sentinel survived the changes. Hidden volumes are inspected through their
  native partition device paths, not nonexistent mount-manager GUID links.
  The modern provider also passed creation, growth, shrink and attribute changes.
  Its mounted-volume offline request returned error 42014; the independent
  Windows Storage cmdlet rejected the same request with the same error.
  An unchanged check-mode query of an existing partition also passed on all six
  disk-facts guests, exercising the shared reader without partition writes.
- Deduplication: role-service installation, real enable/configure/disable,
  independent vendor readback, default/minimum-size handling, previews,
  unchanged repeats and disposable-volume cleanup. The originally absent role
  was removed and its required cleanup restart completed.
- Pagefiles: native size changes, preview without writes, unchanged fixed-size
  repetition, query readback and restoration of the captured registry
  representation without rebooting. XP lacks the global automatic-mode field;
  it is returned as null with a warning, and explicit changes are rejected.
  Windows 7 additionally passed global automatic-mode transitions and unchanged
  repeats. The native write is limited to the requested ComputerSystem property;
  it does not rewrite unrelated privileged settings.
- XML: real XPath predicates and unions, Unicode text and attributes, nested
  elements, backups, unchanged repeats, nonmutating preview and cleanup.
- ZIP: files, Unicode names, empty directories, directory contents, unchanged
  existing destination, nonmutating preview and cleanup.
- Extraction: nested ZIP/GZip, deletion of compressed inputs, nonmutating
  preview, the intentional `creates` skip, traversal rejection and cleanup.
  XP and Windows 7 also passed TAR, TAR.GZ, TAR.BZ2, TAR.XZ, BZ2 and multi-file
  CAB extraction,
  exact output bytes, CAB preview and invalid-CAB failure preserving its source.
  Additional PSCX-only formats still need vendor-capability execution evidence.
- Registry import: Unicode input, real import/export comparison, unchanged
  repeats, changed values, native readback and cleanup.
- Shortcuts: native application and URL shortcuts, Unicode properties,
  administrator flags, unchanged repeats, nonmutating preview and cleanup.
- NetBIOS: named adapter selection, native setting changes, unchanged repeats,
  nonmutating preview and exact restoration of the original setting.
- SNMP: genuinely installed service, manager/community configuration, unchanged
  repeats, nonmutating preview and exact restoration including access levels.
- Robocopy: actual source/destination bytes, nonmutating preview, unchanged
  repeat and cleanup using the installed executable. Vista, Windows 7, Server
  2008 R2 and Server 2025 additionally passed deletion-only file/directory
  previews, apply and repeats, boolean and explicit purge/mirror options,
  explicit-flag precedence and exclusion controls. Purge-only changes are
  reported correctly; custom-selection limitations remain documented in Usage.
- NGen: installed 32-bit and 64-bit executables, preview, update and queued-item
  operations. This is execution evidence, not a performance claim.
- PowerShellGet: an owned local repository, registration and trust updates,
  real module and script installation, version upgrades, metadata queries,
  nonmutating previews, unchanged repeats, uninstallation and cleanup.
- Repository copying: actual vendor CLIXML deserialization of merged entries,
  filtering, force replacement, nonmutating previews, unchanged repeats and
  removal of the owned profile and temporary files.
- Pester: released Pester 3.4 on PowerShell 2 and on the modern reference host,
  tag selection, parameterized tests, real NUnit output, deliberate failed-test
  counts, a required-version failure and previews without report creation.
- IIS 7.5: site, binding, pool, application and virtual-directory lifecycles;
  nonmutating previews, unchanged repeats, HTTPS certificate assignment and
  a real HTTPS response with the expected content. An invalid attribute left
  the existing configuration unchanged; owned keys and endpoints were removed.
  Fresh pools on Server 2008 R2 and Server 2025 additionally passed `present`
  and `started` requests with empty, explicit and inherited runtimes. Independent
  AppCmd XML readback before the first repeat verified persisted settings;
  first-create and repeated results matched the effective native runtime.
  First repeats were unchanged, and previews committed no configuration.
- Controller PsExec: actual encrypted SMB service-backed execution, separate
  stdout/stderr, nonzero process status, repeat and detached PID. Its check-mode
  skip is intentional, matching the upstream interface.
- Installed PsExec: actual service-backed child output, error output and nonzero
  status with Microsoft's PsExec 2.43. Immediate-exit children intermittently
  lost standard output in both this implementation and the released upstream
  launcher in matched trials. The repeatable demonstration flushes its output
  and keeps the child alive briefly; reliable immediate-exit capture is not
  claimed.
- NSSM: actual installed tool, service creation, unchanged configuration repeat,
  startup, independent SCM readback and service cleanup. Redirected tool output
  is decoded using NSSM's UTF-16LE stream format.
- Power plans: legacy numeric schemes and modern GUID-based plans, name
  selection, nonmutating preview, native active-plan readback, unchanged repeat
  and restoration of the original scheme.
- Session messages: the installed messaging utility, a one-second message,
  nonmutating preview, length validation and native return status. This proves
  sending through the utility, not that a person saw the message.
- Speech: installed voice selection, unavailable-voice fallback warnings,
  nonmutating previews, Unicode text-file input, speech synthesis and WAV
  playback through the existing SSH connection. This requires an audio device;
  the test used a temporary virtual device and verified native completion,
  not physical audibility. Temporary text and sound files were removed.
- Scheduled tasks: native registration, unchanged repeats, description changes
  preserving actions, nonmutating previews, dotted names, names ending in
  `.job`, metadata, deletion and cleanup. Independent launch produced a file
  through the actual Python 3.4.4 interpreter on each guest. XP's `schtasks.exe`
  rejected the dotted name; an independent native `ITask.Run` call succeeded.
  Task Scheduler 1.0 cannot provide every newer setting or metadata field;
  unavailable settings fail before modification and unavailable facts use
  nulls with warnings.
- Security policy: native export, a narrow policy import, independent export
  verification, unchanged repetition, nonmutating preview, invalid-key failure
  and restoration of the original password policy. Unrelated legal-notice
  registry values are not normalized or rewritten.
- Remote Desktop Gateway: native CAP/RAP creation, updates, ordering, unchanged
  repeats, settings and certificate assignment on Server 2008 R2. A failure
  injected after certificate assignment was recovered by retrying the public
  module; subsequent repeats preserved the gateway, HTTPS endpoints and IIS
  configuration. Test policies, certificates and keys were removed.
- LAPS: authenticated LDAPS and StartTLS lookups against the legacy schema,
  trusted-certificate success and rejection under default trust. The temporary
  domain fixture was removed by verified rollback to its pretest snapshot.
- WebPI: the genuine WebPI 5.1 command fails against its retired default product
  feed. This is not a positive product-installation result. Installation needs
  a functioning vendor feed; a retired service is not replaced or simulated.

Missing prerequisites are not counted as positive execution coverage.
Capability-specific branches without a named demonstration are unverified,
not deliberately unsupported placeholders.
