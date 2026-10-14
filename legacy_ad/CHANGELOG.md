# Changelog

## 1.0.0

- Add native Python 3.4.4-compatible directory object, account, group, computer,
  organizational unit, site, site-link and subnet management.
- Add password policy and Group Policy link management.
- Add online domain membership, combined join-and-rename workflows and native
  offline join provisioning and consumption.
- Add native forest, child-domain, tree-domain and replica-controller promotion,
  verified reboot handling and controller demotion.
- Add local-side trust management, with separately documented native forest
  routing preparation and paired Kerberos integration tests.
- Add certificate authority and certificate template management.
- Add controller LDAP inventory, directory filters and LDAP diagnostics.
- Preserve familiar interfaces against `microsoft.ad` 1.12.1, with documented
  capability requirements and meaningful legacy differences.
- Add native KDS root-key creation, information and removal with Windows
  group-key acceptance checks.
- Add managed service account lifecycles and password-retrieval permissions.
- Add relying-party trust and claim-rule management through installed AD FS
  vendor commands, including the legacy AD FS 2.0 snap-in.
- Preserve released account aliases, foreign-lookup credential precedence,
  case-insensitive choices and signed 32-bit integer validation.
- Support Unicode promotion passwords through protected UTF-16 answer files.
- Install missing requested DNS quietly before older-engine promotion, avoiding
  hidden setup prompts on DHCP hosts without disabling DHCP or rebooting early.
- Use `sustainablelobster.legacy_windows` 1.1.0's shared execution runtime;
  package and release the two collections independently.
