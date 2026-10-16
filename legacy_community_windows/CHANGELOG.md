# Changelog

## 1.0.0

- Implement all 55 module interfaces and the LAPS lookup from the recorded
  community.windows 3.3.0 release, with its redirects and removed-module notices.
- Use Python 3.4.4-compatible native Windows payloads through the separately
  versioned sustainablelobster.legacy_windows 1.2.0 runtime.
- Add native storage, IIS, Remote Desktop Gateway, scheduling, networking,
  file and system management, plus installed vendor-tool integrations.
- Record real controller-to-Windows demonstrations, meaningful provider
  limitations and upstream differences in the coverage and module documentation.
- Preserve available disk facts when a driver returns malformed optional device
  strings, retaining WMI fallbacks and reporting the affected fields as warnings.
- Correct Robocopy change reporting and prediction for purge-only deletions
  without changing native return codes or explicit-flag precedence.
- Persist an explicitly empty application-pool runtime on first creation without
  a corrective second apply, and return committed inherited settings instead of
  transient schema defaults.
