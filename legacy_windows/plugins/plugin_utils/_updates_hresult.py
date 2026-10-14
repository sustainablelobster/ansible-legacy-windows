"""Format Windows Update codes and available native descriptions."""

# SPDX-License-Identifier: GPL-3.0-or-later


def describe_hresult(hresult: int, description: str | None = None) -> str:
    """Return a diagnostic retaining the unsigned hexadecimal result code.

    :param hresult: HRESULT reported by Windows or the controller update loop.
    :param description: Optional localized message captured on the target.
    :returns: Native description and code, or the code when no description exists.
    """
    code = f"Windows Update HRESULT 0x{hresult & 0xFFFFFFFF:08X}"
    message = description.strip() if description else ""
    return f"{message} ({code})" if message else code
