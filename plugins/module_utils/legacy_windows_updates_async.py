# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Wait for one native update round using the released async result contract."""

import legacy_windows_updates_worker as worker  # pylint: disable=import-error


def _com_message(error, hresult):
    message = error["message"]
    prefix, marker, native = message.rpartition("WUA.")
    suffix = " failed (HRESULT 0x{0:08X}).".format(hresult)
    if marker and native.endswith(suffix) and native[: -len(suffix)].isidentifier():
        # Native IDispatch uses this exact diagnostic only when EXCEPINFO has
        # no description. The released COM async default exposes the HRESULT
        # without our API-operation wrapper; preserve actual descriptions.
        message = prefix + "Exception from HRESULT: 0x{0:08X}".format(hresult)
    description = error.get("hresult_description")
    if description and description.strip():
        message += " - {0} (Windows Update HRESULT 0x{1:08X})".format(
            description.strip(), hresult
        )
    return message


def _receive(result, updates, packet):
    name, value = packet["task"], packet["result"]
    if name == "search_result":
        filtered = {row["id"]: row["reasons"] for row in value["filtered"]}
        for row in value["updates"]:
            info = {
                "id": row["id"],
                "title": row["title"],
                "categories": list(row["categories"]),
                "kb": [
                    item[2:] if item.startswith("KB") else item for item in row["kb"]
                ],
                "downloaded": False,
                "installed": False,
            }
            if row["id"] in filtered:
                info["filtered_reasons"] = list(filtered[row["id"]])
            updates[row["id"]] = info
    elif name in ("download_result", "install_result"):
        for row in value["info"]:
            info = updates[row["id"]]
            if row["result_code"] != 2:
                # The released async path retains the raw HRESULT and does not
                # add the synchronous controller's failure_msg description.
                info["failure_hresult_code"] = row["hresult"]
            else:
                info["downloaded" if name == "download_result" else "installed"] = True
    elif name == "exit":
        for field in ("changed", "reboot_required", "failed"):
            result[field] = value[field]
        error = value.get("exception")
        if error:
            result["msg"] = error["message"]
            result["exception"] = error.get("exception")
            if error.get("hresult"):
                # The worker retains UInt32 HRESULTs for synchronous controller
                # lookup. Released target-side async exposes COMException's
                # signed Int32 instead. Keep that field while enriching the
                # message with an available native description.
                hresult = error["hresult"] & 0xFFFFFFFF
                result["hresult"] = (
                    hresult - 0x100000000 if hresult >= 0x80000000 else hresult
                )
                result["msg"] = _com_message(error, hresult)


def wait(options):
    """Return one complete update result while the core async wrapper supervises us.

    :param dict options: Bound public options for the dedicated native worker.
    :returns: The complete released target-side async update result.
    :rtype: dict
    :raises OSError: Worker launch, polling or cooperative cleanup fails.
    :raises ValueError: Progress packets or ownership options are invalid.
    """
    result = {
        "changed": False,
        "reboot_required": False,
        "rebooted": False,
        "found_update_count": 0,
        "failed_update_count": 0,
        "installed_update_count": 0,
        "updates": {},
        "filtered_updates": {},
    }
    updates = {}
    started = worker.start(options, supervised=True)
    polling = dict(started["poll_options"])
    try:
        finished = False
        while not finished:
            response = worker.poll(polling)
            for packet in response["output"]:
                _receive(result, updates, packet)
                finished = finished or packet["task"] == "exit"
            polling = dict(polling, offset=response["offset"])
    finally:
        worker.cancel(started["cancel_options"])
    for info in updates.values():
        if "filtered_reasons" in info:
            result["filtered_updates"][info["id"]] = info
            continue
        result["updates"][info["id"]] = info
        result["found_update_count"] += 1
        if "failure_hresult_code" in info:
            result["failed_update_count"] += 1
        elif info["installed"]:
            result["installed_update_count"] += 1
    return result
