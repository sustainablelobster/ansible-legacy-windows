# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Search, select, download and install updates through native WUA objects."""

import os
import subprocess
import traceback

from legacy_windows_reboot_request import observe_boot  # pylint: disable=import-error
from legacy_windows_regex import search  # pylint: disable=import-error
from legacy_windows_updates_native import (  # pylint: disable=import-error
    UpdateAgent,
    hresult_description,
)

_RESULT_NAMES = (
    "NotStarted",
    "InProgress",
    "Succeeded",
    "SuceededWithErrors",
    "Failed",
    "Aborted",
)
_CATEGORY_NAMES = {
    "criticalupdates": "Critical Updates",
    "definitionupdates": "Definition Updates",
    "developerkits": "Developer Kits",
    "featurepacks": "Feature Packs",
    "securityupdates": "Security Updates",
    "servicepacks": "Service Packs",
    "updaterollups": "Update Rollups",
}
_ENUMS = {
    "type": (1, ("Software", "Driver")),
    "deployment_action": (0, ("None", "Installation", "Uninstallation", "Detection")),
    "impact": (0, ("Normal", "Minor", "RequiresExclusiveHandling")),
    "reboot_behaviour": (
        0,
        ("NeverReboots", "AlwaysRequiresReboot", "CanRequestReboot"),
    ),
    "auto_selection": (
        0,
        (
            "LetWindowsUpdateDecide",
            "AutoSelectIfDownloaded",
            "NeverAutoSelect",
            "AlwaysAutoSelect",
        ),
    ),
    "auto_download": (
        0,
        ("LetWindowsUpdateDecide", "NeverAutoDownload", "AlwaysAutoDownload"),
    ),
}
_PROGRESS_FIELDS = {
    "Download": (
        "CurrentUpdateBytesDownloaded",
        "CurrentUpdateBytesToDownload",
        "CurrentUpdateDownloadPhase",
        "CurrentUpdateIndex",
        "CurrentUpdatePercentComplete",
        "PercentComplete",
        "TotalBytesDownloaded",
        "TotalBytesToDownload",
    ),
    "Install": (
        "CurrentUpdateIndex",
        "CurrentUpdatePercentComplete",
        "PercentComplete",
    ),
}


def _enum(name, value):
    offset, names = _ENUMS[name]
    index = value - offset
    return names[index] if 0 <= index < len(names) else "Unknown {0}".format(value)


def _metadata(update):
    identity = update.get("Identity")
    behavior = update.get("InstallationBehavior")
    result = {
        "id": identity.get("UpdateID"),
        "title": update.get("Title"),
        "description": update.get("Description"),
        "kb": ["KB" + str(value) for value in update.get("KBArticleIDs").items()],
        "revision_number": identity.get("RevisionNumber"),
        "categories": [value.get("Name") for value in update.get("Categories").items()],
    }
    for name, property_name in (
        ("auto_select_on_websites", "AutoSelectOnWebSites"),
        ("browse_only", "BrowseOnly"),
        ("is_installed", "IsInstalled"),
        ("is_hidden", "IsHidden"),
        ("is_present", "IsPresent"),
        ("reboot_required", "RebootRequired"),
        ("is_beta", "IsBeta"),
        ("is_downloaded", "IsDownloaded"),
        ("is_mandatory", "IsMandatory"),
        ("is_uninstallable", "IsUninstallable"),
    ):
        result[name] = update.get(property_name)
    for name, property_name, owner in (
        ("type", "Type", update),
        ("deployment_action", "DeploymentAction", update),
        ("impact", "Impact", behavior),
        ("reboot_behaviour", "RebootBehavior", behavior),
        ("auto_selection", "AutoSelection", update),
        ("auto_download", "AutoDownload", update),
    ):
        result[name] = _enum(name, owner.get(property_name))
    return result


def _matches(info, expressions):
    # Released string-plus-array binding forms one title/KB string, with spaces
    # only between KB entries. Separate candidates change anchored expressions
    # and therefore which updates may have EULAs accepted or be serviced.
    candidate = info["title"] + " ".join(info["kb"])
    return not expressions or any(
        search(candidate, expression) for expression in expressions
    )


def _filtered(info, options):
    reasons = []
    if not _matches(info, options["accept_list"]):
        reasons.append("accept_list")
    if options["reject_list"] and _matches(info, options["reject_list"]):
        reasons.append("reject_list")
    if info["is_hidden"]:
        reasons.append("hidden")
    categories = [value.lower() for value in info["categories"]]
    requested = options["category_names"]
    if requested and not any(
        value == "*" or _CATEGORY_NAMES.get(value.lower(), value).lower() in categories
        for value in requested
    ):
        reasons.append("category_names")
    if options["skip_optional"] and info["browse_only"]:
        reasons.append("skip_optional")
    return reasons


def _progress(phase, updates, emit):
    def receive(native):
        fields = {name: native.get(name) for name in _PROGRESS_FIELDS[phase]}
        index = fields["CurrentUpdateIndex"]
        fields["CurrentUpdateId"] = updates[index].get("Identity").get("UpdateID")
        result = native.call("GetUpdateResult", index)
        values = {name: result.get(name) for name in ("HResult", "ResultCode")}
        if phase == "Install":
            values["RebootRequired"] = result.get("RebootRequired")
        emit(phase.lower(), {"progress": fields, "result": values})

    return receive


def _defender(update, result, log):
    executable = os.path.join(
        os.environ.get("ProgramFiles", ""), "Windows Defender", "MpCmdRun.exe"
    )
    if (
        result["result_code"] == 2
        or "2267602" not in update.get("KBArticleIDs").items()
        or not os.path.exists(executable)
    ):
        return
    for arguments in (
        ("-RemoveDefinitions", "-DynamicSignatures"),
        ("-SignatureUpdate",),
    ):
        command = [executable] + list(arguments)
        log("Running defender command " + subprocess.list2cmdline(command))
        with subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as process:
            stdout, stderr = process.communicate()
        log(
            "Defender command result - RC: {0}\nSTDOUT:\n{1}\nSTDERR:\n{2}".format(
                process.returncode,
                stdout.decode("mbcs", "replace"),
                stderr.decode("mbcs", "replace"),
            )
        )
    if process.returncode == 0:
        result["result_code"], result["hresult"] = 2, 0


# This internal resource-bound round has no public object API; run is its entry.
class _Round:  # pylint: disable=too-few-public-methods
    """One native WUA round with its fixed protocol and cancellation callbacks."""

    def __init__(self, options, emit, cancelled, log):
        self.options, self.emit, self.cancelled, self.log = (
            options,
            emit,
            cancelled,
            log,
        )
        self.agent, self.session = None, None
        self.final = {
            "changed": False,
            "failed": False,
            "reboot_required": False,
            "exception": None,
            "action": None,
        }

    def _operation(self, target, phase, updates):
        labels = {
            "Search": "Searching",
            "Download": "Downloading",
            "Install": "Installing",
        }
        try:
            return self.agent.operation(
                target,
                phase,
                "IsInstalled = 0" if phase == "Search" else None,
                self.cancelled,
                _progress(phase, updates, self.emit) if phase != "Search" else None,
            )
        except Exception as error:  # pylint: disable=broad-exception-caught
            # Preserve native HRESULTs and annotate the actual failed phase.
            error.update_action = labels[phase] + (
                " for updates" if phase == "Search" else " updates"
            )
            raise

    def _search(self):
        self.log("Searching for updates to install with query 'IsInstalled = 0'")
        searcher = self.session.call("CreateUpdateSearcher")
        searcher.put(
            "ServerSelection",
            {"default": 0, "managed_server": 1, "windows_update": 2}[
                self.options["server_selection"]
            ],
        )
        result = self._operation(searcher, "Search", [])
        code = result.get("ResultCode")
        if code not in (2, 3):
            name = _RESULT_NAMES[code] if 0 <= code < len(_RESULT_NAMES) else str(code)
            raise OSError("Failed to search for updates ({0} {1})".format(name, code))
        if code == 3:
            for warning in result.get("Warnings").items():
                self.log(
                    "Search warning - Context {0} - HResult 0x{1:08X} - Message: {2}".format(
                        warning.get("Context"),
                        warning.get("HResult") & 0xFFFFFFFF,
                        warning.get("Message"),
                    )
                )
        updates, filtered, selected = [], [], []
        for update in result.get("Updates").items():
            info = _metadata(update)
            updates.append(info)
            reasons = _filtered(info, self.options)
            if reasons:
                filtered.append({"id": info["id"], "reasons": reasons})
                self.log(
                    "Skipping update {0} due to {1}".format(
                        info["id"], ", ".join(reasons)
                    )
                )
            else:
                if not update.get("EulaAccepted"):
                    self.log("Accepting EULA for " + info["id"])
                    update.call("AcceptEula")
                selected.append(update)
                self.log("Adding update " + info["id"])
        self.log("Found {0} updates".format(len(updates)))
        self.emit("search_result", {"updates": updates, "filtered": filtered})
        return selected

    def _transfer(self, phase, updates):
        collection = self.agent.collection(updates)
        target = self.session.call(
            "CreateUpdateDownloader" if phase == "Download" else "CreateUpdateInstaller"
        )
        target.put("Updates", collection)
        if phase == "Install":
            target.put("AllowSourcePrompts", False)
            target.put("ClientApplicationID", "ansible.windows.win_updates")
        self.log(
            "Downloading updates..." if phase == "Download" else "Installing updates..."
        )
        native = self._operation(target, phase, updates)
        results = []
        for index, update in enumerate(updates):
            current = native.call("GetUpdateResult", index)
            result = {
                "id": update.get("Identity").get("UpdateID"),
                "result_code": current.get("ResultCode"),
                "hresult": current.get("HResult"),
            }
            if result["result_code"] != 2:
                description = hresult_description(result["hresult"])
                if description:
                    result["hresult_description"] = description
            if phase == "Install":
                result["reboot_required"] = current.get("RebootRequired")
                _defender(update, result, self.log)
            self.log(
                "{0} result for {1} - ResultCode: {2}, HResult: {3}".format(
                    phase, result["id"], result["result_code"], result["hresult"]
                )
            )
            results.append(result)
        return results

    def _execute(self, agent):
        # This private round is the only caller; the method's native owner is
        # explicit and its emitted progress is the return protocol.
        self.agent = agent
        self.final["reboot_required"] = agent.reboot_required()
        self.log("Reboot requirement check: " + str(self.final["reboot_required"]))
        self.log("Creating Windows Update session...")
        self.session = agent.create_session()
        if self.options["test"]:
            searcher = self.session.call("CreateUpdateSearcher")
            searcher.put(
                "ServerSelection",
                {"default": 0, "managed_server": 1, "windows_update": 2}[
                    self.options["server_selection"]
                ],
            )
            return
        selected = self._search()
        if (
            self.options["check_mode"]
            or self.options["state"] == "searched"
            or not selected
        ):
            self.final["changed"] = (
                bool(selected) and self.options["state"] != "searched"
            )
            return
        if self.final["reboot_required"]:
            raise OSError("A reboot is required before more updates can be installed")
        downloading = [update for update in selected if not update.get("IsDownloaded")]
        if downloading:
            results = self._transfer("Download", downloading)
            self.final["changed"] = True
            self.emit("download_result", {"info": results})
            if any(value["result_code"] != 2 for value in results):
                raise OSError(
                    "Failed to download all updates - see updates for more information"
                )
        if self.options["state"] != "downloaded":
            results = self._transfer("Install", selected)
            self.final["changed"] = True
            self.final["reboot_required"] = any(
                value["reboot_required"] for value in results
            )
            self.emit("install_result", {"info": results})
            if any(value["result_code"] != 2 for value in results):
                raise OSError(
                    "Failed to install all updates - see updates for more information"
                )
            self.final["reboot_required"] = agent.reboot_required()
            self.log(
                "Post-install reboot requirement " + str(self.final["reboot_required"])
            )


def run(options, emit, cancelled, log, agent_factory=UpdateAgent):
    """Emit one released update round, including its final failure packet.

    :param dict options: Bound public options, check mode and access-only test flag.
    :param emit: Callable accepting a packet name and JSON-serializable result.
    :type emit: callable
    :param cancelled: Callable reporting whether cancellation was requested.
    :type cancelled: callable
    :param log: Callable appending diagnostics to the requested log, if any.
    :type log: callable
    :param agent_factory: Native WUA resource-owner factory.
    :type agent_factory: callable
    :raises OSError: Writing the progress protocol fails.
    """
    update_round = _Round(options, emit, cancelled, log)
    boot_time = None
    try:
        boot = observe_boot()
        if boot["rc"]:
            raise OSError("Could not read boot time: " + boot["stderr"])
        boot_time = boot["stdout"]
        emit("started", {})
        with agent_factory() as agent:
            update_round._execute(agent)  # pylint: disable=protected-access
    except Exception as error:  # pylint: disable=broad-exception-caught
        # The dedicated worker reports native and progress-consumer failures as
        # a final packet instead of crashing and stranding the controller.
        final = update_round.final
        final["failed"] = True
        message = str(error)
        if getattr(error, "update_action", None):
            message = error.update_action + ": " + message
        exception = {"message": message, "exception": traceback.format_exc()}
        if hasattr(error, "hresult"):
            exception["hresult"] = error.hresult
            description = hresult_description(error.hresult)
            if description:
                exception["hresult_description"] = description
            if error.hresult & 0xFFFFFFFF == 0x8007045B and boot_time is not None:
                exception["_is_rebooting_last_boot_time"] = boot_time
        final["exception"] = exception
        if getattr(error, "cleanup_error", None):
            log("Secondary native cleanup failure: " + error.cleanup_error)
    emit("exit", update_round.final)
