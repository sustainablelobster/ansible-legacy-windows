"""Keep the status wrapper bounded to the maintained paired HTTP fixture."""

# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any

import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


def _yaml(relative: str) -> Any:
    return yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))


def test_status_wrapper_reuses_existing_requests_and_cleanup() -> None:
    plays = _yaml("tests/integration/uri_status.yml")
    assert plays[1]["ansible.builtin.import_playbook"] == "win_uri.yml"
    assert plays[2]["tasks"][-1]["ansible.builtin.meta"] == "reset_connection"
    tasks = plays[0]["tasks"]
    assert tasks[0]["ansible.builtin.raw"].find("command_inputs_observer") >= 0
    assert "BC-24-11-3E-87-91" in str(tasks[1]["ansible.builtin.assert"])
    assert (
        "[Net.HttpStatusCode]" in tasks[2]["ansible.windows.win_powershell"]["script"]
    )
    binding = tasks[-1]["ansible.builtin.set_fact"]
    assert binding == {"uri_cases": "{{ uri_status_cases }}", "uri_compare": True}


def test_status_cases_have_no_eager_future_workspace_reference() -> None:
    cases = _yaml("tests/integration/vars/uri_status.yml")["uri_status_cases"]
    assert len(cases) == 3
    assert "get_url_setup_data" not in str(cases)
    assert cases[0]["params"] == {"return_content": True}
    assert cases[1]["params"] == {
        "url": "http://127.0.0.1:52771/status/206",
        "return_content": True,
        "status_code": [206],
    }
    assert cases[2]["params"] == {
        "url": "http://127.0.0.1:52771/status/206",
        "return_content": True,
    }
    assert cases[2]["failed"] is True and cases[2]["elapsed"] == 0
    fixture = _yaml("tests/integration/vars/uri_fixture.yml")
    assert "Server(('127.0.0.1', 52771), Handler)" in fixture["get_url_server"]
    # Decode the exact embedded native fixture, not a separate replacement.
    compile(fixture["get_url_server"], "<maintained URI fixture>", "exec")
