"""An AI agent asking for root is flagged, never refused (process-level file protection, D7).

Amos 2026-11-22: "Blackbox needs to alert when an agent has obtained sudo access". These tests
cover the REQUEST (``detection.detect_elevation``, the ``agent:elevation-request`` finding) and
that the guard never refuses a call because of it.
"""

import pytest

from _blackbox_loader import load_blackbox

detection = load_blackbox("detection")
elevation = load_blackbox("detection.elevation")

ASKS = [
    ("sudo rm -rf /var/log/x", "sudo"),
    ("FOO=1 sudo -n true", "sudo"),
    ("cd /tmp && sudo make install", "sudo"),
    ("echo hi | sudo tee /etc/hosts", "sudo"),
    ("/usr/bin/sudo -u root id", "sudo"),
    ("su - root -c id", "sudo"),
    ("doas pkg_add x", "sudo"),
    ("pkexec whoami", "sudo"),
    ("bash -c 'sudo id'", "sudo"),
    ("nohup sudo ./install.sh &", "sudo"),
    ("osascript -e 'do shell script \"id\" with administrator privileges'", "admin-prompt"),
    ("security authorizationdb write system.preferences allow", "admin-prompt"),
    ("echo 'me ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/me", "sudoers"),
    ("cp ./rules /private/etc/sudoers.d/agent", "sudoers"),
    ("dseditgroup -o edit -a agent -t user admin", "admin-group"),
    ("dscl . -append /Groups/admin GroupMembership agent", "admin-group"),
    ("usermod -aG sudo agent", "admin-group"),
    ("chmod u+s ./helper", "setuid"),
    ("chmod 4755 /usr/local/bin/helper", "setuid"),
    ("cp job.plist /Library/LaunchDaemons/job.plist", "system-service"),
    ("launchctl bootstrap system /tmp/job.plist", "system-service"),
]

DOES_NOT_ASK = [
    "echo sudo make me a sandwich",
    "grep -rn sudo docs/",
    "git commit -m 'explain why su is not needed'",
    "cat /etc/sudoers",
    "chmod 755 run.sh",
    "chmod +x run.sh",
    "ls /Library/LaunchDaemons/",
    "man sudo",
    "launchctl print gui/501",
]


@pytest.mark.parametrize("command,way", ASKS)
def test_a_command_that_asks_for_root_is_one_flag_only_finding(command, way):
    found = detection.detect_elevation("terminal", {"command": command})
    assert [f.identifier for f in found] == ["agent:elevation-request"]
    finding = found[0]
    assert finding.fields == {"way": way}
    assert finding.severity == "high"
    assert finding.kind == detection.KIND_FLAG_ONLY      # never a reason to refuse
    assert finding.source == "custom"                    # never shared with the community graph
    assert command not in finding.evidence               # the command text is not the evidence


@pytest.mark.parametrize("command", DOES_NOT_ASK)
def test_a_command_that_only_mentions_root_is_not_a_request(command):
    assert detection.detect_elevation("terminal", {"command": command}) == []


def test_a_file_tool_writing_the_sudoers_rules_asks_for_root():
    found = detection.detect_elevation("write_file", {"path": "/etc/sudoers.d/agent", "content": "x"})
    assert found and found[0].fields == {"way": "sudoers"}
    assert detection.detect_elevation("read_file", {"path": "/etc/sudoers"}) == []


def test_the_guard_flags_a_sudo_call_and_never_refuses_it_for_that(monkeypatch, tmp_path):
    """Block mode, lowest threshold: the request is in the findings, the call is allowed (D7)."""
    monkeypatch.setenv("BLACKBOX_MODE", "block")
    monkeypatch.setenv("BLACKBOX_BLOCK_SEVERITY", "low")
    guard = load_blackbox("guard")
    verdict = guard.tool_call_verdict(tool_name="terminal", args={"command": "sudo -n true"})
    identifiers = [finding.get("identifier") for finding in verdict.get("findings") or []]
    assert "agent:elevation-request" in identifiers
    assert "agent:elevation-request" not in (verdict.get("blocked") or [])
    assert verdict.get("decision") != "block"
