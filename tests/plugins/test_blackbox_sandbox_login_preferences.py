"""The login window's and login items' preferences, and what the agent sandbox can close of them.

Wave 9, item 4 (a VM probe is due on whether the sandbox closes a login-window or login-items
preference written through cfprefsd). Measured HERE with real Seatbelt (``sandbox-exec``) and a
THROWAWAY domain only - never the real login window - removed again after each test:

* a ``defaults write`` is made by cfprefsd, not by the sandboxed process: a ``file-write*`` deny of
  the domain's plist does NOT stop it, and ``(deny user-preference-write (preference-domain …))``
  is accepted but not enforced for a ``sandbox-exec`` process;
* denying BOTH cfprefsd lookups (``profile.cfprefsd_lines``) puts CFPreferences in direct mode: the
  process writes the plist itself, so the file deny then refuses the write, while every other
  domain is still written and read, and global preferences are still read.

So the rule (``profile.CLOSE_PREFERENCES_THROUGH_CFPREFSD``) is ON since fix wave 10: security
round 7's VM probe of the REAL login-window and login-items domains (lw7.sh, core 96b24d43b1) found
them written from inside the installed profile, and unchanged with the rule on, while ordinary work
(other domains, git, npm, brew) kept running. The hook refusal is there too
(``defaults write loginwindow …`` is a schedule, test_blackbox_persistence_scripts.py), and the
login window's plists are persistence places (``kernel.persistence_places.PERSISTENCE_GLOBS``):
a direct write of them (``cp x.plist ~/Library/Preferences/com.apple.loginwindow.plist``) is refused
by the sandbox's file deny and by the hook alike.
"""

from __future__ import annotations

import os
import pwd
import subprocess
import sys
import uuid

import pytest

from plugins.blackbox.detection import detect_persistence_write
from plugins.blackbox.kernel import persistence_places
from plugins.blackbox.shields.files.sandbox.platform.macos import profile as macos_profile

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos_profile.SANDBOX_EXEC, os.X_OK),
                          reason="real Seatbelt is macOS's")
BASE = "(version 1)\n(allow default)\n"


def _places(**more):
    from plugins.blackbox.shields.files.sandbox.places import Places
    return Places(denied_folders=(), denied_files=(), denied_globs=(), no_write=(), no_rename=(), canary="", **more)


@pytest.fixture
def domain():
    """A throwaway preference domain (cfprefsd keeps it in the real user's Preferences, whatever
    HOME says), deleted again afterwards."""
    name = f"ai.blackbox.test.w9-{uuid.uuid4().hex[:10]}"
    yield name
    preferences = os.path.join(pwd.getpwuid(os.getuid()).pw_dir, "Library", "Preferences")
    for each in (name, name + "-other"):
        _defaults("delete", each)
        try:   # ``defaults delete`` leaves an empty plist behind
            os.unlink(os.path.join(preferences, each + ".plist"))
        except FileNotFoundError:
            pass


def _defaults(*words: str, profile: str = "") -> subprocess.CompletedProcess:
    command = ["/usr/bin/defaults", *words]
    if profile:
        command = [macos_profile.SANDBOX_EXEC, "-p", profile, *command]
    return subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)


def _plist_deny(name: str) -> str:
    """The profile's own kind of file deny (``(deny file-write* (literal …))``) for *name*'s plist."""
    home = pwd.getpwuid(os.getuid()).pw_dir   # where cfprefsd keeps it: the user's real home
    return f'(deny file-write* (literal "{os.path.realpath(home)}/Library/Preferences/{name}.plist"))\n'


@REAL
def test_a_file_deny_alone_does_not_stop_a_write_made_through_cfprefsd(domain):
    """Why the rule exists: the profile's file denies do not hold for a ``defaults write``."""
    assert _defaults("write", domain, "probe", "-string", "inside", profile=BASE + _plist_deny(domain)).returncode == 0
    assert _defaults("read", domain, "probe").stdout.strip() == "inside"


@REAL
def test_user_preference_write_is_accepted_but_not_enforced(domain):
    """Why the rule is not Seatbelt's preference filter (the narrower one asked for first)."""
    rule = f'(deny user-preference-write (preference-domain "{domain}"))\n'
    assert _defaults("write", domain, "probe", "-string", "inside", profile=BASE + rule).returncode == 0
    assert _defaults("read", domain, "probe").stdout.strip() == "inside"


@REAL
def test_with_cfprefsd_closed_the_file_deny_holds_and_other_preferences_keep_working(domain):
    profile = BASE + "\n".join(macos_profile.cfprefsd_lines()) + "\n" + _plist_deny(domain)
    refused = _defaults("write", domain, "probe", "-string", "inside", profile=profile)
    assert refused.returncode != 0 and _defaults("read", domain, "probe").returncode != 0
    other = domain + "-other"
    assert _defaults("write", other, "k", "-string", "v", profile=profile).returncode == 0
    assert _defaults("read", other, "k", profile=profile).stdout.strip() == "v"
    assert _defaults("read", "-g", "AppleLocale", profile=profile).returncode in (0, 1)   # reads, found or not: no hang, no crash


def test_the_rule_is_on_and_rendered_in_the_never_list(tmp_path):
    """Security round 7's VM probe answered: the installed profile let login-domain writes through
    cfprefsd; the rule is on, after the never-list's mark where no permission lifts it."""
    assert macos_profile.CLOSE_PREFERENCES_THROUGH_CFPREFSD is True
    assert macos_profile.cfprefsd_lines() == ['(deny mach-lookup (global-name "com.apple.cfprefsd.agent") '
                                              '(global-name "com.apple.cfprefsd.daemon"))']
    text = macos_profile.render(_places())
    assert macos_profile.cfprefsd_lines()[0] in text.split(macos_profile.NEVER_MARK)[1]


@REAL
def test_the_rendered_profile_refuses_a_login_domain_write_and_keeps_others_working(domain, tmp_path):
    """The profile Blackbox renders, with a throwaway domain standing in for the login window (never
    the real one): its ``defaults write`` leaves it unchanged, another domain is written and read."""
    home = os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
    text = macos_profile.render(_places(startup_globs=(f"{home}/Library/Preferences/{domain}.p*",)))
    assert subprocess.run([macos_profile.SANDBOX_EXEC, "-p", text, "/usr/bin/true"], timeout=30, check=False).returncode == 0
    _defaults("write", domain, "LoginHook", "-string", "/tmp/x", profile=text)
    assert _defaults("read", domain, "LoginHook").returncode != 0   # read outside: never written
    other = domain + "-other"
    assert _defaults("write", other, "k", "-string", "v", profile=text).returncode == 0
    assert _defaults("read", other, "k", profile=text).stdout.strip() == "v"


def test_the_login_windows_preference_files_are_persistence_places(tmp_path):
    # macOS's list, whatever OS runs the test (Linux has no login window; its own list is checked
    # in test_blackbox_persistence_hooks.py)
    _folders, _files, globs = persistence_places.startup_places(str(tmp_path), system="darwin")
    assert f"{tmp_path}/Library/Preferences/com.apple.loginwindow*" in globs
    assert f"{tmp_path}/Library/Preferences/loginwindow*" in globs


@pytest.mark.parametrize("command", [
    "cp hook.plist ~/Library/Preferences/com.apple.loginwindow.plist",
    "plutil -insert LoginHook -string /tmp/x.sh ~/Library/Preferences/com.apple.loginwindow.plist",
    "echo x > ~/Library/Preferences/loginwindow.plist",
])
def test_a_direct_write_of_the_login_windows_preferences_is_refused_by_the_hook(command, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert detect_persistence_write("terminal", {"command": command}), command


def test_reading_the_login_windows_preferences_stays_allowed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert detect_persistence_write("terminal", {"command": "cat ~/Library/Preferences/com.apple.loginwindow.plist"}) == []
