"""Network Shield's system watch endpoints — exposure, startup items, tampering and the posture
check — merged into the shield's API by :mod:`.api`. Paths: ``/api/shields/network-shield/api/<name>``.

Reads (``GET``):
  ``system-plan``   the root helper's small plan: watch (shield on), the posture fixes asked for,
                    the tamper guard, the posture refresh counter (all off while the shield is off)
  ``exposure``      listeners the network can reach + startup items, each judged, and tampering
                    (DNS / proxy / VPN / firewall / Blackbox's helper) — 409 while off
  ``posture``       the posture checks, score, the fixes asked for and applied — 409 while off

Writes (``POST``):
  ``system-report`` the helper's report (validated strictly, :mod:`.monitor.system_report`)
  ``posture-fix``   ``{"fix": id, "apply": bool}`` — asked for in the app first; ``apply: false`` is Undo
  ``posture-refresh`` ask the helper for a fresh posture look now
  ``tamper-guard``  ``{"on": bool}`` — the opt-in DNS tamper guard
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from ...shields.network import mode as mode_module
from ...shields.shield_api import ShieldApiError, ShieldContext
from .monitor import exposure, posture, system_report
from .protect import enforcement, posture_fix, tamper_guard

OFF = "Switch Network Shield on to see this machine's network."
RESOLVER = "127.0.0.1"


def _shield_on() -> bool:
    return bool(mode_module.current().enabled)


def _require_on() -> None:
    if not _shield_on():
        raise ShieldApiError(409, OFF)


def system_plan(_context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    on = _shield_on()
    return {"watch": on, **posture_fix.plan_part(on), **tamper_guard.plan_part(on)}


def system_report_write(_context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    return system_report.record(system_report.validate(body, time.time()))


def _tamper_status(raw: Any, summary: Mapping[str, Any]) -> dict[str, Any]:
    """The tamper look for a person: what is fine and what is not, with DNS Shield taken into account."""
    if not raw:
        return {"checked": False}
    dns_shield = bool(summary.get("dns_active"))
    servers = list(raw.get("dns_servers") or [])
    return {"checked": True, "dns_shield": dns_shield, "dns_servers": servers,
            "dns_ok": (not dns_shield) or (bool(servers) and servers[0] == RESOLVER),
            "proxy": list(raw.get("proxy") or []), "vpn_count": int(raw.get("vpn_count") or 0),
            "firewall": raw.get("firewall", "unknown"), "guard": tamper_guard.is_on()}


def exposure_read(_context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    _require_on()
    view = exposure.view()
    view["tamper"] = _tamper_status(view.get("tamper"), enforcement.summary())
    return view


def posture_read(_context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    _require_on()
    snap = system_report.snapshot()
    facts = (snap or {}).get("posture")
    summary = enforcement.summary()
    blackbox = {"running": summary.get("running"), "dns_active": summary.get("dns_active"), "firewall_active": summary.get("firewall_active"),
                "remote_locked": bool(summary.get("ssh_lockdown_active") or summary.get("remote_lock_active"))}
    checks = posture.checks(facts, blackbox) if facts else []
    return {"watching": snap is not None, "checked": bool(facts), "updated_at": (snap or {}).get("at"),
            "score": posture.score(checks) if checks else None, "checks": checks,
            "wanted": posture_fix.wanted(), "applied": list((snap or {}).get("fixes") or [])}


def posture_fix_write(_context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    _require_on()
    return {"wanted": posture_fix.set_fix(body.get("fix"), body.get("apply"))}


def posture_refresh_write(_context: ShieldContext, _body: Mapping[str, Any]) -> dict[str, Any]:
    _require_on()
    return {"refresh": posture_fix.request_refresh()}


def tamper_guard_write(_context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    _require_on()
    return {"on": tamper_guard.set_on(body.get("on"))}


READS = {"system-plan": system_plan, "exposure": exposure_read, "posture": posture_read}
WRITES = {"system-report": system_report_write, "posture-fix": posture_fix_write, "posture-refresh": posture_refresh_write,
          "tamper-guard": tamper_guard_write}
