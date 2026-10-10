"""Response shaping for the direct graph backend."""
from fastapi.responses import JSONResponse
from .. import ruleset
from ..kernel.dkg_client import DkgError


def unavailable(exc):
    return JSONResponse(status_code=503, content={"state": "unavailable", "code": getattr(exc, "code", "QUERY_UNAVAILABLE")})


def status(cfg):
    try:
        rs = ruleset.peek(cfg)
        return rs, rs.counts()
    except DkgError as exc:
        return unavailable(exc)


def metadata(cfg, rs):
    direct = getattr(cfg, "detection_backend", "legacy-cache") == "dkg"
    return {"last_sync": None if direct else rs.synced_at or None,
            "detection_backend": getattr(cfg, "detection_backend", "legacy-cache"),
            "count_kind": "confirmed-entities" if direct else "compiled-rules"}


def page(cfg, **kwargs):
    try:
        return ruleset.graph_page(cfg, **kwargs)
    except DkgError as exc:
        return unavailable(exc)


def lookup(cfg, identifier, tier):
    try:
        rule = ruleset.graph_lookup(cfg, identifier)
        return {"identifier": identifier, "tier": tier, "found": rule is not None,
                "coverage": "local-confirmed-subset",
                **{k: v for k, v in (rule or {}).items() if k != "pattern"}}
    except DkgError as exc:
        return unavailable(exc)
