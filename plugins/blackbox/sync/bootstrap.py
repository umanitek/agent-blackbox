"""Observe the same daemon-owned native bootstrap on installer and managed restarts."""
import importlib.util
from pathlib import Path


def wait_for_native_bootstrap(cfg):
    path = Path(__file__).resolve().parents[1] / "setup" / "blackbox-native-bootstrap.py"
    spec = importlib.util.spec_from_file_location("blackbox_native_bootstrap", path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    try:
        helper.wait_for_bootstrap(cfg.dkg_home, cfg.dkg_url)
    except (ValueError, OSError) as exc:
        raise RuntimeError(str(exc)) from exc
