"""Explicit local index maintenance; never a network sync or rules export."""
import json

from ..kernel.config import load_blackbox_config
from ..kernel.dkg_client import DkgClient
from ..ruleset import local_graph_url, semantic_index_spec, validate_config


def add_semantic_parser(sub):
    group = sub.add_parser("semantic", help="Configure local graph entity discovery")
    actions = group.add_subparsers(dest="semantic_command", required=True)
    index = actions.add_parser("index", help="Build or resume the local behavioral entity index")
    index.add_argument("--restart", action="store_true", help="Rescan current local graph data")
    index.set_defaults(func=cmd_index)


def cmd_index(args):
    cfg = load_blackbox_config()
    try:
        validate_config(cfg)
        client = DkgClient(url=local_graph_url(cfg.dkg_url), dkg_home=cfg.dkg_home)
        for page in range(12_501):
            state = client.request("POST", "/api/entities/index", {**semantic_index_spec,
                "contextGraphId": cfg.context_graph_id, "restart": page == 0 and args.restart}, timeout=35)
            if not isinstance(state, dict) or state.get("version") != 1 or type(state.get("scanComplete")) is not bool:
                raise ValueError("invalid index response")
            print(json.dumps(state))
            if state["scanComplete"]:
                print("Set semantic.index_id to the indexId above; enable semantic review with a local model.")
                return 0
        raise ValueError("index page limit reached")
    except Exception:
        print("Semantic index unavailable. Check the local node's embedding configuration and operator permission.")
        return 2
