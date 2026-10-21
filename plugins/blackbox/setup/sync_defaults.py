"""Load the installed plugin's default gate from either installer layout."""
import importlib
import importlib.util
import sys
from pathlib import Path


def defaults(entry, network):
    plugin = Path(__file__).resolve().parents[1]
    name = "_blackbox_installer_sync"
    spec = importlib.util.spec_from_file_location(name, plugin / "__init__.py", submodule_search_locations=[str(plugin)])
    package = importlib.util.module_from_spec(spec)
    sys.modules[name] = package
    spec.loader.exec_module(package)
    return importlib.import_module(name + ".sync").snapshot_defaults(entry, network)
