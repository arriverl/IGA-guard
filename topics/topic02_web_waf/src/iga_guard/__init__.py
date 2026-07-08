"""IGA-Guard 2.0"""

from iga_guard.runtime_env import configure_runtime_warnings

configure_runtime_warnings()

from iga_guard.pipeline import IgaGuardEngine, load_config

__version__ = "2.0.0"
__all__ = ["IgaGuardEngine", "load_config", "__version__"]
