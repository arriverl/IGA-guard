#!/usr/bin/env python3
"""Start IGA-Guard API server."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from backend.app import app, create_app  # noqa: E402
from iga_guard.pipeline import load_config  # noqa: E402

if __name__ == "__main__":
    cfg = load_config(ROOT / "configs" / "default.yaml")
    host = cfg.get("server", {}).get("host", "127.0.0.1")
    port = cfg.get("server", {}).get("port", 5000)
    create_app().run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
