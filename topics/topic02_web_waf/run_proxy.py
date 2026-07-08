#!/usr/bin/env python3
"""Start IGA-Guard inline proxy (VPS plug-and-play traffic forwarding)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from backend.proxy_app import app, create_proxy_app, proxy_cfg  # noqa: E402
from iga_guard.pipeline import load_config  # noqa: E402

if __name__ == "__main__":
    cfg_path = Path(os.environ.get("IGA_CONFIG", str(ROOT / "configs" / "proxy.yaml")))
    cfg = load_config(cfg_path)
    host = cfg.get("server", {}).get("host", "0.0.0.0")
    port = int(cfg.get("server", {}).get("port", 8080))
    print(f"IGA-Guard Proxy listening on {host}:{port}", flush=True)
    print(f"  upstream: {proxy_cfg.upstream_url}", flush=True)
    print(f"  mode: {proxy_cfg.mode}", flush=True)
    print(f"  health: http://{host}:{port}/_iga/health", flush=True)
    create_proxy_app().run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
