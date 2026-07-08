"""IGA-Guard VPS inline proxy — 即插即用流量转发入口。"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard import __version__  # noqa: E402
from iga_guard.pipeline import IgaGuardEngine, load_config  # noqa: E402
from iga_guard.proxy.forwarder import ProxyConfig, TrafficForwarder  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

CONFIG_PATH = Path(os.environ.get("IGA_CONFIG", str(ROOT / "configs" / "proxy.yaml")))
cfg = load_config(CONFIG_PATH)
proxy_raw = cfg.get("proxy", {})
if os.environ.get("IGA_UPSTREAM_URL"):
    proxy_raw = {**proxy_raw, "upstream_url": os.environ["IGA_UPSTREAM_URL"]}
if os.environ.get("IGA_PROXY_MODE"):
    proxy_raw = {**proxy_raw, "mode": os.environ["IGA_PROXY_MODE"]}

proxy_cfg = ProxyConfig.from_dict(proxy_raw)
engine = IgaGuardEngine(cfg)
forwarder = TrafficForwarder(engine, proxy_cfg)

app = Flask(__name__)
CORS(app)


@app.get("/_iga/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "IGA-Guard-Proxy",
        "version": __version__,
        "upstream": proxy_cfg.upstream_url,
        "mode": proxy_cfg.mode,
        **forwarder.stats(),
    })


@app.get("/_iga/stats")
def stats():
    return jsonify(forwarder.stats())


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def proxy_all(path: str):
    if request.path.startswith("/_iga/"):
        return jsonify({"error": "not found"}), 404
    return forwarder.handle(request)


def create_proxy_app() -> Flask:
    return app
