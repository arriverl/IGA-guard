"""Proxy forwarder smoke tests."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from iga_guard.pipeline import IgaGuardEngine, load_config
from iga_guard.proxy.forwarder import ProxyConfig, TrafficForwarder, from_flask_request


@pytest.fixture(scope="module")
def engine():
    cfg = load_config("configs/default.yaml")
    cfg.setdefault("detector", {})["warmup_on_init"] = False
    cfg.setdefault("continual_cache", {})["enabled"] = False
    return IgaGuardEngine(cfg)


@pytest.fixture
def forwarder(engine):
    cfg = ProxyConfig(
        mode="inline",
        upstream_url="http://127.0.0.1:9999",
        block_on_malicious=True,
    )
    return TrafficForwarder(engine, cfg)


def test_from_flask_request_builds_url():
    req = MagicMock()
    req.method = "GET"
    req.scheme = "http"
    req.host = "example.com"
    req.path = "/search"
    req.query_string = b"q=test"
    req.headers = {"User-Agent": "test"}
    req.get_data = MagicMock(return_value=b"")
    http = from_flask_request(req)
    assert http.method == "GET"
    assert "example.com/search?q=test" in http.url
    assert http.source == "proxy"


def test_blocks_sqli(forwarder):
    req = MagicMock()
    req.method = "GET"
    req.scheme = "http"
    req.host = "victim.local"
    req.path = "/"
    req.query_string = b"p=1%20union%20select%201--"
    req.headers = {}
    req.remote_addr = "10.0.0.1"
    req.get_data = MagicMock(return_value=b"")

    resp = forwarder.handle(req)
    assert resp.status_code == 403
    body = json.loads(resp.get_data(as_text=True))
    assert body["blocked"] is True


@patch("iga_guard.proxy.forwarder.requests.request")
def test_forwards_benign(mock_req, forwarder):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"ok"
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_req.return_value = mock_resp

    req = MagicMock()
    req.method = "GET"
    req.scheme = "http"
    req.host = "victim.local"
    req.path = "/home"
    req.query_string = b""
    req.headers = {}
    req.remote_addr = "10.0.0.2"
    req.get_data = MagicMock(return_value=b"")

    resp = forwarder.handle(req)
    assert resp.status_code == 200
    assert resp.get_data() == b"ok"
    mock_req.assert_called_once()
