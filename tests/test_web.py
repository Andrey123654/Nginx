import io
import json

from fastapi.testclient import TestClient

from web.app import app


client = TestClient(app)


def test_healthcheck():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["version"] == "1.2.0"
    assert response.headers["x-nginx-scope-version"] == "1.2.0"
    assert response.headers["x-frame-options"] == "DENY"


def test_analyze_returns_findings_without_echoing_config():
    config = b"events {} http { server { listen 443 ssl; ssl_protocols TLSv1 TLSv1.2; autoindex on; } }"
    response = client.post("/api/analyze", files={"nginx_config": ("nginx.conf", io.BytesIO(config), "text/plain")})
    assert response.status_code == 200
    payload = response.json()
    rules = {item["rule"] for item in payload["findings"]}
    assert "nginx-old-tls" in rules
    assert "nginx-autoindex" in rules
    assert payload["corrected_config"] != config.decode()
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in payload["corrected_config"]
    assert "autoindex off;" in payload["corrected_config"]
    assert all(item.get("recommendation") for item in payload["findings"] if item["rule"].startswith("nginx-"))
    assert len(payload["publications"]) == 1
    assert payload["publications"][0]["server_names"] == ["(не задан)"]
    assert payload["baseline"]["kind"] == "nginx-publication-baseline"


def test_baseline_comparison_detects_publication_change():
    first = b"events {} http { server { listen 443 ssl; server_name app.example; } }"
    initial = client.post("/api/analyze", files={"nginx_config": ("nginx.conf", first, "text/plain")}).json()
    changed = b"events {} http { server { listen 8443 ssl; server_name app.example; } }"
    response = client.post("/api/analyze", files={
        "nginx_config": ("nginx.conf", changed, "text/plain"),
        "baseline": ("nginx-baseline.json", json.dumps(initial["baseline"]).encode(), "application/json"),
    })
    assert response.status_code == 200
    comparison = response.json()["comparison"]
    assert comparison["status"] == "changed"
    assert comparison["modified"][0]["changes"][0]["field"] == "listen"


def test_binary_file_is_rejected():
    response = client.post("/api/analyze", files={"nginx_config": ("nginx.conf", b"abc\x00def", "text/plain")})
    assert response.status_code == 415
    detail = response.json()["detail"]
    assert detail["code"] == "binary_file"
    assert detail["filename"] == "nginx.conf"
    assert detail["hint"]


def test_extensionless_nginx_output_is_accepted():
    response = client.post("/api/analyze", files={
        "nginx_config": ("nginx-T", b"events {} http { server_tokens off; }", "text/plain")
    })
    assert response.status_code == 200


def test_arbitrary_extension_is_accepted_for_text_config():
    response = client.post("/api/analyze", files={
        "nginx_config": ("nginx.yaml", b"events {}", "text/plain")
    })
    assert response.status_code == 200


def test_config_only_with_empty_optional_uploads_is_accepted():
    response = client.post("/api/analyze", files={
        "nginx_config": ("nginx.conf", b"events {} http { server_tokens off; }", "text/plain"),
        "inventory": ("", b"", "application/octet-stream"),
        "external_sensor": ("", b"", "application/octet-stream"),
        "internal_sensor": ("", b"", "application/octet-stream"),
    })
    assert response.status_code == 200
    assert response.json()["resources"] == []


def test_sensor_requires_inventory():
    response = client.post("/api/analyze", files={
        "nginx_config": ("nginx.conf", b"events {}", "text/plain"),
        "external_sensor": ("sensor.json", b'{"kind":"sensor","zone":"external"}', "application/json"),
    })
    assert response.status_code == 422
