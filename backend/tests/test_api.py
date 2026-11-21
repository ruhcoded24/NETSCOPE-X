import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["service"] == "netscope-x"


def test_interfaces(client):
    response = client.get("/api/interfaces")
    assert response.status_code == 200
    data = response.json()
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)
    assert len(data["interfaces"]) > 0


def test_capture_status(client):
    response = client.get("/api/capture/status")
    assert response.status_code == 200
    data = response.json()
    assert "capturing" in data
    assert "activeInterface" in data


def test_settings_get_and_put(client):
    response = client.get("/api/settings")
    assert response.status_code == 200
    data = response.json()
    assert "defaultInterface" in data
    assert "thresholds" in data

    put_res = client.put("/api/settings", json={"reducedMotion": True})
    assert put_res.status_code == 200
    assert put_res.json()["reducedMotion"] is True


def test_stats(client):
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "totalPackets" in data
    assert "protocolDistribution" in data


def test_topology(client):
    response = client.get("/api/topology")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert isinstance(data["nodes"], list)
    assert isinstance(data["edges"], list)


def test_alerts(client):
    response = client.get("/api/alerts")
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    assert isinstance(data["alerts"], list)


