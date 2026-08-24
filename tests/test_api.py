from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

def test_safe_read():
    r = client.post("/api/analyze", json={
        "intent": "I want to view files in ~/Downloads",
        "command": "ls -la ~/Downloads"
    })
    assert r.status_code == 200
    d = r.json()
    assert d["risk"]["level"] in {"LOW", "MEDIUM"}
    assert d["alignment"]["status"] == "MATCH"

def test_delete_is_not_low():
    r = client.post("/api/analyze", json={
        "intent": "I want to delete old files in ~/Downloads",
        "command": "rm ~/Downloads/old.txt"
    })
    d = r.json()
    assert d["risk"]["level"] in {"MEDIUM", "HIGH", "CRITICAL"}

def test_privilege_review():
    r = client.post("/api/analyze", json={
        "intent": "I want to view system information",
        "command": "sudo cat /etc/passwd"
    })
    d = r.json()
    assert d["decision"] in {"REVIEW", "BLOCK"}
