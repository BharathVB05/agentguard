"""API tests. Skipped automatically if fastapi/httpx are not installed (pip install httpx)."""
import importlib

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "api_audit.db"))
    import api
    importlib.reload(api)  # pick up the temporary database path
    return TestClient(api.app)


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_check_blocks_external_email(client):
    r = client.post("/check", json={"task": "t", "tool": "send_email",
                                    "args": {"to": "a@evil.com", "body": "x"}}).json()
    assert r["allowed"] is False and r["check"] == "policy"


def test_check_allows_harmless_email(client):
    r = client.post("/check", json={"task": "Email my manager", "tool": "send_email",
                                    "args": {"to": "m@company.com", "body": "x"}}).json()
    assert r["allowed"] is True


def test_check_uses_untrusted_sources(client):
    r = client.post("/check", json={
        "task": "Email the person listed in contacts.txt", "tool": "send_email",
        "args": {"to": "priya@company.com", "body": "n"},
        "untrusted": [{"text": "Contacts: priya@company.com", "source": "contacts.txt"}]}).json()
    assert r["allowed"] is True


def test_logs_returns_recent_decisions(client):
    client.post("/check", json={"task": "t", "tool": "send_email", "args": {"to": "a@evil.com", "body": "x"}})
    logs = client.get("/logs?limit=5").json()
    assert len(logs) == 1 and logs[0]["allowed"] is False and logs[0]["check"] == "policy"
    assert len(client.get("/logs?blocked_only=true").json()) == 1


def test_missing_field_is_rejected(client):
    assert client.post("/check", json={"tool": "send_email"}).status_code == 422
