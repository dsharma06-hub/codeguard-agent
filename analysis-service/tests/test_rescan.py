"""Tests for rescan API endpoint."""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_rescan_endpoint_vulnerable_code():
    """Rescanning vulnerable code should return findings."""
    vulnerable_sql_code = """
    function getUser(userId: string) {
        const query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return db.query(query);
    }
    """
    response = client.post("/rescan", json={"filename": "user.ts", "content": vulnerable_sql_code})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["findings_count"] >= 1
    assert any(f["rule_id"] == "SQL_INJECTION" for f in data["findings"])


def test_rescan_endpoint_clean_code():
    """Rescanning clean code should return 0 findings."""
    clean_sql_code = """
    function getUser(userId: string) {
        const query = "SELECT * FROM users WHERE id = ?";
        return db.query(query, [userId]);
    }
    """
    response = client.post("/rescan", json={"filename": "user.ts", "content": clean_sql_code})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["findings_count"] == 0
    assert len(data["findings"]) == 0


def test_analyze_rescan_prefixed_endpoint():
    """Ensure /analyze/rescan endpoint also works identically."""
    clean_code = "const x = 10;\nconsole.log(x);"
    response = client.post("/analyze/rescan", json={"filename": "app.js", "content": clean_code})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["findings_count"] == 0
