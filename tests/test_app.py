"""
Automated Test Suite for SQL Injection Lab
==========================================
Tests:
1. Detection Engine heuristics (normal vs suspicious inputs).
2. Exploitation analysis simulation logic.
3. Secure parameterized query authentication.
4. Cryptographic password hashing and verification.
5. Flask API endpoints and response integrity.
"""

import os
import pytest
from werkzeug.security import check_password_hash

from app import app, detect_sqli, simulate_exploitation
from database import (
    init_db,
    get_db_connection,
    authenticate_secure,
    DUMMY_USERS,
)

# Use an isolated test database
TEST_DB_PATH = os.path.join(os.path.dirname(__file__), "test_lab.db")


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Initialize fresh test database before tests and clean up after."""
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    init_db(TEST_DB_PATH)
    yield
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except OSError:
            pass


@pytest.fixture
def client():
    """Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ============================================================================
# PHASE 1 TESTS: DETECTION ENGINE
# ============================================================================
class TestDetectionEngine:
    """Test suite for identifying normal vs suspicious inputs."""

    def test_normal_alphanumeric_inputs(self):
        """Normal alphanumeric usernames must be classified as SAFE."""
        normal_samples = ["alice", "bob_miller", "johnDoe2026", "analyst_01"]
        for sample in normal_samples:
            result = detect_sqli(sample)
            assert not result["is_suspicious"], f"Failed for normal input: {sample}"
            assert result["risk_level"] == "SAFE"
            assert result["risk_score"] < 30
            assert len(result["matched_rules"]) == 0

    def test_normal_email_input(self):
        """Standard email formatted input must not trigger false positive SQLi."""
        result = detect_sqli("alice.vance@company.org")
        assert result["risk_level"] == "SAFE"
        assert not result["is_suspicious"]

    def test_empty_and_whitespace_input(self):
        """Empty or whitespace input must handle gracefully without errors."""
        result = detect_sqli("")
        assert result["risk_score"] == 0
        assert not result["is_suspicious"]

    def test_detect_quote_delimiter(self):
        """Single quotes used to break SQL string boundaries must be flagged."""
        result = detect_sqli("admin'")
        assert result["is_suspicious"]
        rule_ids = [r["id"] for r in result["matched_rules"]]
        assert "RULE_QUOTE_DELIMITER" in rule_ids

    def test_detect_comment_truncation(self):
        """SQL comment indicators (--, /*, #) must be detected."""
        result = detect_sqli("admin'--")
        assert result["is_suspicious"]
        rule_ids = [r["id"] for r in result["matched_rules"]]
        assert "RULE_COMMENT_DELIMITER" in rule_ids
        assert result["risk_score"] >= 60

    def test_detect_boolean_tautology(self):
        """Boolean tautologies like ' OR '1'='1' must be flagged as CRITICAL / HIGH RISK."""
        tautologies = [
            "' OR '1'='1",
            "' or 1=1",
            "admin' OR 'a'='a",
            "' OR true--",
        ]
        for payload in tautologies:
            result = detect_sqli(payload)
            assert result["is_suspicious"], f"Failed to flag tautology: {payload}"
            assert result["risk_level"] in ("SUSPICIOUS", "HIGH RISK")
            rule_ids = [r["id"] for r in result["matched_rules"]]
            assert "RULE_BOOLEAN_TAUTOLOGY" in rule_ids or "RULE_QUOTE_DELIMITER" in rule_ids

    def test_detect_stacked_keywords(self):
        """SQL keywords like UNION SELECT or DROP TABLE must be flagged."""
        result = detect_sqli("' UNION SELECT username, password FROM users--")
        assert result["is_suspicious"]
        assert result["risk_level"] == "HIGH RISK"
        rule_ids = [r["id"] for r in result["matched_rules"]]
        assert "RULE_KEYWORD_STACKING" in rule_ids


# ============================================================================
# PHASE 2 TESTS: EXPLOITATION ANALYSIS (SAFE SIMULATOR)
# ============================================================================
class TestExploitationSimulator:
    """Test educational simulation of query syntax modification."""

    def test_simulation_normal_input(self):
        """Simulating normal input produces standard query outcome."""
        res = simulate_exploitation("alice", "AlicePassword123!")
        assert res["theoretical_outcome"] == "NORMAL_AUTHENTICATION"
        assert "Standard Query Execution" in res["simulated_status"]
        assert not res["syntax_breakdown"]["has_quote_breakout"]

    def test_simulation_tautology_breakout(self):
        """Simulating ' OR '1'='1 correctly models theoretical syntax breakout."""
        res = simulate_exploitation("' OR '1'='1", "arbitrary")
        assert res["theoretical_outcome"] == "THEORETICAL_BYPASS"
        assert res["syntax_breakdown"]["has_quote_breakout"]
        assert res["syntax_breakdown"]["has_boolean_tautology"]
        assert "WHERE username = '' OR '1'='1'" in res["simulated_raw_query"]
        assert "EDUCATIONAL SIMULATION ONLY" in res["safety_badge"]

    def test_simulation_unbalanced_quote(self):
        """Simulating single quote models syntax error / fingerprinting risk."""
        res = simulate_exploitation("admin'", "pass")
        assert res["theoretical_outcome"] == "SYNTAX_ERROR_RISK"
        assert res["syntax_breakdown"]["has_quote_breakout"]


# ============================================================================
# PHASE 3 TESTS: DATABASE, PASSWORD HASHING & MITIGATION
# ============================================================================
class TestDatabaseAndMitigation:
    """Test SQLite parameterized queries and cryptographic password hashing."""

    def test_database_initialization_and_seeding(self):
        """Ensure dummy accounts are seeded with secure hashes."""
        conn = get_db_connection(TEST_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT username, password_hash, role FROM users")
        rows = cursor.fetchall()
        conn.close()

        assert len(rows) == len(DUMMY_USERS)
        for row in rows:
            # Verify password hash format (PBKDF2)
            assert row["password_hash"].startswith("pbkdf2:sha256:")
            assert len(row["password_hash"]) > 40

    def test_legitimate_authentication_succeeds(self):
        """Valid dummy account credentials must authenticate successfully."""
        user = authenticate_secure("alice", "AlicePassword123!", db_path=TEST_DB_PATH)
        assert user is not None
        assert user["username"] == "alice"
        assert user["role"] == "Security Analyst"
        # Ensure password_hash is stripped from authenticated session payload
        assert "password_hash" not in user

    def test_invalid_password_fails(self):
        """Valid username with incorrect password must fail authentication."""
        user = authenticate_secure("alice", "WrongPassword999!", db_path=TEST_DB_PATH)
        assert user is None

    def test_sql_injection_attempt_fails_against_parameterized_query(self):
        """
        SQL injection input MUST fail authentication against parameterized query.
        SQLite must search literally for the string and return None.
        """
        injection_inputs = [
            "' OR '1'='1",
            "' or 1=1--",
            "admin_demo'--",
            "' UNION SELECT id, username, password_hash, full_name, role FROM users--",
            "admin' #",
        ]
        for inj in injection_inputs:
            user = authenticate_secure(inj, "random_password", db_path=TEST_DB_PATH)
            assert user is None, f"Security Failure: Injection payload '{inj}' bypassed parameterized query!"


# ============================================================================
# API ENDPOINT TESTS
# ============================================================================
class TestApiEndpoints:
    """Test Flask routes and HTTP responses."""

    def test_index_route(self, client):
        """Main page must render successfully with HTTP 200."""
        res = client.get("/")
        assert res.status_code == 200
        assert b"SQL-i CYBER LAB" in res.data
        assert b"Phase 1" in res.data
        assert b"Phase 2" in res.data
        assert b"Phase 3" in res.data

    def test_api_detect_endpoint(self, client):
        """POST /api/detect returns valid JSON response."""
        res = client.post("/api/detect", json={"input_text": "' OR '1'='1"})
        assert res.status_code == 200
        data = res.get_json()
        assert data["is_suspicious"] is True
        assert data["risk_score"] > 50

    def test_api_simulate_exploit_endpoint(self, client):
        """POST /api/simulate-exploit returns syntax analysis without live bypass."""
        res = client.post(
            "/api/simulate-exploit",
            json={"username": "admin'--", "password": ""},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert "SELECT * FROM users" in data["simulated_raw_query"]
        assert "EDUCATIONAL SIMULATION" in data["safety_badge"]

    def test_api_secure_login_success(self, client):
        """POST /api/secure-login with valid credentials returns 200."""
        res = client.post(
            "/api/secure-login",
            json={"username": "bob", "password": "BobPassword456!"},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["user"]["username"] == "bob"

    def test_api_secure_login_injection_neutralized(self, client):
        """POST /api/secure-login with injection payload returns 401 safely."""
        res = client.post(
            "/api/secure-login",
            json={"username": "' OR '1'='1", "password": "arbitrary_password"},
        )
        assert res.status_code == 401
        data = res.get_json()
        assert data["success"] is False
        assert "neutralized" in data["security_details"]["neutralization_note"].lower()
