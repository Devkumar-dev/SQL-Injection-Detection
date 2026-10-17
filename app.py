"""
SQL Injection Detection, Exploitation Analysis, and Mitigation Lab
===================================================================
A College Minor Project demonstrating:
1. Detection: Heuristic and pattern-based analysis of suspicious SQL inputs.
2. Exploitation Analysis: Safe, self-contained educational simulation of SQL injection syntax manipulation.
3. Mitigation: SQLite parameterized queries with salted cryptographic password hashing.

Safety & Educational Disclaimer:
- Strictly confined to localhost on an isolated SQLite database.
- Uses only fictional dummy test accounts.
- Exploitation phase is a safe query grammar simulation (no functional bypass executed).
"""

import os
import re
from typing import Dict, Any, List
from flask import Flask, render_template, request, jsonify
from database import (
    init_db,
    authenticate_secure,
    get_public_dummy_accounts,
    DEFAULT_DB_PATH,
)

app = Flask(__name__)

# Ensure database is initialized on startup
init_db()


# ============================================================================
# PHASE 1 — DETECTION ENGINE
# ============================================================================
DETECTION_RULES = [
    {
        "id": "RULE_QUOTE_DELIMITER",
        "name": "SQL String Delimiter Injection",
        "pattern": r"['\"\\]",
        "severity": "HIGH",
        "weight": 35,
        "category": "Syntax Breakout",
        "description": (
            "Detected unescaped quotation marks or escape slashes (' or \" or \\) "
            "often used to terminate string literals prematurely in dynamic SQL."
        ),
    },
    {
        "id": "RULE_COMMENT_DELIMITER",
        "name": "SQL Comment Delimiter",
        "pattern": r"(--|/\*|\*/|#)",
        "severity": "HIGH",
        "weight": 35,
        "category": "Syntax Truncation",
        "description": (
            "Detected SQL comment sequence (--, /* */, or #) used to truncate "
            "the remainder of a query, neutralizing subsequent clauses like password checks."
        ),
    },
    {
        "id": "RULE_BOOLEAN_TAUTOLOGY",
        "name": "Boolean Tautology / Predicate Manipulation",
        "pattern": r"\b(or|and)\b\s+(['\"]?[\w]+['\"]?)\s*=\s*\2|\bor\s+true\b|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?",
        "severity": "CRITICAL",
        "weight": 45,
        "category": "Logic Bypass",
        "description": (
            "Detected boolean tautology pattern (e.g., OR 1=1, OR 'a'='a', OR TRUE) "
            "designed to force WHERE clauses to evaluate unconditionally to TRUE."
        ),
    },
    {
        "id": "RULE_KEYWORD_STACKING",
        "name": "SQL Control Keywords in Input",
        "pattern": r"\b(union\s+select|select\b.*\bfrom|drop\s+table|insert\s+into|update\s+\w+\s+set|delete\s+from|exec\s*\(|execute\s*\()",
        "severity": "CRITICAL",
        "weight": 50,
        "category": "Query Stacking / Exfiltration",
        "description": (
            "Detected SQL DDL/DML keywords (UNION, SELECT, DROP, UPDATE, EXEC) "
            "indicating an attempt to execute stacked queries or exfiltrate additional data."
        ),
    },
    {
        "id": "RULE_MULTIPLE_STATEMENTS",
        "name": "Multiple Statement Semicolon Terminator",
        "pattern": r";\s*(select|insert|update|delete|drop|alter|create|exec)",
        "severity": "CRITICAL",
        "weight": 40,
        "category": "Statement Stacking",
        "description": (
            "Detected semicolon followed by SQL command keywords, attempting to chain "
            "multiple distinct SQL statements within a single execution."
        ),
    },
    {
        "id": "RULE_DATABASE_FINGERPRINT",
        "name": "Database Probing / Time-Delay Functions",
        "pattern": r"\b(sleep\s*\(|benchmark\s*\(|sqlite_version\s*\(|schema_version\b|load_extension\b)",
        "severity": "HIGH",
        "weight": 40,
        "category": "Reconnaissance / Blind SQLi",
        "description": (
            "Detected database function calls (e.g., sqlite_version(), sleep()) "
            "commonly used in blind SQL injection or system fingerprinting."
        ),
    },
]


def detect_sqli(input_text: str) -> Dict[str, Any]:
    """
    Analyze input text for SQL injection patterns and generate risk scoring.
    """
    if not input_text or not isinstance(input_text, str):
        return {
            "input_text": "",
            "is_suspicious": False,
            "risk_score": 0,
            "risk_level": "SAFE",
            "matched_rules": [],
            "character_count": 0,
            "analysis_summary": "Input is empty; no SQL injection indicators detected.",
        }

    matched_rules = []
    total_score = 0

    for rule in DETECTION_RULES:
        matches = list(re.finditer(rule["pattern"], input_text, flags=re.IGNORECASE))
        if matches:
            matched_fragments = [m.group(0) for m in matches]
            matched_rules.append(
                {
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "description": rule["description"],
                    "matches_found": matched_fragments,
                    "count": len(matches),
                }
            )
            total_score += rule["weight"]

    # Normalize risk score to 0 - 100 range
    risk_score = min(total_score, 100)

    if risk_score >= 60:
        risk_level = "HIGH RISK"
        is_suspicious = True
        summary = (
            "High confidence SQL injection pattern detected. The input contains syntax "
            "alteration tokens (quotes, tautologies, or SQL keywords) that would alter unparameterized queries."
        )
    elif risk_score >= 30:
        risk_level = "SUSPICIOUS"
        is_suspicious = True
        summary = (
            "Suspicious input detected. Input contains characters often associated with SQL syntax "
            "manipulation (such as quote delimiters or comments)."
        )
    else:
        risk_level = "SAFE"
        is_suspicious = False
        summary = (
            "Normal input detected. Input consists of expected alphanumeric characters, "
            "standard symbols, or clean identifiers without SQL injection tokens."
        )

    return {
        "input_text": input_text,
        "is_suspicious": is_suspicious,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "matched_rules": matched_rules,
        "character_count": len(input_text),
        "analysis_summary": summary,
    }


# ============================================================================
# PHASE 2 — EXPLOITATION ANALYSIS (SAFE EDUCATIONAL SIMULATOR)
# ============================================================================
def simulate_exploitation(username_input: str, password_input: str = "") -> Dict[str, Any]:
    """
    Educational query syntax analysis simulator.
    Demonstrates how unsafe dynamic SQL construction modifies the query grammar
    without performing an actual authentication bypass.
    """
    # 1. Fictional vulnerable pattern template
    vulnerable_template = (
        "SELECT * FROM users WHERE username = '{username}' AND password = '{password}';"
    )

    # 2. Reconstructed raw query (Educational representation of string concatenation)
    simulated_raw_query = vulnerable_template.format(
        username=username_input,
        password=password_input or "user_provided_secret",
    )

    # 3. Syntax breakdown analysis
    has_quote = "'" in username_input or '"' in username_input
    has_tautology = bool(
        re.search(r"\b(or|and)\b\s+(['\"]?[\w]+['\"]?)\s*=\s*\2", username_input, re.IGNORECASE)
        or re.search(r"\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?", username_input, re.IGNORECASE)
        or re.search(r"\bor\s+true\b", username_input, re.IGNORECASE)
    )
    has_comment = bool(re.search(r"(--|/\*|#)", username_input))

    # 4. Determine theoretical impact
    if has_quote and (has_tautology or has_comment):
        theoretical_outcome = "THEORETICAL_BYPASS"
        explanation = (
            "The single-quote prematurely terminates the string literal. "
            "The injected 'OR' operator introduces a tautology (e.g., 1=1) or the comment (--) "
            "discards the password verification clause. In an unsafe system using dynamic string concatenation, "
            "the WHERE condition evaluates to TRUE for all rows, returning the first account in the database."
        )
        simulated_status = "Simulated Authentication Bypass Condition"
        query_behavior = "Query logic was modified from 'username AND password check' to 'always TRUE'."
    elif has_quote:
        theoretical_outcome = "SYNTAX_ERROR_RISK"
        explanation = (
            "An unclosed single-quote alters SQL grammar without forming valid logic. "
            "In an unparameterized database query, this would trigger an unhandled SQLite OperationalError "
            "(syntax error), which attackers use for error-based database fingerprinting."
        )
        simulated_status = "Simulated Syntax Error / Error-based Leak"
        query_behavior = "Unbalanced quotes break query syntax."
    else:
        theoretical_outcome = "NORMAL_AUTHENTICATION"
        explanation = (
            "Input contains no syntax breaking characters. The query checks for an exact match "
            "of both username and password literals as intended by the developer."
        )
        simulated_status = "Standard Query Execution"
        query_behavior = "Query executes strictly within the intended developer parameters."

    return {
        "vulnerable_template": "SELECT * FROM users WHERE username = '$user' AND password = '$pass';",
        "simulated_raw_query": simulated_raw_query,
        "theoretical_outcome": theoretical_outcome,
        "simulated_status": simulated_status,
        "query_behavior": query_behavior,
        "explanation": explanation,
        "syntax_breakdown": {
            "has_quote_breakout": has_quote,
            "has_boolean_tautology": has_tautology,
            "has_comment_truncation": has_comment,
        },
        "safety_badge": "EDUCATIONAL SIMULATION ONLY — NO LIVE DATABASE EXPLOIT EXECUTED",
    }


# ============================================================================
# API ROUTES
# ============================================================================
@app.route("/")
def index():
    """Render the main Cybersecurity Dashboard."""
    dummy_accounts = get_public_dummy_accounts()
    return render_template("index.html", dummy_accounts=dummy_accounts)


@app.route("/api/detect", methods=["POST"])
def api_detect():
    """Endpoint for detecting SQL injection patterns in an input string."""
    data = request.get_json(silent=True) or {}
    input_text = data.get("input_text", "")
    result = detect_sqli(input_text)
    return jsonify(result)


@app.route("/api/simulate-exploit", methods=["POST"])
def api_simulate_exploit():
    """Endpoint for safe educational simulation of query syntax manipulation."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    result = simulate_exploitation(username, password)
    return jsonify(result)


@app.route("/api/secure-login", methods=["POST"])
def api_secure_login():
    """
    Live secure authentication endpoint using SQLite parameterized queries.
    Demonstrates that SQL injection attempts are treated strictly as string literals.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    # Execute secure parameterized query
    user = authenticate_secure(username, password)

    # Diagnostic response for educational analysis
    if user:
        return jsonify(
            {
                "success": True,
                "message": f"Successfully authenticated as {user['full_name']}!",
                "user": {
                    "username": user["username"],
                    "full_name": user["full_name"],
                    "role": user["role"],
                },
                "security_details": {
                    "query_used": "SELECT id, username, password_hash, full_name, role FROM users WHERE username = ?",
                    "parameters_bound": [username],
                    "mechanism": "Parameterized Prepared Query + Salted Hash Verification (PBKDF2)",
                    "result": "MATCH_FOUND",
                },
            }
        )
    else:
        # Determine why authentication failed for clear educational insight
        # If user input looks like an injection, explain how parameterization neutralized it
        detection = detect_sqli(username)
        if detection["is_suspicious"]:
            neutralization_note = (
                f"SQL injection attempt neutralized! SQLite bound '{username}' as a literal string value. "
                "The database searched literally for a username matching the entire injection string, "
                "resulting in 0 matching records. No syntax manipulation occurred."
            )
        else:
            neutralization_note = "Invalid username or password credentials."

        return (
            jsonify(
                {
                    "success": False,
                    "message": "Authentication failed.",
                    "security_details": {
                        "query_used": "SELECT id, username, password_hash, full_name, role FROM users WHERE username = ?",
                        "parameters_bound": [username],
                        "mechanism": "Parameterized Prepared Query + Salted Hash Verification",
                        "neutralization_note": neutralization_note,
                        "result": "NO_MATCH_OR_INVALID_PASSWORD",
                    },
                }
            ),
            401,
        )


@app.route("/api/dummy-accounts", methods=["GET"])
def api_dummy_accounts():
    """Return public dummy accounts for laboratory testing."""
    return jsonify({"dummy_accounts": get_public_dummy_accounts()})


if __name__ == "__main__":
    # Localhost development server only
    app.run(host="127.0.0.1", port=5000, debug=True)
