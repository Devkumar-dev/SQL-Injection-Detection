# Detection, Exploitation, and Mitigation of SQL Injection Vulnerabilities in Web Applications

**College Minor Project — Educational Cybersecurity Laboratory**  
*Technology Stack: Python 3, Flask, SQLite3, HTML5, Vanilla CSS3, Pytest*

---

## 1. Project Abstract & Objectives

SQL Injection (SQLi / CWE-89 / OWASP Top 10 A03:2021) remains one of the most critical vulnerabilities affecting data-driven web applications. This college minor project provides a self-contained, educational cybersecurity laboratory designed to examine, demonstrate, and mitigate SQL injection vulnerabilities in a strictly isolated localhost environment.

### Core Objectives:
1. **Detection (Phase 1)**: Inspect incoming user parameters for syntax breakout characters, comment sequences, tautologies, and dangerous keywords; explain the behavioral distinction between normal and suspicious login inputs.
2. **Exploitation Analysis (Phase 2)**: Provide a safe, self-contained educational simulator that models how dynamic string concatenation alters the Abstract Syntax Tree (AST) of SQL queries, without executing live database bypasses or targeting external systems.
3. **Mitigation (Phase 3)**: Implement production-grade defenses using SQLite parameterized queries (`?` placeholders) and cryptographically salted password hashing (`PBKDF2:SHA256`).
4. **Interactive Dashboard**: Provide an intuitive cybersecurity operations center (SOC) web interface for real-time input scanning, query simulation, live authentication testing, and architectural comparison.
5. **Automated Verification**: Validate all phases through a 19-test automated test suite using `pytest`.

---

## 2. Theoretical Background

### What is SQL Injection?
SQL injection occurs when untrusted user input is directly concatenated into a dynamic SQL query string before being submitted to the database engine. In this scenario, the database parser cannot distinguish between **intended query instructions** (code) and **user-supplied parameters** (data).

### Normal vs. Suspicious Login Behavior

| Behavioral Dimension | Normal User Behavior | Suspicious / Malicious Behavior |
| :--- | :--- | :--- |
| **Input Characters** | Alphanumeric characters (`[a-zA-Z0-9_]`), standard email formats (`user@domain.com`). | Meta-characters (`'`, `"`, `;`), comment delimiters (`--`, `/* */`), and whitespace manipulations. |
| **Input Structure** | Simple literal tokens representing credentials. | Syntactic expressions designed to manipulate boolean logic (`' OR '1'='1`). |
| **Query Logic** | Checks for an exact match: `username = ? AND password = ?`. | Forces unconditional evaluation: `WHERE username = '' OR '1'='1'` or comments out subsequent clauses (`admin'--`). |
| **Database Response** | Exactly 1 record retrieved (if valid) or 0 records (if invalid). | Entire tables or unintended records retrieved; syntax error exceptions leaked. |

---

## 3. System Architecture & Data Flow

```mermaid
flowchart TD
    subgraph Client ["Client Browser (Localhost Dashboard)"]
        UI[Cybersecurity Web UI]
    end

    subgraph Server ["Flask Backend Server (app.py)"]
        Detect[Detection Engine /api/detect]
        Sim[AST Query Simulator /api/simulate-exploit]
        SecureAuth[Secure Parameterized Auth /api/secure-login]
    end

    subgraph Database ["SQLite Local Database (sql_lab.db)"]
        PreparedStatement["Pre-compiled Query Plan: SELECT ... WHERE username = ?"]
        Hasher["PBKDF2:SHA256 Salted Verification"]
        UsersTable[(Dummy Users Table)]
    end

    UI -->|Input String| Detect
    Detect -->|Risk Score & Patterns| UI

    UI -->|Simulated Payload| Sim
    Sim -->|AST Breakdown & Theoretical Outcome| UI

    UI -->|Login Credentials| SecureAuth
    SecureAuth -->|Bound Parameter (Literal)| PreparedStatement
    PreparedStatement --> UsersTable
    UsersTable --> Hasher
    Hasher -->|Success / Neutralized Diagnostic| SecureAuth
    SecureAuth -->|Response Payload| UI
```

---

## 4. Implementation Details

### File Structure
```text
SQL-Injection-Detection/
├── .gitignore               # Ignores bytecode, caches, and local database files
├── requirements.txt         # Dependencies: Flask, pytest
├── database.py              # SQLite schema, dummy account seeding, parameterized auth
├── app.py                   # Flask server, detection engine, simulation & API routes
├── README.md                # Comprehensive minor project documentation
├── static/
│   └── style.css            # Dark-mode cybersecurity SOC dashboard stylesheet
├── templates/
│   └── index.html           # Interactive multi-tab cybersecurity dashboard
└── tests/
    └── test_app.py          # 19 automated test cases covering all 3 phases
```

### Phase 1: Detection Engine (`app.py`)
The detection engine employs pattern matching and heuristic rules to inspect user input:
- `RULE_QUOTE_DELIMITER`: Identifies single/double quotes (`'`, `"`) and escape slashes.
- `RULE_COMMENT_DELIMITER`: Flags SQL inline comment sequences (`--`, `/* ... */`, `#`).
- `RULE_BOOLEAN_TAUTOLOGY`: Detects boolean logic manipulation (`OR 1=1`, `OR 'a'='a'`, `OR true`).
- `RULE_KEYWORD_STACKING`: Identifies DDL/DML keywords (`UNION SELECT`, `DROP TABLE`, `UPDATE`).
- `RULE_MULTIPLE_STATEMENTS`: Flags command chaining via semicolons (`;`).
- `RULE_DATABASE_FINGERPRINT`: Detects probing functions (`sleep()`, `sqlite_version()`).

Risk scoring scales from `0` to `100` and classifies inputs into `SAFE`, `SUSPICIOUS`, or `HIGH RISK`.

### Phase 2: Exploitation Analysis Simulator (`app.py`)
Rather than executing a live attack against a database, the simulator provides a safe, in-memory model of query construction:
1. Takes the user's input string.
2. Injects it into the fictional vulnerable template:
   ```sql
   SELECT * FROM users WHERE username = '{username}' AND password = '{password}';
   ```
3. Performs syntax tokenization:
   - Identifies if a quote breaks string boundary.
   - Detects if an `OR` operator and tautological condition (`'1'='1'`) alters the boolean structure.
   - Detects if comment tokens (`--`) truncate the password check.
4. Generates an educational report describing the theoretical impact (e.g., authentication bypass condition or syntax error risk) without touching real credentials.

### Phase 3: Mitigation (`database.py` & `app.py`)
Production-grade defenses are demonstrated through two core mechanisms:
1. **Parameterized Queries (Prepared Statements)**:
   ```python
   query = "SELECT id, username, password_hash, full_name, role FROM users WHERE username = ?"
   cursor.execute(query, (username,))
   ```
   SQLite compiles the query structure *before* receiving the parameter. The parameter `username` is treated strictly as a string constant. If `' OR '1'='1` is submitted, SQLite queries for a user whose literal username is `"' OR '1'='1"`.
2. **Cryptographic Salted Password Hashing**:
   - Implemented via `werkzeug.security.generate_password_hash` using `pbkdf2:sha256` with 16-byte cryptographically random salts.
   - Passwords are never stored in plaintext.
   - Password verification is performed via `check_password_hash`.

---

## 5. Vulnerable vs. Parameterized Comparison

| Dimension | Vulnerable Construction (Dynamic String Concatenation) | Secure Implementation (Parameterized Queries) |
| :--- | :--- | :--- |
| **Query Compilation** | Query string and user input are compiled together. User input can introduce new SQL commands. | The query plan is pre-compiled. User parameters are bound separately as literals. |
| **Character Interpretation** | Quotes (`'`, `"`) and operators (`OR`, `--`) act as control tokens. | All input characters are treated as literal text values. |
| **Input Handling** | Sensitive to unexpected characters; easily broken. | Robust against arbitrary input strings without manual escaping. |
| **Password Storage** | Plaintext or weak unsalted hashes (MD5/SHA1). | Salted PBKDF2:SHA256 hashes resistant to dictionary attacks. |
| **Defense Depth** | None. Single failure grants full database access. | Multi-layered: Parameterized Queries + Input Validation + Least Privilege. |

---

## 6. Seeded Educational Dummy Accounts

For laboratory evaluation, `database.py` automatically initializes `sql_lab.db` with non-sensitive fictional accounts:

| Username | Role | Full Name | Sample Password |
| :--- | :--- | :--- | :--- |
| `alice` | Security Analyst | Alice Vance | `AlicePassword123!` |
| `bob` | Compliance Auditor | Bob Miller | `BobPassword456!` |
| `admin_demo` | System Administrator | Educational Admin | `AdminLabDemo789!` |

*(All passwords are stored strictly as salted PBKDF2 hashes).*

---

## 7. Automated Test Suite & Evaluation Results

The test suite in `tests/test_app.py` contains 19 automated tests validating all three project phases:

```bash
python -m pytest tests/test_app.py -v
```

### Test Suite Execution Output:
```text
tests/test_app.py::TestDetectionEngine::test_normal_alphanumeric_inputs PASSED [  5%]
tests/test_app.py::TestDetectionEngine::test_normal_email_input PASSED   [ 10%]
tests/test_app.py::TestDetectionEngine::test_empty_and_whitespace_input PASSED [ 15%]
tests/test_app.py::TestDetectionEngine::test_detect_quote_delimiter PASSED [ 21%]
tests/test_app.py::TestDetectionEngine::test_detect_comment_truncation PASSED [ 26%]
tests/test_app.py::TestDetectionEngine::test_detect_boolean_tautology PASSED [ 31%]
tests/test_app.py::TestDetectionEngine::test_detect_stacked_keywords PASSED [ 36%]
tests/test_app.py::TestExploitationSimulator::test_simulation_normal_input PASSED [ 42%]
tests/test_app.py::TestExploitationSimulator::test_simulation_tautology_breakout PASSED [ 47%]
tests/test_app.py::TestExploitationSimulator::test_simulation_unbalanced_quote PASSED [ 52%]
tests/test_app.py::TestDatabaseAndMitigation::test_database_initialization_and_seeding PASSED [ 57%]
tests/test_app.py::TestDatabaseAndMitigation::test_legitimate_authentication_succeeds PASSED [ 63%]
tests/test_app.py::TestDatabaseAndMitigation::test_invalid_password_fails PASSED [ 68%]
tests/test_app.py::TestDatabaseAndMitigation::test_sql_injection_attempt_fails_against_parameterized_query PASSED [ 73%]
tests/test_app.py::TestApiEndpoints::test_index_route PASSED             [ 78%]
tests/test_app.py::TestApiEndpoints::test_api_detect_endpoint PASSED     [ 84%]
tests/test_app.py::TestApiEndpoints::test_api_simulate_exploit_endpoint PASSED [ 89%]
tests/test_app.py::TestApiEndpoints::test_api_secure_login_success PASSED [ 94%]
tests/test_app.py::TestApiEndpoints::test_api_secure_login_injection_neutralized PASSED [100%]

============================= 19 passed in 7.60s ==============================
```

---

## 8. Installation & Local Run Guide

### Prerequisites
- Python 3.9+ (Tested on Python 3.14)
- Git (optional)

### Setup Steps
1. Navigate to the project directory:
   ```bash
   cd SQL-Injection-Detection
   ```

2. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

3. Initialize database and seed dummy accounts:
   ```bash
   python database.py
   ```

4. Run the automated test suite:
   ```bash
   python -m pytest tests/test_app.py -v
   ```

5. Launch the local web server:
   ```bash
   python app.py
   ```

6. Open your web browser and navigate to:
   ```text
   http://127.0.0.1:5000
   ```

---

## 9. Security, Ethical, and Lab Isolation Notice

- **Localhost Isolation**: The application binds exclusively to `127.0.0.1` and communicates only with a local SQLite database file (`sql_lab.db`).
- **Fictional Data**: All user accounts, names, and passwords are non-sensitive fictional test data created specifically for this lab.
- **Safe Exploitation Simulation**: The exploitation phase does not perform live attacks, credential harvesting, or unauthorized bypasses. It is an educational query syntax model.
- **No External Targets**: This tool is an educational academic artifact and must never be used against external systems.

---

## 10. Limitations and Future Improvements

1. **Object-Relational Mapping (ORM)**: Integrate high-level ORMs such as SQLAlchemy to demonstrate automated parameterization and abstract away raw SQL writing.
2. **Adaptive Machine Learning Detection**: Supplement regex signature matching with NLP/Bayesian classifiers to detect novel SQLi variations (e.g., heavily encoded or obfuscated payloads).
3. **Multi-Database Support**: Extend the simulation model to compare dialect differences between SQLite, PostgreSQL, and MySQL (e.g., stacked query support, string concatenation operators).
4. **Rate Limiting & Account Lockout**: Implement token-bucket rate limiting and temporary account lockout to prevent automated brute-force attacks.
