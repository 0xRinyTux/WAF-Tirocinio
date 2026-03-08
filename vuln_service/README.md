# Vulnerable Test Service

**WARNING: This application contains INTENTIONAL vulnerabilities (SQL Injection, XSS).**
**It is intended for educational purposes and security testing ONLY.**
**DO NOT DEPLOY IN A PRODUCTION ENVIRONMENT.**

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   python app.py
   ```

## Vulnerabilities

### 1. SQL Injection (`/login`)
The login form is vulnerable to SQL injection because user input is concatenated directly into the query string.
- **Test:** Try logging in with `admin' --` as the username and any password.

### 2. Reflected XSS (`/search`)
The search endpoint reflects the `q` parameter directly into the HTML response without escaping.
- **Test:** Visit `/search?q=<script>alert(1)</script>`
