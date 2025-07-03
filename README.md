# 🛡️ INFO 4345 Web Application Security Project
**Project Name:** BiteBarakah2  
**Course:** INFO 4345 Web Application Security 
**Semester:** Semester 2, 2024/2025  
**Institution:** International Islamic University Malaysia
**Group Name:** Last  
**Members:**
- Raja Muhamad Umar [Rubrics 1–4]
- [Teammate 2 Name] [Rubrics 5–8]
- [Teammate 3 Name] [Rubrics 9–13]

---

## 🔍 Overview
This project is an enhancement of our previous Laravel-based web application `bitebarakah2`, which has been evaluated and improved based on 13 web application security principles aligned with the course rubric and OWASP best practices.

Based on the given rubrics, each group member focused on specific security criteria, and changes were implemented across authentication, validation, session handling, authorization, browser security, database access, and file protection.

---

## ✅ Vulnerability Scan Report (ZAP)
- Tool: OWASP ZAP vX.X.X
- Target: http://127.0.0.1:8000
- Result: [Summary of ZAP results]
- Before Fixes
    🟠 Medium Risk (2 alerts)
    1. Content Security Policy (CSP) Header Not Set
        - Description: Missing CSP headers means browsers have no restrictions on where content (e.g., JS, fonts, CSS) can be loaded from. This increases risk of XSS and code injection.
        - Pages Affected: /login, /register, /home, /forgot-password, /sitemap.xml
        - Fix suggestion: Add a Content-Security-Policy header in your Laravel middleware.

    2. Missing Anti-clickjacking Header (X-Frame-Options)
        - Description: Your site doesn’t block iframe embedding, making it vulnerable to clickjacking.
        - Pages Affected: /login, /register, /home, /forgot-password
        - Fix suggestion: Add X-Frame-Options: DENY or use CSP frame-ancestors 'none';.

    🟡 Low Risk (5 alerts)
    1. Big Redirect Detected
        - Description: Large redirect responses may unintentionally leak sensitive information in the response body.
        - Pages Affected: /, /login, /register, /home, /forgot-password
    2. Cookie Missing HttpOnly Flag
        - Description: Cookies without HttpOnly are accessible to JavaScript, increasing risk of session hijacking.
        - Fix suggestion: Ensure cookies are set with HttpOnly.
    3. Cross-Domain JS File Inclusion
        - Description: External scripts (like Google Fonts or JSCDN) were loaded without CSP restrictions.
        - Fix suggestion: Use CSP to restrict allowed JS origins.
    4. Server Leaks Info via X-Powered-By Header
        - Description: This header exposes technology stack info (e.g., PHP), which helps attackers.
        - Fix suggestion: Remove this header in Laravel or your server config.
    5. Missing X-Content-Type-Options Header
        - Description: Without this, browsers may attempt MIME-type sniffing, which can lead to XSS.
        - Fix suggestion: Set X-Content-Type-Options: nosniff.

    ℹ️ Informational (3 alerts)
    1. Authentication Request Identified
        - ZAP detected login forms on the site.
    2. Session Management Response Identified
        - Session tokens were found in responses (normal for login systems).
    3. User-Agent Fuzzing
        - No exploit found, just ZAP testing different user-agents.

📄 [View Full ZAP Report](reports/2025-06-30-ZAP-Report-bitebarakah2.html)

---

## 🔒 Rubric-based Security Enhancements

### 🧾 Rubrics 1–4 (Handled by Umar)

---

### ✅ **Rubric 1: Input Validation**

**Issue (Before):**  
- No validation in `OrderController`
- Basic rules only for registration/login

**Fix (After):**
- Applied strict server-side validation:
```php
$request->validate([
  'name' => 'required|string|max:100',
  'email' => 'required|email:rfc,dns|max:255|unique:users,email',
  'password' => [
    'required', 'string', 'min:8', 'confirmed',
    'regex:/[A-Z]/', 'regex:/[a-z]/', 'regex:/[0-9]/', 'regex:/[@$!%*#?&]/',
  ],
]);


<!-- Force update -->
<!-- Dummy test commit -->
