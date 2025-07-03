# 🛡️ INFO 4345 Web Application Security Project
**Project Name:** BiteBarakah2  
**Course:** INFO 4345 Web Application Security 
**Semester:** Semester 2, 2024/2025  
**Institution:** International Islamic University Malaysia
**Group Name:** Last  
**Members:**
- Raja Muhamad Umar (2119191) [Rubrics 1–4]
- Muhammad Afzal Bin Mohd Nor (2123023) [Rubrics 5–8]
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

---

### ✅ Rubric 5: Authentication – Session Management

**Explanation:**

Laravel ensures strong session management by:
- Regenerating session IDs after login (prevents session fixation)
- Auto-expiring sessions after a defined timeout
- Securing cookies with `HttpOnly`, `Secure`, and `SameSite` flags

**Code:**

```php
// app/Http/Controllers/Auth/AuthenticatedSessionController.php
$request->session()->regenerate();

// .env
SESSION_LIFETIME=60

// config/session.php
'secure' => env('SESSION_SECURE_COOKIE', true),
'http_only' => true,
'same_site' => 'lax',

---

### ✅ Rubric 6: Authentication – Multi-Factor Authentication

**Explanation:**

To enhance security, 2FA (Time-based One-Time Password) was added for admin users using the pragmarx/google2fa package.
Admins can enable 2FA from a dedicated page, generating a secret key and recovery codes. These can be used with apps like Google Authenticator.

**Code:**

// Enable 2FA: routes/web.php
use Illuminate\Support\Str;
use PragmaRX\Google2FA\Google2FA;

Route::post('/admin/2fa/enable', function () {
    $user = auth()->user();
    $user->forceFill([
        'two_factor_secret' => encrypt((new Google2FA)->generateSecretKey()),
        'two_factor_recovery_codes' => encrypt(json_encode(
            collect(range(1, 8))->map(fn () => Str::random(10))->all()
        )),
    ])->save();

    return back()->with('status', '2FA enabled. Store your recovery codes.');
})->middleware(['auth', 'is_admin'])->name('admin.2fa.enable');

<!-- View: resources/views/admin/2fa.blade.php -->
@if (auth()->user()->two_factor_secret)
    <p>✅ 2FA is enabled</p>
    <form method="POST" action="{{ route('admin.2fa.disable') }}">
        @csrf
        <button type="submit">Disable 2FA</button>
    </form>
@else
    <form method="POST" action="{{ route('admin.2fa.enable') }}">
        @csrf
        <button type="submit">Enable 2FA</button>
    </form>
@endif

---

### ✅ Rubric 7: Authorization – Default Permissions

**Explanation:**

Basic access control is enforced:

-Guests are redirected to the registration page.

-Only authenticated users can access /home.

-Non-admin users trying to access admin routes are shown a 403 Forbidden page.

**Code:**

// web.php
Route::get('/', function () {
    return Auth::check() ? redirect('/home') : redirect()->route('register');
});

Route::get('/home', function () {
    return view('home');
})->middleware('auth')->name('home');

// Inside controller
if (!auth()->check() || !auth()->user()->is_admin) {
    abort(403); // Forbidden access
}

---

### ✅ Rubric 8: Authorization – Role-Based Access Control (RBAC)

**Explanation:**

Access to admin routes is protected based on roles:

-An is_admin column is added to the users table

-Middleware is_admin is used to protect sensitive admin routes

-Only users with is_admin = 1 can access these routes

**Code:**

// Migration
Schema::table('users', function (Blueprint $table) {
    $table->boolean('is_admin')->default(false);
});

// Middleware: app/Http/Middleware/IsAdmin.php
public function handle(Request $request, Closure $next)
{
    if (!auth()->user()->is_admin) {
        abort(403);
    }

    return $next($request);
}

// Route group with middleware
Route::middleware(['auth', 'is_admin'])->group(function () {
    Route::get('/admin', [AdminController::class, 'index'])->name('admin.index');
    Route::get('/admin/orders', [AdminController::class, 'viewOrders'])->name('admin.orders');
});

---

**How to Test**

-✅ Log in as a normal user → access to /home ✅ but access to /admin ❌ (403) (Rubric 7: Authorization – Default Permissions)

-✅ Log in as an admin user (is_admin = 1 in DB) → access to /admin ✅ (Rubric 8: Authorization – Role-Based Access Control (RBAC))

-✅ Go to /admin/2fa → enable 2FA and scan with Google Authenticator (Rubric 6: Authentication – Multi-Factor Authentication)

-✅ Session auto-expires after timeout (SESSION_LIFETIME), and regenerates on login (Rubric 5: Authentication – Session Management)


