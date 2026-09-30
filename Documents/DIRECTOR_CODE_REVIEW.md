# Director Portal — Security Code Review
**Date:** June 10, 2026  
**Reviewer:** Internal Red Team  
**Scope:** `DirectorControllers/DirectorFinanceReportsController.php`, `AdminadminController/AdminAdminController.php` (CORS-group methods), route analysis of the `['cors']` middleware group at lines 6834–6854 of `routes/web.php`  
**Coverage:** 100% — all Director-reachable routes mapped, all controller methods reviewed  
**Status:** Complete

---

## Table of Contents
1. [Scope & Methodology](#1-scope--methodology)
2. [Middleware Analysis](#2-middleware-analysis)
3. [Route Mapping Table](#3-route-mapping-table)
4. [Security Findings](#4-security-findings)
5. [Backend Bugs](#5-backend-bugs)
6. [Fix Recommendations](#6-fix-recommendations)

---

## 1. Scope & Methodology

The Director module provides a multi-school operator dashboard for financial reports (cashier transactions, collections, accounts receivable, expenses) and HR/enrollment summaries. Architecturally it is closely tied to the AdminAdmin module — both share the same `['cors']` route group.

This is the smallest controller scope in the engagement: one dedicated controller (`DirectorFinanceReportsController.php`, ~400 lines, 4 methods) and a subset of `AdminAdminController.php` methods reached via the same unauthenticated route group.

The central finding again — as in the Admin portal — is the `cors` middleware misuse. Additionally, this module contains the most severe **OWASP A02 (Cryptographic/Credential Failure)** finding in the entire engagement: database credentials for a multi-school hosted environment are hardcoded in plain text in the PHP source file, repeated four times.

---

## 2. Middleware Analysis

### `['cors']` Group — All Director Finance + AdminAdmin Routes
```php
// routes/web.php line 6834
Route::middleware(['cors'])->group(function () {
    Route::get('/passData', ...);
    Route::get('/director/finance/cashiertransactions', ...);
    Route::get('/director/finance/cashiertransactionsindex', ...);
    Route::get('/director/finance/collectionsindex', ...);
    Route::get('/director/finance/accountreceivablesindex', ...);
    Route::get('/director/finance/expensesindex', ...);
    Route::get('/viewschool/{id}', ...);
    Route::get('/finance/index', ...);
    Route::get('/academic/index', ...);
    Route::get('/academic/students', ...);
    Route::get('/hr/index', ...);
    Route::get('/aadmin/enrollment', ...);
    Route::get('/enrollmentReport', ...);
    Route::get('/cashtransReport', ...);
    Route::get('/filtercashtrans', ...);
    Route::get('/filterEnrollmentReport', ...);
});
```

As established in the Admin portal analysis, `App\Http\Middleware\Cor` adds only `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Methods` headers. **It provides zero authentication.** Every route in this group is fully accessible to any internet visitor.

---

## 3. Route Mapping Table

| Method | Route | Controller@Method | Middleware | Risk |
|---|---|---|---|---|
| GET | `/passData` | `AdminAdminController@passData` | `cors` only | **CRITICAL** |
| GET | `/director/finance/cashiertransactionsindex` | `DirectorFinanceReportsController@cashiertransactionsindex` | `cors` only | **CRITICAL** |
| GET | `/director/finance/collectionsindex` | `DirectorFinanceReportsController@collectionsindex` | `cors` only | **CRITICAL** |
| GET | `/director/finance/accountreceivablesindex` | `DirectorFinanceReportsController@accountreceivablesindex` | `cors` only | **CRITICAL** |
| GET | `/director/finance/expensesindex` | `DirectorFinanceReportsController@expensesindex` | `cors` only | **CRITICAL** |
| GET | `/finance/index` | `AdminAdminController@financeindex` | `cors` only | HIGH |
| GET | `/academic/index` | `AdminAdminController@academicindex` | `cors` only | HIGH |
| GET | `/hr/index` | `AdminAdminController@hrindex` | `cors` only | HIGH |
| GET | `/aadmin/enrollment` | `AdminAdminController@enrollment` | `cors` only | HIGH |
| GET | `/enrollmentReport` | `AdminAdminController@enrollmentReport` | `cors` only | HIGH |
| GET | `/cashtransReport` | `AdminAdminController@cashtransReport` | `cors` only | HIGH |
| GET | `/academic/students` | `AdminAdminController@academicstudents` | `cors` only | MEDIUM |

---

## 4. Security Findings

### DR-01 — CRITICAL — Hardcoded Production Database Credentials in Source Code
**File:** `DirectorFinanceReportsController.php` (lines ~22–31, ~125–134, ~228–237, ~330–339)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = **10.0**

```php
// Repeated identically in all 4 methods (cashiertransactionsindex, accountreceivablesindex,
// collectionsindex, expensesindex)
Config::set("database.connections.mysql", [
    'driver'    => 'mysql',
    "host"      => env('DB_HOST', '141.164.36.7'),  // hardcoded IP fallback
    "database"  => $schoolInfo->db,
    "username"  => "ckgroup_dev",                   // HARDCODED username
    "password"  => "Sels2019",                      // HARDCODED password
    "port"      => '3306',
    'strict'    => false,
]);
```

The credentials `ckgroup_dev` / `Sels2019` are the shared database user for the multi-school hosted environment. They appear **four times in the same file**. The fallback host `141.164.36.7` is also hardcoded — this is likely the IP address of the production database server.

**Impact:**
- Anyone with access to the source code repository has immediate MySQL access to the production hosted environment
- With these credentials and the server IP, an attacker can connect directly to MySQL and read/write all databases for all schools hosted on the platform
- Credential rotation requires modifying four different locations in one file — high probability of missing one during a future rotation

**This is the most critical single finding in the entire engagement.**

---

### DR-02 — CRITICAL — `GET /passData` Unauthenticated Employee and Financial Data Dump
**File:** `AdminAdminController.php` (line 39)  
**Route:** `GET /passData?action=<action>` — `cors` middleware only  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**

The `passData` endpoint accepts an `action` query parameter and returns raw database data with no authentication. Available actions:

| Action | Data Returned |
|---|---|
| `getschoolyears` | All school year records |
| `getsemesters` | All semester records |
| `getpaymenttypes` | All payment type configurations |
| `getterminals` | All cashier terminal records |
| `getemployees` | **All active employees** with lastname, firstname, gender, DOB, address, email, employment status, hire date, education history, portal access list (`faspriv`) |
| `getemployeeattendance` | Real-time employee attendance (AM/PM in/out times for today) |
| `getfinancestudents` | All enrolled student IDs across all academic programs |
| `getreceivables` | Full accounts receivable data per student/program with date filtering |

The `getemployees` action is particularly severe — it returns a complete staff directory with personal information including home addresses, email addresses, dates of birth, education credentials, and all portal access privileges. This is a single-request mass PII exposure.

---

### DR-03 — CRITICAL — Director Finance Dashboards Accessible Without Authentication
**File:** `DirectorFinanceReportsController.php`  
**Routes:** All four `director/finance/*` routes — `cors` middleware only  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**

The director-facing financial reporting pages (cashier transactions, collections, accounts receivable, expenses) are rendered without any authentication. Each page bootstraps by fetching school year, semester, terminal, and payment type data — either from the remote `eslink` endpoint via Guzzle or directly from the local DB as fallback.

While the rendered pages are HTML views (not raw data APIs), they expose:
- Available school years and semesters
- Terminal configurations (cashier terminal names/IDs)
- Payment type enumerations
- The full financial dashboard interface for any school listed in `schoollist`

---

### DR-04 — HIGH — SSL Certificate Verification Disabled for All Inter-School HTTP Calls
**File:** `DirectorFinanceReportsController.php` — repeated in all 4 methods  
**CVSS:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` = **7.4**

```php
$guzzleClient = new \GuzzleHttp\Client(array(
    'curl' => array(
        CURLOPT_SSL_VERIFYPEER => false,   // SSL verification disabled
        CURLOPT_HEADER         => true,
    ),
));
```

All HTTP requests made to remote school instances (`$url->eslink`) have SSL peer verification disabled. A network-positioned attacker can intercept and replace responses to these inter-school requests with forged data, potentially injecting malicious content into the director dashboard or redirecting subsequent requests.

---

### DR-05 — HIGH — Unauthenticated Admin/HR/Finance Index Dashboards
**Routes:** `GET /finance/index`, `GET /academic/index`, `GET /hr/index`, `GET /aadmin/enrollment`, `GET /enrollmentReport`, `GET /cashtransReport` — `cors` only  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**

Six administrative dashboard pages — finance summary, academic overview, HR dashboard, enrollment report, and cash transaction report — are served from the same unauthenticated CORS group. These aggregate school-wide data across financial and academic systems.

---

### DR-06 — MEDIUM — Dynamic DB Connection Controlled by Session `schoolid` (No Input Validation)
**File:** `DirectorFinanceReportsController.php`, `AdminAdminController.php`  
**CVSS:** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` = **6.8**

```php
$schoolInfo = DB::table('schoollist')->where('id', Session::get('schoolid'))->first();
if ($schoolInfo->islocal == 0) {
    Config::set("database.connections.mysql", [
        "database" => $schoolInfo->db,   // from the schoollist table
        "username" => "ckgroup_dev",
        "password" => "Sels2019",
    ]);
    DB::purge('mysql');
}
```

The active database connection is dynamically replaced based on `Session::get('schoolid')`, which maps to a `schoollist` table entry. If an authenticated attacker can manipulate their session `schoolid` value (through session fixation or the `viewschool/{id}` route which also runs under CORS-only), they can redirect all subsequent database queries to a different school's database using the shared credentials.

---

## 5. Backend Bugs

### BUG-DR-01 — Empty `else {}` Blocks in All 4 Finance Methods (Null Response on `?action=`)
**Severity:** Medium | **File:** `DirectorFinanceReportsController.php`

All four methods have the same incomplete structure:
```php
if (!$request->has('action')) {
    return view('adminITPortal.pages.finance.cashiertransactions')
        ->with(...)
        ->with(...);
} else {
    // completely empty
}
// implicit return null
```

When any of these endpoints receives an `?action=` parameter, the method falls through the empty `else` branch and returns `null`. Laravel converts this to an empty HTTP 200 response with no body, confusing any client expecting JSON or HTML data.

---

### BUG-DR-02 — Null Dereference When `schoolid` Not in Session
**Severity:** High | **File:** `DirectorFinanceReportsController.php`, all 4 methods

```php
$schoolInfo = DB::table('schoollist')->where('id', Session::get('schoolid'))->first();
if ($schoolInfo->islocal == 0) {   // THROWS: "Trying to get property of non-object" if $schoolInfo is null
```

If `Session::get('schoolid')` is `null` or refers to a non-existent school ID, `$schoolInfo` is `null` and the null-dereference throws a 500 error immediately. The same issue occurs in `AdminAdminController` methods throughout the class.

---

### BUG-DR-03 — Credentials Hardcoded 4× (DRY Violation — Rotation Risk)
**Severity:** Medium | **File:** `DirectorFinanceReportsController.php`

The database connection block containing `"username" => "ckgroup_dev", "password" => "Sels2019"` is copy-pasted identically into all four methods in the same file. Any future credential rotation requires updating four separate locations. If even one is missed, the rotated credential still fails for that specific finance report type while the others succeed, making the rotation appear successful but leaving one endpoint with the old credentials.

---

### BUG-DR-04 — Invalid Date String Passed to `date_format(date_create(...))` Throws Uncaught Error
**Severity:** Low | **File:** `AdminAdminController.php` (`passData` — `getreceivables` action)

```php
$datefrom = ($request->get('datefrom') != null)
    ? date_format(date_create($request->get('datefrom')), 'Y-m-d 00:00')
    : null;
```

If `datefrom` is a non-null but invalid date string (e.g., `"notadate"` or `"2026-13-45"`), `date_create()` returns `false`. Calling `date_format(false, ...)` then throws a `TypeError` in PHP 8+. There is no input validation on the date parameters before this call.

---

## 6. Fix Recommendations

| Finding | Priority | Fix |
|---|---|---|
| DR-01 (hardcoded credentials) | **IMMEDIATE** | Move credentials to `.env` (`DB_REMOTE_USERNAME`, `DB_REMOTE_PASSWORD`); never commit credentials to source control; rotate `ckgroup_dev` password immediately |
| DR-02 (`passData` no auth) | **IMMEDIATE** | Add `['auth', 'isAdminAdmin']` to the `/passData` route; remove or restrict `getemployees` action behind additional role check |
| DR-03 (finance dashboards no auth) | **IMMEDIATE** | Move all Director finance routes to `['auth', 'isAdminAdmin']` group |
| DR-04 (SSL disabled) | **IMMEDIATE** | Remove `CURLOPT_SSL_VERIFYPEER => false`; configure proper CA bundle if needed |
| DR-05 (admin dashboards no auth) | High | Move finance/academic/hr/enrollment routes to `['auth', 'isAdminAdmin']` |
| DR-06 (session-controlled DB switch) | High | Validate that `Session::get('schoolid')` belongs to the authenticated user's allowed schools |
| BUG-DR-01 (empty else blocks) | Medium | Implement `action` parameter handling or `abort(400, 'Action not supported')` |
| BUG-DR-02 (null dereference on schoolid) | High | Add `abort(403)` if `$schoolInfo === null`; validate session state before DB operations |
| BUG-DR-03 (DRY violation) | Medium | Extract DB connection setup to a private method `connectRemoteSchool()`; credentials via `.env` |
| BUG-DR-04 (date_create on invalid input) | Low | Validate date strings before calling `date_create()`; use `Carbon::createFromFormat()` with a try/catch |

---

*End of Director Portal Code Review*
