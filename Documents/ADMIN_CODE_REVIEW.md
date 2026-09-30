# Admin Portal — Security Code Review
**Date:** June 9, 2026  
**Reviewer:** Internal Red Team  
**Scope:** `AdministratorControllers/` (11 files), `AdminadminController/` (1 file), `app/Http/Middleware/AuthenticateAdmin.php`, `AuthenticateAdminAdmin.php`, `Cor.php` — route analysis of all admin-related groups  
**Coverage:** 100% — all controller methods reviewed, full route mapping  
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

The Admin module is split across two roles and one misused middleware:

| Sub-module | Type | Middleware | Purpose |
|---|---|---|---|
| **Admin** | type 6 | `isAdmin` (parametric) | School administrator — account management, RFID, tapping |
| **AdminAdmin** | type 12 | `isAdminAdmin` | Multi-school admin — enrollment/cash reports |
| **FNS sync group** | any | `cors` only | Faculty/Staff account CRUD, password reset, privilege management |

**The central finding before reading a single controller:** The `cors` middleware (`App\Http\Middleware\Cor`) adds only `Access-Control-Allow-Origin: *` headers. It provides **zero authentication**. All routes under `['cors']` are fully unauthenticated and accessible from any origin.

---

## 2. Middleware Analysis

### `cors` Middleware — Critical Misuse
```php
// app/Http/Middleware/Cor.php
public function handle($request, Closure $next)
{
    return $next($request)
        ->header('Access-Control-Allow-Origin', '*')
        ->header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
}
```

`cors` is a **header-injection-only middleware** — it does not check authentication, session, or user type. Any request passes straight through. It was designed to allow cross-origin AJAX from a companion sync system, but it was applied to all faculty and staff account management routes, exposing them to the open internet.

**Routes under `['cors']` only (fully unauthenticated):**
```php
// routes/web.php — lines 455–477
Route::middleware(['cors'])->group(function () {
    Route::get('/administrator/setup/accounts/create/account', ...);
    Route::get('/administrator/setup/accounts/update/privilege', ...);
    Route::get('/administrator/setup/accounts/update/fasacadprog', ...);
    Route::get('/administrator/setup/accounts/update/information', ...);
    Route::get('/administrator/setup/accounts/update/accountinfo', ...);
    Route::get('/administrator/setup/accounts/update/active', ...);
    Route::get('/administrator/setup/accounts/remove', ...);
    Route::get('/administrator/setup/accounts/getnewinfo', ...);
    Route::get('/administrator/setup/accounts/getupdated', ...);
    Route::get('/administrator/setup/accounts/getdeleted', ...);
    Route::get('/administrator/setup/accounts/updatestat', ...);
    Route::get('/administrator/setup/accounts/getmoreinfo', ...);
    Route::get('/administrator/setup/accounts/synnew', ...);
    Route::get('/administrator/setup/accounts/syncupdate', ...);
    Route::get('/administrator/setup/accounts/syncdelete', ...);
    Route::get('/administrator/setup/accounts/updatepass', ...);  // PASSWORD RESET
    Route::get('/administrator/setup/accounts/list', ...);        // PLAINTEXT PASSWORDS
    Route::get('/administrator/setup/accounts/generateaccount', ...);
});
```

### `AuthenticateAdmin` — Parametric Role Middleware
```php
if( ( auth()->user()->type==6 || Session::get('currentPortal') == 6 )
    && ( collect($roles)->contains('admin') || collect($roles)->contains('principal') || collect($roles)->contains('dean') ) ){
    return $next($request);
}
```
Accepts `currentPortal` bypass (same as Teacher/Registrar). Also accepts type 2 (Principal), type 14 (Dean), type 16 (Chairperson) for their respective roles. Complex multi-role middleware.

### `AuthenticateAdminAdmin`
```php
if(auth()->user()->type == 12){
    return $next($request);
}
```
Type 12 = AdminAdmin (multi-school operator). Simple, no `currentPortal` bypass. Well-structured.

---

## 3. Route Mapping Table

| Method | Route | Controller@Method | Middleware | Risk |
|---|---|---|---|---|
| GET | `/administrator/setup/accounts/updatepass` | `FNSAccountController@change_password` | `cors` only | **CRITICAL** |
| GET | `/administrator/setup/accounts/list` | `FNSAccountController@list` | `cors` only | **CRITICAL** |
| GET | `/administrator/setup/accounts/create/account` | `FNSAccountController@create_fas_account` | `cors` only | **CRITICAL** |
| GET | `/administrator/setup/accounts/generateaccount` | `FNSAccountController@generateaccount` | `cors` only | HIGH |
| GET | `/administrator/setup/accounts/update/privilege` | `FNSAccountController@update_fas_priv_ajax` | `cors` only | HIGH |
| GET | `/administrator/setup/accounts/update/active` | `FNSAccountController@update_active` | `cors` only | HIGH |
| GET | `/reportcard/grade/status/approve` | `TeacherGradingV3@approveGrade` | **None** | HIGH |
| GET | `/reportcard/grade/status/post` | `TeacherGradingV3@postGrade` | **None** | HIGH |
| GET | `/administrator/setup/accounts/synnew` | `FNSAccountController@sync_insert` | `cors` only | HIGH |
| GET | `/administrator/setup/accounts/syncupdate` | `FNSAccountController@sync_update` | `cors` only | HIGH |
| GET | `/administrator/setup/accounts/syncdelete` | `FNSAccountController@sync_delete` | `cors` only | HIGH |
| GET | `/studentmasterlist` | `AdminAdminController@studentmasterlist` | **None** | MEDIUM |
| GET | `/cashtransaction` | `AdminAdminController@chrngtrans` | **None** | MEDIUM |
| GET | `/targetcollection` | `AdminAdminController@targetcollection` | **None** | MEDIUM |
| GET | `/reportcard/grade/status/pending` | `TeacherGradingV3@pendingGrade` | **None** | MEDIUM |

---

## 4. Security Findings

### A-01 — CRITICAL — Unauthenticated Password Reset for Any Account
**File:** `FNSAccountController.php` (line 1210)  
**Route:** `GET /administrator/setup/accounts/updatepass` — `cors` middleware only  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.8**

```php
public static function change_password(Request $request)
{
    $tid = $request->get('tid');   // ATTACKER-CONTROLLED — any user's email

    DB::table('users')
        ->where('email', $tid)     // Targets any account by email
        ->update([
            'password' => Hash::make('123456'),  // Resets to known default
            'isDefault' => 1,                   // Marks as default password
        ]);
    // No auth check, no current password required, no ownership check
}
```

**Impact:** Any internet visitor can reset ANY user's password to `123456` by supplying their email address:
- Admin: `?tid=admin@school.edu` → admin password reset
- Registrar: `?tid=registrar@school.edu` → registrar password reset
- Super Admin: `?tid=<admin email>` → full system takeover
- All teacher accounts: `?tid=<year><0001..NNNN>` → bulk reset via enumeration

This is the highest-severity finding across the entire engagement — completely unauthenticated, no rate limiting, resets to a **known password** (`123456`).

---

### A-02 — CRITICAL — Unauthenticated Plaintext Password Dump for All Staff
**File:** `FNSAccountController.php` (line ~500 inside `list()`)  
**Route:** `GET /administrator/setup/accounts/list` — `cors` middleware only  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5** (higher impact in practice)

```php
$temp_users = DB::table('users')
    ->whereIN('email', collect($teacher)->pluck('tid'))
    ->select(
        'email',
        'passwordstr',   // ← PLAINTEXT PASSWORD FIELD returned in response
        'type',
        'password'       // ← HASHED PASSWORD also returned
    )
    ->get();
```

The `list()` endpoint returns a JSON payload containing `passwordstr` — a column that stores passwords in plain text for historical/sync reasons. This is returned in the unauthenticated AJAX response alongside the hashed password. An attacker can retrieve login credentials for all faculty and staff in a single request.

---

### A-03 — CRITICAL — Unauthenticated Staff Account Creation
**File:** `FNSAccountController.php` (line 618)  
**Route:** `GET /administrator/setup/accounts/create/account` — `cors` middleware only  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **7.5**

```php
public static function create_fas_account(Request $request)
{
    if (!Auth::user()) {
        $userid = $request->get('userid');  // ATTACKER-CONTROLLED audit trail
    } else {
        $userid = auth()->user()->id;
    }

    $teacherid = DB::table('teacher')->insertGetId([
        'lastname'   => $request->get('lname'),
        'usertypeid' => $request->get('utype'),  // ATTACKER sets user type
        // ...
    ]);

    DB::table('users')->insertGetId([
        'type'     => $request->get('utype'),    // Any type — can create type=17 superadmin?
        'password' => Hash::make('123456'),
    ]);
}
```

Any internet visitor can create staff accounts with any `usertype`, bypassing the entire account provisioning workflow. The `usertypeid` from the request is inserted directly — if type 17 (SuperAdmin) can be specified, this is a direct privilege escalation to full system access.

---

### A-04 — HIGH — Unauthenticated Portal Privilege Modification
**File:** `FNSAccountController.php` (line 83)  
**Route:** `GET /administrator/setup/accounts/update/privilege` — `cors` middleware only  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **8.5**

```php
public static function update_fas_priv_ajax(Request $request)
{
    $userid     = $request->get('userid');    // ATTACKER-CONTROLLED target user
    $usertype   = $request->get('usertype');  // ATTACKER-CONTROLLED portal type
    $status     = $request->get('status');

    if (!Auth::user()) {
        $updateuserid = $request->get('updateuserid');  // ATTACKER-CONTROLLED audit trail
    }

    return self::update_fas_priv($userid, $usertype, $status, $updateuserid);
}
```

The `faspriv` table controls which portals each user can access (used by `gotoPortal`). An unauthenticated attacker can:
1. Grant any user access to any portal by inserting a `faspriv` record
2. Remove access to portals from legitimate users (denial of service)
3. Forge the `updateuserid` audit trail to frame another user

---

### A-05 — HIGH — Unauthenticated Account Activation/Deactivation
**File:** `FNSAccountController.php` (line 14)  
**Route:** `GET /administrator/setup/accounts/update/active` — `cors` middleware only  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5**

```php
public static function update_active(Request $request)
{
    $teacherid = $request->get('teacher');  // ATTACKER-CONTROLLED teacher ID
    $status    = $request->get('status');   // 0 = deactivate, 1 = activate

    DB::table('teacher')
        ->where('id', $teacherid)
        ->update(['isactive' => $status]);
}
```

An attacker can deactivate all teacher accounts (`status=0`) or activate deactivated accounts, disrupting system operations.

---

### A-06 — HIGH — K-12 Report Card Grade Approve/Post Without Any Middleware
**Routes:** `GET /reportcard/grade/status/approve`, `GET /reportcard/grade/status/post` — **No middleware**  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **8.1**

Both K-12 grade approval (Principal function) and grade posting (Principal/Admin function) are accessible without any authentication. This mirrors the College ECR finding (C-04) but affects K-12 basic education report cards. Any internet visitor can call these endpoints with a known grade status ID to approve or post grades for any section.

---

### A-07 — HIGH — Unauthenticated Database Sync Operations
**Routes:** `GET /administrator/setup/accounts/synnew`, `/syncupdate`, `/syncdelete` — `cors` middleware only  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` = **8.1**

These sync routes insert, update, and delete teacher/staff records in the local database. They were designed for a companion sync system but expose unauthenticated database write access. Calling `syncdelete` with a teacher ID permanently removes a staff record.

---

### A-08 — MEDIUM — AdminAdmin Reports Accessible Without Middleware
**Routes:** `GET /studentmasterlist`, `GET /cashtransaction`, `GET /targetcollection` — **No middleware**  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**

These three reports are intended for the AdminAdmin role (type 12 — multi-school operator) but have no middleware at all. They return school-wide enrollment data, cash transaction histories, and target collection figures to any visitor.

---

## 5. Backend Bugs

### BUG-A-01 — `list()` Uses `@json_encode()` (Suppressed Errors)
```php
return @json_encode((object) ['data' => $teacher, ...]);
```
The `@` operator silently suppresses encoding errors. If `$teacher` contains non-UTF-8 data, the response is `null` with no error feedback.

### BUG-A-02 — `generateaccount()` Calls `auth()->user()->id` Under CORS (No Auth)
```php
// When refid==36 (TESDA trainer), calls auth()->user()->id with no auth middleware
'createdby' => auth()->user()->id,  // throws "Trying to get property of non-object"
```
For TESDA trainer accounts, unauthenticated calls crash with a 500 error after the `users` record is already inserted — leaving orphaned user accounts.

### BUG-A-03 — `change_password()` Targets by `tid` (Teacher ID Format), Not `userid`
The route uses `?tid=<email>` but teacher accounts use format `<year><sequence>` (e.g., `20260001`). Targeting admin accounts requires knowing their email format. However, the `users` table stores admin emails in their actual email format, making them targetable by guessing `admin@`, `registrar@`, etc.

---

## 6. Fix Recommendations

| Finding | Priority | Fix |
|---|---|---|
| A-01 (`change_password` no auth) | **IMMEDIATE** | Remove route entirely OR add `['auth', 'isAdmin:admin']`; require current password in body |
| A-02 (`list` returns passwordstr) | **IMMEDIATE** | Remove `passwordstr` from SELECT; add `['auth', 'isAdmin:admin']` to route |
| A-03 (`create_fas_account` no auth) | **IMMEDIATE** | Add `['auth', 'isAdmin:admin']`; validate `utype` against an allowlist of permitted types |
| A-04 (`update_fas_priv` no auth) | **IMMEDIATE** | Add `['auth', 'isAdmin:admin']` |
| A-05 (`update_active` no auth) | **IMMEDIATE** | Add `['auth', 'isAdmin:admin']` |
| A-06 (grade approve/post no auth) | **IMMEDIATE** | Add `['auth', 'isSuperAdmin:principal']` to approve/post routes |
| A-07 (sync routes no auth) | High | Gate sync routes with IP allowlist or shared secret header; not open-internet routes |
| A-08 (AdminAdmin reports no auth) | High | Move inside `['auth', 'isAdminAdmin']` group |
| BUG-A-01 (`@json_encode`) | Low | Remove `@` suppressor; use `response()->json()` |
| BUG-A-02 (null auth in generateaccount) | Medium | Add auth check before calling `auth()->user()->id` |

---

*End of Admin Portal Code Review*
