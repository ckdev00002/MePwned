# Parent Portal — Security Code Review
**Date:** June 08, 2026   
**Scope:** `app/Http/Controllers/ParentControllers/` (2 files), `app/Http/Middleware/AuthenticateParent.php`, `routes/web.php` (parent sections)  
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

The Parent portal allows parents (type=9) to view their child's grades, attendance, billing, schedule, and submit online payments. Two controllers handle all functionality:

| Controller | Lines | Responsibility |
|---|---|---|
| `ParentsController.php` | ~1,450 | Main portal — grades, billing, ledger, payments, photo |
| `ParentServerEventController.php` | ~200 | Server-sent events — notifications, tap attendance |

The portal's session-based design is central to several findings. A critical design flaw was identified during login flow analysis: **both students (type=7) and parents (type=9) set the same `Session::put('studentInfo', ...)` key at login**, meaning any student with an active session can call parent-only data endpoints that rely solely on that session key.

---

## 2. Middleware Analysis

### `AuthenticateParent` (alias `isParent`)
```php
// app/Http/Middleware/AuthenticateParent.php
public function handle($request, Closure $next)
{
    if(auth()->user()->type == 9){
        return $next($request);
    }
    return back();
}
```

**Notable difference from all other portal middleware:** `isParent` does **NOT** check `Session::get('currentPortal')`. Every other portal middleware (Teacher, Registrar, CT, CP, Dean) includes a `currentPortal` session bypass. Parent does not — so the portal-switching vulnerability does not apply here.

**However:** The `isParent` check is irrelevant for the most sensitive routes because they are defined **outside** the `['auth', 'isParent']` group entirely.

### Route Group Structure
```php
// routes/web.php

// OUTSIDE ALL MIDDLEWARE — lines 249–293
Route::get('/testingesayloading', ...);
Route::post('/parent/update/studpic', ...);
Route::get('/parent/enrollment/record', ...);
Route::get('/parent/enrollment/record/grades', ...);
Route::get('/parent/enrollment/record/attendance', ...);
Route::get('/parent/enrollment/record/subjects', ...);
Route::get('/parent/enrollment/billing', ...);
Route::get('/parent/enrollment/ledger', ...);
Route::get('/parent/enrollment/previousbalance', ...);

// PROTECTED — lines 263–291
Route::middleware(['auth', 'isParent'])->group(function () {
    Route::get('/parentsPortalDashboard', ...);
    Route::get('/parentsPortalGrades', ...);
    Route::get('/parentsPortalBilling', ...);
    // ... notification and calendar routes
});

// OUTSIDE ALL MIDDLEWARE AGAIN — lines 292–293
Route::get('/getremBill', ...);
Route::post('/parentEnterAmount', ...);
Route::get('/parent/onlinepayment', ...);
```

**10 routes are outside all middleware.** The protected group only covers dashboard views and notifications.

### Session Key Collision (Critical Design Flaw)
```php
// app/Http/Controllers/Auth/LoginController.php

// For student login (type=7):
$studentInfo = DB::table('studinfo')->where('sid', str_replace("S","", auth()->user()->email))->first();
Session::put('studentInfo', $studentInfo);  // LINE 451

// For parent login (type=9):
$studendinfo = DB::table('studinfo')->where('sid', str_replace("P","", auth()->user()->email))->first();
Session::put('studentInfo', $studendinfo);  // LINE 468
```

Both user types write to the same `studentInfo` session key. All unprotected parent endpoints rely exclusively on `Session::get('studentInfo')` for authorization — meaning any logged-in student can call parent data endpoints without triggering the `isParent` middleware.

---

## 3. Route Mapping Table

| Method | Route | Controller@Method | Middleware | Risk |
|---|---|---|---|---|
| GET | `/parent/enrollment/record` | `ParentsController@enrollment_record` | **None** | HIGH |
| GET | `/parent/enrollment/record/grades` | `ParentsController@enrollment_grades` | **None** | HIGH |
| GET | `/parent/enrollment/record/attendance` | `ParentsController@enrollment_attendance` | **None** | HIGH |
| GET | `/parent/enrollment/record/subjects` | `ParentsController@enrollment_subjects` | **None** | HIGH |
| GET | `/parent/enrollment/billing` | `ParentsController@student_billing` | **None** | HIGH |
| GET | `/parent/enrollment/ledger` | `ParentsController@student_student_ledger` | **None** | HIGH |
| GET | `/parent/enrollment/previousbalance` | `ParentsController@previous_balance` | **None** | HIGH |
| POST | `/parentEnterAmount` | `ParentsController@parentEnterAmount` | **None** | HIGH |
| GET | `/getremBill` | `ParentsController@getremBill` | **None** | MEDIUM |
| POST | `/parent/update/studpic` | `ParentsController@updateStudPic` | **None** | MEDIUM |
| GET | `/parent/onlinepayment` | `ParentsController@onlinepayment` | **None** | LOW |
| GET | `/testingesayloading` | `ParentsController@testing` | **None** | LOW |
| GET | `/parentsPortalDashboard` | `ParentsController@loaddDashboard` | `auth, isParent` | ✅ |
| GET | `/parentsPortalGrades` | `ParentsController@loadGrades` | `auth, isParent` | ✅ |
| GET | `/parentsPortalBilling` | `ParentsController@loadBilling` | `auth, isParent` | ✅ |

---

## 4. Security Findings

### P-01 — HIGH — Student Portal Users Can Access Parent Data Endpoints
**Files:** `routes/web.php` (lines 253–259), `LoginController.php` (lines 451, 468)  
**Routes:** All 7 `/parent/enrollment/*` routes — No middleware  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5**

**Root cause — session key collision:**
```php
// STUDENT login sets:
Session::put('studentInfo', $studentData);   // same key as parent

// PARENT login sets:
Session::put('studentInfo', $studendInfo);   // same key as student
```

**Consequence:** A logged-in student (type=7) calling any `/parent/enrollment/*` endpoint:
1. Is NOT blocked — no `auth` or `isParent` middleware on these routes
2. `Session::get('studentInfo')` returns their own student record
3. The method executes as if it were a parent request
4. Student receives their own data through the parent endpoint — bypassing the `isParent` access control layer

While this yields the student's OWN data (not another student's), it demonstrates a complete bypass of the intended role separation. Any feature behavior differences between student and parent portal endpoints are also bypassed.

---

### P-02 — HIGH — Unauthenticated Online Payment Submission
**File:** `ParentsController.php` (line 1000)  
**Route:** `POST /parentEnterAmount` (No middleware)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **7.5**

```php
public function parentEnterAmount(Request $request){
    $studendinfo = Session::get('studentInfo');  // session only — no auth middleware
    // ...
    $paymentId = DB::table('onlinepayments')->insertGetID([
        'amount'      => str_replace(',','',$request->get('amount')),  // ATTACKER-CONTROLLED
        'refNum'      => $request->get('refNum'),
        'paymentType' => $request->get('paymentType'),
        'TransDate'   => $request->get('transDate'),
        // ...
    ]);
    // Also inserts into onlinepaymentdetails per payment line item
}
```

Any session-bearing user (student, teacher, cashier with `studentInfo` in session) can call this endpoint. The `amount` field:
- Has no minimum value validation → `amount=0` or `amount=-5000` accepted
- Has no maximum cap → `amount=99999999` inserted
- Finance staff review and approve entries from `onlinepayments` — fraudulent records create noise and workload

---

### P-03 — MEDIUM — Negative and Zero Amounts Accepted in Payment Submission
**File:** `ParentsController.php` (line 1155)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:M/A:N` = **5.3**

```php
'amount' => str_replace(',', '', $request->get('amount'))
```

The validator only checks `required` — it does not enforce `numeric`, `min:1`, or `max`. A negative amount (`-10000`) passes validation and inserts into `onlinepayments.amount`. If finance staff approve this record, it creates a negative payment entry in the ledger — effectively a fraudulent credit to a student's balance.

---

### P-04 — MEDIUM — Receipt Image Stored with Unvalidated Extension
**File:** `ParentsController.php` (line 1130)  
**Route:** `POST /parentEnterAmount`  
**CVSS:** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` = **4.2**

```php
$extension = $file->getClientOriginalExtension();  // CLIENT-CONTROLLED

// File saved to public/onlinepayments/<sid>/<sid>-payment-<time>.<extension>
$img = Image::make($file->path());  // Validates as real image
$img->save($destinationPath);       // Saves with client extension
```

- `getClientOriginalExtension()` reads from the attacker-supplied filename
- Intervention Image (`Image::make()`) validates the file is a real image — prevents PHP web shell execution
- **BUT:** Saving with `.html`, `.svg`, or `.htm` extension creates a web-accessible file under the student's payment folder (`public/onlinepayments/<sid>/`) that serves attacker-controlled markup
- MIME-sniffing browsers may execute embedded JavaScript in an SVG receipt upload

**Mitigating factor:** Intervention Image re-encodes the file, stripping non-image content from most formats. Risk is LOW for PHP execution, MEDIUM for XSS via SVG if the server serves it with `Content-Type: image/svg+xml`.

---

### P-05 — LOW — Testing Endpoint in Production Exposes Section Data
**Route:** `GET /testingesayloading` (No middleware)  
**CVSS:** 3.1

```php
public function testing(){
    $sections = SPP_Section::with('rooms')->get();
    return $sections;  // Returns ALL sections with room data
}
```

A development probe route left in production. Returns the full list of school sections and their assigned rooms without authentication.

---

### P-06 — LOW — Photo Update Outside `isParent` Middleware
**Route:** `POST /parent/update/studpic` (No middleware)  
**CVSS:** 2.1

Any session holder with `studentInfo` can update the student profile picture (hardcoded `.png` extension — no RCE risk). The file path is derived from the session's `sid`, not a request parameter — so cross-student IDOR is not possible.

---

### P-07 — INFO — `isParent` Middleware Missing `currentPortal` Check
Unlike all other portal middleware, `AuthenticateParent` does not include a `Session::get('currentPortal')` check. This is actually **safer** than other portals (no portal-switching bypass), but the inconsistency is worth noting for maintenance.

---

## 5. Backend Bugs

### BUG-P-01 — `loadGrades()` Has Unreachable Code After Return
```php
public function loadGrades(){
    return view('parentsportal.pages.enrollment_report');  // returns here

    if(Session::get('enrollmentstatus')) {   // UNREACHABLE — dead code
        $studendinfo = Session::get('studentInfo');
        // ...
    }
```
The actual grade-loading logic (with session check and grade generation) is unreachable — all visitors always get the empty `enrollment_report` view regardless of enrollment status.

### BUG-P-02 — `enrollment_grades()` Returns Boolean `false` on Missing Session
```php
public function enrollment_grades(Request $request){
    if(!isset($studendinfo->id)){
        return false;  // Non-JSON response on error
    }
```
Frontend AJAX callers receive `false` as a response — not a JSON error object. This can break frontend error handling that expects a JSON structure.

### BUG-P-03 — `enrollment_record()` Has Inconsistent Session Guard
```php
public function enrollment_record(){
    $studendinfo = Session::get('studentInfo');
    if(!isset($studendinfo->id)){
        Auth::logout();  // Logs out the user
        Session::flush();
        return redirect('/login');
    }
```
This method calls `Auth::logout()` on missing session — but since the route has no `auth` middleware, `auth()->user()` may already be null, making `Auth::logout()` a no-op that hides the actual state. Other methods in the same route group simply `return false` — no consistent error handling pattern.

---

## 6. Fix Recommendations

| Finding | Priority | Fix |
|---|---|---|
| P-01 (7 routes outside middleware) | **IMMEDIATE** | Move all 7 `/parent/enrollment/*` routes inside `['auth', 'isParent']` group |
| P-02 (`/parentEnterAmount` no middleware) | **IMMEDIATE** | Move inside `['auth', 'isParent']` group |
| P-03 (negative amounts) | High | Add validator rule: `'amount' => ['required', 'numeric', 'min:1']` |
| P-04 (unvalidated extension) | Medium | Hardcode extension to `jpg` from Intervention Image output format |
| P-05 (testing route) | Medium | Remove `GET /testingesayloading` route entirely |
| P-06 (studpic no middleware) | Low | Move inside `['auth', 'isParent']` group |
| BUG-P-01 (dead code in loadGrades) | Medium | Remove the dead `return` that precedes the grade logic |
| BUG-P-02 (false return) | Low | Return `response()->json(['status'=>0,'message'=>'Session expired'])` |

---

*End of Parent Portal Code Review*
