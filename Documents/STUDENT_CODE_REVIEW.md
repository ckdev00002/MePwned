# Student Portal — Security Code Review
**Date:** June 3, 2026  
**Reviewer:** Internal Red Team  
**Scope:** `app/Http/Controllers/StudentControllers/` (8 controllers) + `routes/web.php` lines 100–260, 7181–7195  
**Status:** 100% Complete — all 8 controllers reviewed line-by-line

---

## Table of Contents
1. [Scope & Methodology](#1-scope--methodology)
2. [Middleware Analysis](#2-middleware-analysis)
3. [Route Mapping Table](#3-route-mapping-table)
4. [Security Findings](#4-security-findings)
5. [Backend Bugs](#5-backend-bugs)
6. [Frontend Bugs](#6-frontend-bugs)
7. [Fix Recommendations](#7-fix-recommendations)

---

## 1. Scope & Methodology

### Controllers Reviewed
| File | Methods | Notes |
|---|---|---|
| `StudentControllers/StudentController.php` | ~30 | Main portal hub — grades, billing, profile, pre-enrollment |
| `StudentControllers/EnrollmentInformation.php` | ~20 | Financial data, schedule, photo upload, payment upload |
| `StudentControllers/BillingInformationController.php` | ~10 | Ledger, transaction history, financial history |
| `StudentControllers/ScholarshipController.php` | 6 | Scholarship apply, upload requirement, delete |
| `StudentControllers/StudentBehaviorController.php` | 2 | Student view own behavior records |
| `StudentControllers/StudentGradeEvaluation.php` | 1 | College grade evaluation view |
| `StudentControllers/StudentSeverEventController.php` | 5 | Server-sent events (SSE) for attendance/tap |
| `StudentControllers/StudentInformation.php` | 2 | Admin-side student info (not student-facing) |

### Approach
- Full line-by-line review of all 8 controllers
- Cross-referenced every method against `routes/web.php` for middleware
- Checked `app/Http/Middleware/AuthenticateStudent.php` for student auth logic
- Traced data flow from HTTP input → DB query for every user-controlled parameter

---

## 2. Middleware Analysis

### `AuthenticateStudent` (alias `isStudent`)
```php
// app/Http/Middleware/AuthenticateStudent.php
public function handle($request, Closure $next)
{
    if(auth()->user()->type == 7){
        return $next($request);
    }
    return back();
}
```
- **Student = `type == 7` only** — no bypass via `currentPortal` session (unlike Teacher)
- Strict single-type check — correct

### Route Middleware Groups (Student Portal)
| Group | Routes (approx.) | Notes |
|---|---|---|
| **No middleware** | `GET /api/mobile/api_student_ledger_v2`, `GET /api/mobile/api_class_schedule_v2`, `GET /api/mobile/api_reportcard_v2`, `GET /student/submit/form`, `GET /student/view/surveyForm` | CRITICAL: fully unauthenticated |
| **`['cors']` only** | `POST /student/notify_individual_student` | CORS only ≠ auth. Unauthenticated |
| **`['auth']`** | `/current/billingassesment`, `/current/schedule`, `/current/enrollment`, `/payment/upload`, `/student/ledger`, scholarship routes | Any authenticated user (teacher, admin, cashier, etc.) |
| **`['auth', 'isStudent']`** | Main portal pages — grades, billing, preenrollment, profile | Correct protection |

---

## 3. Route Mapping Table

| Method | Route | Controller@Method | Middleware | Risk |
|---|---|---|---|---|
| GET | `/api/mobile/api_student_ledger_v2` | `BillingInformationController@getStudentLedger` | **None** | CRITICAL |
| GET | `/api/mobile/api_class_schedule_v2` | `EnrollmentInformation@class_schedule` | **None** | HIGH |
| GET | `/api/mobile/api_reportcard_v2` | `EnrollmentInformation@enrollment_reportcard` | **None** | HIGH |
| POST | `/student/notify_individual_student` | `StudentController@notify_individual_student` | `cors` only | CRITICAL |
| GET | `/current/billingassesment` | `EnrollmentInformation@billingassesment` | `auth` | MEDIUM |
| GET | `/current/schedule` | `EnrollmentInformation@schedule` | `auth` | MEDIUM |
| GET | `/current/enrollment` | `EnrollmentInformation@enrollment` | `auth` | MEDIUM |
| POST | `/student/enrollment/record/profile/update/photo` | `EnrollmentInformation@upload_photo` | `auth` | MEDIUM |
| POST | `/payment/upload` | `EnrollmentInformation@send_payment` | `auth` | MEDIUM |
| GET | `/student/ledger` | `BillingInformationController@getStudentLedger` | `auth` | MEDIUM |
| POST | `/uploadrequirement` | `ScholarshipController@uploadrequirement` | `auth` | CRITICAL |
| POST | `/student/delete/scholarship` | `ScholarshipController@delscholarship` | `auth` | HIGH |
| POST | `/student/scholarship/saveScholarship` | `ScholarshipController@saveScholarship` | `auth` | MEDIUM |
| GET | `/student/submit/form` | `StudentController@submitSurvey` | **None** | MEDIUM |
| GET | `/student/view/surveyForm` | `StudentController@surveyForm` | **None** | LOW |
| GET | `/studentgrades` | `StudentController@loadGrades` | `auth, isStudent` | OK |
| POST | `/student/preenrollment/submit` | `StudentController@student_preenrollment_submit` | `auth, isStudent` | HIGH |
| GET | `/homeevent/{id}` | `StudentSeverEventController@homeevent` | `auth, isStudent` | LOW |
| GET | `/tapstate/{id}` | `StudentSeverEventController@tapstate` | `auth, isStudent` | LOW |
| GET | `/subjectattendanceevent/{id}/{sectionid}/{blockid}` | `StudentSeverEventController@subjectattendanceevent` | `auth, isStudent` | LOW |

---

## 4. Security Findings

### ST-01 — CRITICAL — RCE via Unrestricted PHP File Upload (Scholarship)
**File:** `app/Http/Controllers/StudentControllers/ScholarshipController.php` (lines ~240–260)  
**Route:** `POST /uploadrequirement` (`['auth']` middleware only)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` = **9.9**

**Vulnerable Code:**
```php
public function uploadrequirement(Request $request)
{
    $file = $request->file('file');

    $newFileName = time() . '.' . $file->getClientOriginalExtension(); // ATTACKER-CONTROLLED
    $destinationPath = public_path('scholarship/'); // Web-accessible directory
    $file->move($destinationPath, $newFileName);    // No MIME check, no extension whitelist
    return $newFileName;
}
```

**Attack Path:**
1. Any authenticated user (not just students — route is under `['auth']` only) uploads `evil.php` as the `file` parameter
2. `getClientOriginalExtension()` returns `php` — attacker-controlled
3. File is saved to `public/scholarship/<timestamp>.php` — **web-accessible**
4. Attacker navigates to `http://<app>/scholarship/<timestamp>.php` — **PHP executes**

**Impact:** Full server compromise, database access, internal network pivot. Identical pattern to PoC-9 in SUPERADMIN_POC.md.

---

### ST-02 — CRITICAL — Unauthenticated SMS Injection via tapbunker Queue
**File:** `app/Http/Controllers/StudentControllers/StudentController.php` (line 33)  
**Route:** `POST /student/notify_individual_student` (`['cors']` only — NO authentication)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **7.5** (but DoS/financial damage elevates practical risk to CRITICAL)

**Vulnerable Code:**
```php
public function notify_individual_student(Request $request){
    $message = "LDCU: Hello! You can now proceed with enrollment...";

    $inserted = DB::table('tapbunker')->insert([
        'smsstatus' => 1,
        'message'   => $message,           // Hardcoded — not user-controlled
        'receiver'  => $request->get('phone'), // ATTACKER-CONTROLLED — any phone number
        'createddatetime' => now('Asia/Manila')
    ]);
    ...
```

**Attack Path:**
1. Any unauthenticated attacker sends `POST /student/notify_individual_student` with `phone=<victim_number>`
2. The record is inserted into `tapbunker` with `smsstatus=1` (queued for sending)
3. The SMS daemon processes the queue and sends an SMS to the attacker-supplied number
4. Repeating this floods any phone number with SMS, depleting the school's SMS credits

**Note:** The `['cors']` middleware only adds `Access-Control-Allow-Origin: *` headers — it performs **zero authentication**. The comment in the route file ("Added by clyde") suggests this was a development shortcut left in production.

---

### ST-03 — HIGH — Unauthenticated IDOR: Complete Student Financial Records
**File:** `app/Http/Controllers/StudentControllers/BillingInformationController.php` (line ~201)  
**Route:** `GET /api/mobile/api_student_ledger_v2` (No middleware)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**

**Vulnerable Code:**
```php
public function getStudentLedger(Request $request, $id = null)
{
    if ($id === null) {
        $id = $request->input('studid'); // Accepts studid directly from request — no auth required
        // auth()->check() path is never reached because studid was just set above
        if ($id === null && auth()->check()) { ... }
    }
    // Fetches complete financial data for $id — no ownership verification
    $student = DB::table('studinfo as si')...->where('si.id', $id)->first();
    ...
    return response()->json(...$financialData);
}
```

**Comment in web.php confirms intent:**
```php
// Public mobile API — no session auth required; studid passed as query param
Route::get('/api/mobile/api_student_ledger_v2', ...);
```

**Impact:** Any person on the internet (no account needed) can enumerate `studid=1,2,3,...` and extract the full financial ledger (balances, payments, billing items, program, photo URL) for every student.

**Same Pattern:** `GET /api/mobile/api_class_schedule_v2?studid=X` and `GET /api/mobile/api_reportcard_v2?studid=X&syid=X` share the identical unauthenticated `studid` input pattern.

---

### ST-04 — HIGH — Unauthenticated IDOR: Grades and Class Schedule
**File:** `app/Http/Controllers/StudentControllers/EnrollmentInformation.php`  
**Routes:** `GET /api/mobile/api_class_schedule_v2`, `GET /api/mobile/api_reportcard_v2` (No middleware)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**

```php
// class_schedule() — line 1109
$studid = $request->input('studid');
if ($studid === null && auth()->check()) { ... } // Only falls back to auth if studid not given
// Uses $studid to query enrollments, class schedules, etc. with no ownership check

// enrollment_reportcard() — line 1727
$studid = $request->input('studid');
if ($studid === null && auth()->check()) { ... }
// Returns full grade report card including all subjects and final grades
```

**Impact:** Grades and schedules for any student accessible by anyone. FERPA/data privacy violation.

---

### ST-05 — HIGH — Cleartext Password Stored in Audit Log Table
**File:** `app/Http/Controllers/StudentControllers/StudentController.php` (line ~1494)  
**Route:** `POST /student/preenrollment/submit` (`['auth', 'isStudent']`)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5**

**Vulnerable Code:**
```php
public function student_preenrollment_submit(Request $request){
    ...
    DB::enableQueryLog();
    DB::table('studinfo')->where('id',$studid)->take(1)->update([...]);
    DB::disableQueryLog();
    $logs = json_encode(DB::getQueryLog()); // Raw SQL with all bound parameters

    DB::table('updatelogs')->insert([
        'type'            => 1,
        'sql'             => $logs . $request->get('password'), // PASSWORD CONCATENATED INTO LOG
        'createdby'       => auth()->user()->id,
        'createddatetime' => \Carbon\Carbon::now('Asia/Manila')
    ]);
}
```

**Impact:** Any `password` parameter submitted with the pre-enrollment form is stored in plaintext in `updatelogs.sql`. Anyone with read access to that table (including future SQL injection attackers) obtains plaintext user passwords.

---

### ST-06 — HIGH — IDOR: Unauthorized Scholarship Application Deletion
**File:** `app/Http/Controllers/StudentControllers/ScholarshipController.php` (line ~75)  
**Route:** `POST /student/delete/scholarship` (`['auth']` only)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **6.5**

**Vulnerable Code:**
```php
public function delscholarship(Request $request)
{
    $id = $request->get('id'); // Attacker-supplied scholarship ID

    DB::table('scholarship_applicants')
        ->where('id', $id)         // No ownership check — no ->where('studid', $currentStudent)
        ->update(['deleted' => 1]);

    return 1;
}
```

**Impact:** Any authenticated user can soft-delete any scholarship application from any student. A malicious student could delete competitors' scholarship applications, potentially affecting financial aid decisions.

---

### ST-07 — MEDIUM — Privilege Confusion: Core Student Routes Under `['auth']` Only
**Routes Affected:** Lines 113–150 of `web.php` (full `['auth']`-only block)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` = **5.4**

**Affected Routes:**
```
GET /current/billingassesment  → EnrollmentInformation@billingassesment
GET /current/schedule          → EnrollmentInformation@schedule
GET /current/enrollment        → EnrollmentInformation@enrollment
GET /student/ledger            → BillingInformationController@getStudentLedger
GET /student/home/financial-history → BillingInformationController@getHomeFinancialHistory
GET /student/transaction-logs  → BillingInformationController@getTransactionLogs
GET /student/enrollment/record/profile/info → EnrollmentInformation@enrollment_student_information
POST /student/enrollment/record/profile/update/photo → EnrollmentInformation@upload_photo
POST /payment/upload           → EnrollmentInformation@send_payment
```

These routes are accessible by any authenticated user (type 1 = teacher, type 3 = registrar, type 4 = finance, type 5 = admin, etc.). The controller logic uses `auth()->user()->email` pattern matching to derive `studid`:

```php
if (auth()->user()->type == 9) {
    $studid = DB::table('studinfo')->where('sid', str_replace('P', '', auth()->user()->email))->first()->id;
} else {
    // A teacher with email 'S001@school.edu' would reach this branch
    $studid = DB::table('studinfo')->where('sid', str_replace('S', '', auth()->user()->email))->first()->id;
}
```

A teacher whose email begins with `S` (e.g., `Santos@school.edu` → `SID = antos@school.edu`) would fail the lookup and cause a 500. But a carefully crafted account with the right email format could potentially access financial data.

---

### ST-08 — MEDIUM — Missing Authentication on Survey Submission Routes
**File:** `app/Http/Controllers/StudentControllers/StudentController.php`  
**Routes:** `GET /student/submit/form`, `GET /student/view/surveyForm` (No middleware at all)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = **6.5**

```php
// web.php — OUTSIDE all middleware groups
Route::get('/student/submit/form', 'StudentControllers\StudentController@submitSurvey');
Route::get('/student/view/surveyForm', 'StudentControllers\StudentController@surveyForm');
```

`submitSurvey()` calls `auth()->user()->id` immediately — without authentication, this returns `null` and the subsequent `->first()->id` throws a PHP 500. This reveals debug/error information to unauthenticated users and represents intent failure (forgot to add middleware). The survey also updates `studinfo` and inserts into `leasf` — if authentication were ever relaxed, this becomes a data corruption vector.

---

### ST-09 — LOW — Profile Photo: No Content Validation on Base64 Payload
**File:** `app/Http/Controllers/StudentControllers/EnrollmentInformation.php` (line ~2640)  
**Route:** `POST /student/enrollment/record/profile/update/photo` (`['auth']`)  
**CVSS:** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N` = **3.1**

```php
$data = $request->image;
list($type, $data) = explode(';', $data);   // $type from attacker-controlled data URI header
list(, $data)      = explode(',', $data);
$data              = base64_decode($data);
$extension         = 'png';                  // Extension is hardcoded — mitigates PHP execution
file_put_contents($destinationPath, $data); // Raw binary written to disk — no content validation
```

The `$type` variable (e.g., `data:image/png`) is attacker-controlled. The actual decoded content is never validated against image magic bytes. However, since the extension is hardcoded to `.png`, PHP execution is prevented in a standard configuration. The risk is primarily theoretical (misconfigured web server, ImageMagick exploit via crafted PNG).

---

### ST-10 — LOW — Duplicate Route Definitions Causing Ambiguous Behavior
**File:** `routes/web.php` (lines 205–211 and 222–228)  
**CVSS:** N/A — Configuration error

The same pre-enrollment routes are registered twice within the same `['auth', 'isStudent']` middleware group:
```php
// First registration: lines 205-211
Route::get('/student/preenrollment/personalinfo', 'StudentControllers\StudentController@personalinfo');
Route::get('/student/preenrollment/infoupdate', ...);
Route::get('/student/preenrollment/submitinfo', ...);
// ... etc.

// Second registration: lines 222-228 (identical)
Route::get('/student/preenrollment/personalinfo', 'StudentControllers\StudentController@personalinfo');
// ... etc.
```

Laravel resolves duplicate routes by using the **first** registration, silently ignoring the second. This creates maintenance confusion and could cause unexpected behavior if the two definitions diverge.

---

## 5. Backend Bugs

### BUG-ST-01 — Dead Code After Early Return in `loadGrades()`
**File:** `StudentController.php` (line ~258)
```php
public function loadGrades(){
    return view('studentPortal.pages.enrollment_report'); // RETURNS HERE

    // UNREACHABLE — entire block below never executes:
    $studinfo = DB::table('studinfo')...->first();
    if($studinfo->acadprogid == 6){
        return view('studentPortal.pages.college.collegestudentgrading');
    }else{
        return view('studentPortal.pages.enrollment_report');
    }
}
```
All students see the basic enrollment_report view regardless of academic program. College students (`acadprogid=6`) never see their college-specific grading page.

---

### BUG-ST-02 — `$type` Undefined Variable in `teacherevaluation()`
**File:** `StudentController.php` (line ~383)
```php
if(!isset($check_enrollment->id)){
    if($type == 'all'){          // $type is NEVER DEFINED — always throws notice/warning
        return view(...)->with('schedule',array());
    }
}
```
`$type` is referenced but never assigned in `teacherevaluation()`. This causes a PHP notice (or E_NOTICE) and always evaluates to falsy, silently bypassing the branch.

---

### BUG-ST-03 — `student_preenrollment_submit()` Returns No Response
**File:** `StudentController.php` (line ~1530)

The method performs all database operations (update, insert to `updatelogs`, insert to `earlybirds`, insert to `student_pregistration`) but has no explicit `return` statement at the end. Laravel returns an empty 200 response. If the front-end checks for a specific return value, this causes silent failure.

---

### BUG-ST-04 — `tapstate($studentInfo)` Route Parameter Collision with SSE
**File:** `StudentSeverEventController.php` + `routes/web.php` line 180

The route is:
```php
Route::get('/tapstate/{id}', 'StudentSeverEventController@tapstate');
```
But the method signature is:
```php
public function tapstate($studentInfo){
```
The parameter is named `$studentInfo` but bound to `{id}`. This is just a naming inconsistency, but `$studentInfo` is passed directly to `AttendanceReport::todaySchoolAttendance($studentInfo)` — meaning any authenticated student can check another student's tap/attendance data by guessing their `studid`.

---

### BUG-ST-05 — `homeevent({id})` Parameter Not Used
**File:** `StudentSeverEventController.php` (line 18)

Route: `GET /homeevent/{id}` — but `homeevent($id)` never uses the `$id` parameter. It always uses `Session::get('studentInfo')`. The `{id}` segment is silently discarded. The route was likely designed to accept a student ID but the implementation ignores it.

---

## 6. Frontend Bugs

### FE-ST-01 — HTML Injection in SSE Responses (StudentSeverEventController)
**File:** `StudentSeverEventController.php`

The `homeevent()` and `subjectattendanceevent()` methods build HTML strings by concatenating raw database values:
```php
$datastring .= '<td width=20%>' . $item->subjcode . '</td>';  // subjcode not escaped
// ...
$datastring .= '<span>Starts in ' . $item->classstatus . '</span>'; // classstatus not escaped
```
If a subject code or class status field contains HTML/JS, it is injected directly into the DOM. Mitigated by the fact that these fields are set by admins, not students. Risk: stored XSS via admin-controlled data.

---

## 7. Fix Recommendations

| Finding | Priority | Fix |
|---|---|---|
| ST-01 (File Upload RCE) | **IMMEDIATE** | Validate MIME type against whitelist (`image/jpeg`,`image/png`,`application/pdf`). Check magic bytes. Store outside `public/`. Return signed URL. |
| ST-02 (SMS Injection) | **IMMEDIATE** | Add `['auth', 'isStudent']` middleware OR require admin role. Rate-limit by IP. |
| ST-03/ST-04 (Unauthenticated IDOR) | **IMMEDIATE** | Remove public mobile API routes or require a shared API token. Lock down `studid` to authenticated user only. |
| ST-05 (Password in Log) | **IMMEDIATE** | Remove `$request->get('password')` from the `updatelogs` insert entirely. |
| ST-06 (Scholarship IDOR) | High | Add `->where('studid', $studid)` to the `delscholarship` query. |
| ST-07 (Missing isStudent) | High | Move the `['auth']`-only student routes into the `['auth', 'isStudent']` group. |
| ST-08 (Survey no auth) | Medium | Add `['auth', 'isStudent']` to the survey routes. |
| BUG-ST-01 (Dead code) | Medium | Remove the early `return` or restructure the grade routing logic. |
| BUG-ST-03 (No return) | Low | Add `return response()->json(['status'=>1])` at end of `student_preenrollment_submit`. |
| ST-10 (Duplicate routes) | Low | Remove the second duplicate registration block (lines 222–228). |

---

*End of Student Portal Code Review*
