# Teacher Portal — Code Security Review
**Module:** Teacher Portal (`app/Http/Controllers/TeacherControllers/`)  
**Reviewer:** GitHub Copilot Security Analysis  
**Scope:** 100% controller coverage + route mapping + frontend Blade views  
**Date:** 2025

---

## Table of Contents
1. [Module Overview](#1-module-overview)
2. [Security Findings](#2-security-findings)
   - 2.1 T-01: Unauthenticated Dynamic Column Injection — `gradesdetail`
   - 2.2 T-02: Unauthenticated Dynamic Column Injection — `grades` Header
   - 2.3 T-03: Grade Workflow Manipulation Without Role Check
   - 2.4 T-04: Final Grade Submission Without Teacher Role Check
   - 2.5 T-05: Grade Reports Accessible Without Authentication
   - 2.6 T-06: Deportment Grade Status Update Without Authentication
   - 2.7 T-07: Grade Header Data Disclosure Without Authentication
   - 2.8 T-08: Teacher Evaluation Routes Without Authentication
   - 2.9 T-09: Cross-Teacher Attendance IDOR
   - 2.10 T-10: Virtual Classroom Assignment IDOR
   - 2.11 T-11: State-Changing Operations via HTTP GET
   - 2.12 T-12: Client-Supplied Filename in File Operations
   - 2.13 T-13: Mass Password Reset Without Role Check
   - 2.14 T-14: Plaintext Password Exposure via Credential Dump
   - 2.15 T-15: Behavior Report Manipulation Without Role Check
3. [Middleware Architecture Analysis](#3-middleware-architecture-analysis)
4. [Route Mapping — Security Annotations](#4-route-mapping--security-annotations)
5. [Controller Analysis](#5-controller-analysis)
6. [File Upload Review](#6-file-upload-review)
7. [Database Access Patterns](#7-database-access-patterns)
8. [Frontend Security Review](#8-frontend-security-review)
9. [Backend Bugs](#9-backend-bugs)
10. [Frontend JS Bugs](#10-frontend-js-bugs)
11. [Fix Recommendations](#11-fix-recommendations)

---

## 1. Module Overview

The Teacher portal is served by 32 PHP controllers in `app/Http/Controllers/TeacherControllers/`. The portal handles grade entry, attendance tracking, class scheduling, virtual classrooms, and student credential management.

**Primary middleware guard:** `isTeacher` (`AuthenticateTeacher.php`) — passes when `auth()->user()->type == 1` OR `Session::get('currentPortal') == 1`.

**Route file:** `routes/web.php` (7,659 lines). Teacher routes appear in multiple middleware groups:
- Lines 105–106: **NO MIDDLEWARE AT ALL** (top-level, outside all groups) — grade update endpoints
- Lines 291–330: **NO MIDDLEWARE** — grade reports and deportment status endpoints
- Lines 371–379: `['auth', 'isDefaultPass']` only — grade posting/approve/unpost
- Lines 580–585: **NO MIDDLEWARE** — teacher evaluation endpoints
- Line 656: **NO MIDDLEWARE** — grade header read endpoint
- Lines 669–676: `['auth', 'isDefaultPass']` only — final grade save/submit
- Lines 678+: `['auth', 'isTeacher', 'isDefaultPass']` — core teacher functions (attendance, scheduling)

---

## 2. Security Findings

### 2.1 T-01: Unauthenticated Dynamic Column Injection — `gradesdetail` (CRITICAL)

**File:** `app/Http/Controllers/TeacherControllers/TeacherGradingV2.php`, function `udpate_grade_detail()`, line 1143  
**Route:** `routes/web.php`, line 105  
**HTTP method:** GET (state-changing)

**Vulnerable code:**
```php
// routes/web.php line 105 — NO middleware group
Route::get('gradesdetail/update', 'TeacherControllers\TeacherGradingV2@udpate_grade_detail')
    ->name('udpate_grade_detial');
```
```php
// TeacherGradingV2.php line 1143
function udpate_grade_detail(Request $request)
{
    $data = $request->get('data');

    try {
        foreach ($data as $item) {
            DB::table('gradesdetail')
                ->where('id', $item['id'])
                ->where('studid', $item['studid'])
                ->take(1)
                ->update([
                    $item['field'] => $item['grade'],   // ← USER-CONTROLLED COLUMN NAME
                    'updatedby' => auth()->user()->id,  // ← inside try; fails for unauth
                    'updateddatetime' => \Carbon\Carbon::now('Asia/Manila')
                ]);
        }
```

**Impact:**
- The route has **zero middleware** — it is reachable by anyone who can send an HTTP request.
- For *authenticated* users (including students, type=7; parents, type=9; or any portal user), `auth()->user()->id` returns a valid integer. The UPDATE executes with a user-supplied column name.
- Any authenticated user can update **any column** in any `gradesdetail` row by supplying:
  - `data[0][id]` = target row ID
  - `data[0][studid]` = matching student ID (discoverable from grade reports — see T-05)
  - `data[0][field]` = target column name (`grade`, `qg`, `gdstatus`, `grade_1` ... `grade_4`, etc.)
  - `data[0][grade]` = desired value
- A student can raise their own failing grades to 100 or set `gdstatus=3` (approved) for their records.
- The column name injection is also an **unvalidated column reference** — passing a non-existent column causes a DB exception caught silently (returns `status:0`), but valid column names execute unrestricted updates.

**Attack scenario:** Student logged in with user type=7 sends `GET /gradesdetail/update?data[0][id]=1234&data[0][studid]=456&data[0][field]=grade&data[0][grade]=100` and receives `[{"status":1}]`.

**CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` — **7.1 HIGH** (Note: with no `auth` middleware enforced, any user who has ever logged in with a session cookie can exploit this; impact is data integrity of academic records.)

---

### 2.2 T-02: Unauthenticated Dynamic Column Injection — `grades` Header (CRITICAL)

**File:** `app/Http/Controllers/TeacherControllers/TeacherGradingV2.php`, function `udpate_grade_header()`, line 1185  
**Route:** `routes/web.php`, line 106  
**HTTP method:** GET (state-changing)

**Vulnerable code:**
```php
// routes/web.php line 106 — NO middleware group
Route::get('gradesheader/update', 'TeacherControllers\TeacherGradingV2@udpate_grade_header')
    ->name('udpate_grade_header');
```
```php
// TeacherGradingV2.php line 1185
function udpate_grade_header(Request $request)
{
    $data = $request->get('data');

    try {
        foreach ($data as $item) {
            if (isset($item['field'])) {
                DB::table('grades')
                    ->where('id', $item['id'])
                    ->where('syid', $item['syid'])
                    ->where('sectionid', $item['sectionid'])
                    ->where('subjid', $item['subjid'])
                    ->update([
                        $item['field'] => $item['grade'],    // ← USER-CONTROLLED COLUMN NAME
                        'updatedby' => auth()->user()->id,
                        'updateddatetime' => \Carbon\Carbon::now('Asia/Manila')
                    ]);
            }
        }
```

**Impact:** Identical class of vulnerability to T-01 but targeting the `grades` header table. An attacker can:
- Set `status` to `3` (approved/posted) for any grade header — bypassing the formal approval workflow.
- Set `submitted=1` to mark grades as submitted without going through `submit_grades()`.
- Set `coorapp=1` to mark coordinator approval.
- The constraints `syid`, `sectionid`, and `subjid` are all user-supplied, so they can be brute-forced or discovered from the unauthenticated grade report endpoints (T-05).

**CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` — **7.1 HIGH**

---

### 2.3 T-03: Grade Workflow Manipulation Without Role Check (CRITICAL)

**File:** `app/Http/Controllers/TeacherControllers/TeacherGradingV4.php`, lines 94, 421, 451, 481, 510, 517, 525, 532  
**Route:** `routes/web.php`, lines 371–379  
**Middleware:** `['auth', 'isDefaultPass']` — **missing `isTeacher` and `isPrincipal`**

**Vulnerable routes:**
```php
Route::middleware(['auth', 'isDefaultPass'])->group(function () {
    Route::get('posting/grade/post',     'TeacherControllers\TeacherGradingV4@post_student_grade');
    Route::get('posting/grade/unpost',   'TeacherControllers\TeacherGradingV4@unpost_student_grade');
    Route::get('posting/grade/pending',  'TeacherControllers\TeacherGradingV4@pending_student_grade');
    Route::get('posting/grade/approve',  'TeacherControllers\TeacherGradingV4@approve_student_grade');
    Route::get('posting/grade/subject/unpost',   'TeacherControllers\TeacherGradingV4@unpost_subject_grade');
    Route::get('posting/grade/subject/post',     'TeacherControllers\TeacherGradingV4@post_subject_grade');
    Route::get('posting/grade/subject/pending',  'TeacherControllers\TeacherGradingV4@pending_subject_grade');
    Route::get('posting/grade/subject/approve',  'TeacherControllers\TeacherGradingV4@approve_subject_grade');
});
```

**Vulnerable code — approve/pending subject grade (TeacherGradingV4.php line 525–540):**
```php
public static function pending_subject_grade(Request $request)
{
    $teacherid = $request->get('teacherid');  // user-supplied, not verified
    $gdid = $request->get('gdid');
    return IndividualGrading::pending_subject_grade($gdid);  // teacherid IGNORED
}

public static function approve_subject_grade(Request $request)
{
    $teacherid = $request->get('teacherid');  // user-supplied, not verified
    $gdid = $request->get('gdid');
    return IndividualGrading::approve_subject_grade($gdid);  // teacherid IGNORED
}
```

**Impact:**
- Any authenticated user who has changed their default password from `123456` can reach these endpoints.
- This includes students, parents, cashiers, registrars, and any portal user type.
- A student can approve their own or anyone else's grade record by calling `GET /posting/grade/subject/approve?gdid=<target_gdid>`.
- The `teacherid` parameter is accepted from the request but the model method ignores it — the system performs no verification that the caller is the assigned teacher.
- The grade state machine (pending → submitted → posted → approved) can be bypassed in any direction.

**CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` — **7.1 HIGH**

---

### 2.4 T-04: Final Grade Submission Without Teacher Role Check (HIGH)

**File:** `app/Http/Controllers/TeacherControllers/TeacherFinalGrade.php`, lines 11, 828  
**Route:** `routes/web.php`, lines 669–676  
**Middleware:** `['auth', 'isDefaultPass']` — **missing `isTeacher`**

**Vulnerable routes:**
```php
Route::middleware(['auth', 'isDefaultPass'])->group(function () {
    Route::get('teacher/submit/grades',         'TeacherControllers\TeacherFinalGrade@submit_grades');
    Route::get('teacher/finalgrades/savegrades','TeacherControllers\TeacherFinalGrade@save_grades');
    Route::get('teacher/get/teacheingload',     'TeacherControllers\TeacherFinalGrade@teachingload');
    Route::get('teacher/get/gradestatus',       'TeacherControllers\TeacherFinalGrade@gradestatus');
    Route::get('teacher/get/students',          'TeacherControllers\TeacherFinalGrade@enrolled_learners');
});
```

**Vulnerable code — `submit_grades` (TeacherFinalGrade.php line 11):**
```php
// No ownership check — takes all parameters from request
$id      = $request->get('id');
$syid    = $request->get('syid');
$sectionid = $request->get('sectionid');
$subjid  = $request->get('subjid');
// ...
DB::table('grades')->where('id', $id)->update(['status' => 0, 'submitted' => 1, ...]);
DB::table('gradesdetail')->where('headerid', $id)->update(['gdstatus' => 1]);
```

**Vulnerable code — `save_grades` (TeacherFinalGrade.php line 828):**
```php
$id      = $request->get('id');      // gradesdetail row ID
$studid  = $request->get('studid');
$qg      = $request->get('qg');      // quarterly grade value
// No check that auth()->user() owns this section/subject
DB::table('gradesdetail')->where('id', $id)->where('studid', $studid)->update(['qg' => $qg, ...]);
```

**Impact:**
- Any authenticated user who has changed their password can submit grades for any section and save arbitrary quarterly grades for any student.
- The route group is clearly labeled `teacher/finalgrades/*` but enforces no teacher role.

---

### 2.5 T-05: Grade Reports Accessible Without Authentication (HIGH)

**Route:** `routes/web.php`, lines 291–309 — **zero middleware**

**Unauthenticated routes:**
```
GET posting/grade/getstudents                        → TeacherGradingV4@get_student
GET grades/report/mastersheet                        → MasterSheetController@...
GET grades/report/mastersheet/excel                  → ...
GET grades/report/mastersheet/excel/composite        → ...
GET grades/report/mastersheet/gsa                    → ...
GET grades/report/mastersheet/lp                     → ...
GET grades/report/gradingsheet/finalcomposite        → ...
GET grades/report/gradingsheet/bysubject             → ...
GET grades/report/consolodiated                      → ...
GET grades/report/gradingsheet/gradestatus           → ...
GET grades/report/gradingsheet                       → ...
GET grades/report/gradelevel                         → ...
GET grades/report/studentawards                      → ...
GET grades/report/studentawards/certificate          → ...
GET posting/grade                                    → (grade posting view)
```

**Impact:**
- The mastersheet endpoint exposes the full grade roster for every section of a school year. No authentication is required — a direct browser request returns all student grades.
- Student award data and report cards are accessible to the public internet.
- These endpoints collectively represent a mass personal data breach (student names, grades, academic standing).

---

### 2.6 T-06: Deportment Grade Status Update Without Authentication (HIGH)

**File:** `app/Http/Controllers/PrincipalControllers/DeportmentStatus.php`  
**Route:** `routes/web.php`, lines 320–326 — **zero middleware**

```
GET posting/grade/update-grade-status  → DeportmentStatus@update_grade_status
GET posting/grade/get-deportment-details
GET posting/grade/get-student-list
GET posting/grade/get-student-status
GET posting/grade/filter-student-status
GET posting/grade/load-class-table
```

**Impact:** `update-grade-status` is a state-changing endpoint with no authentication. Anyone can modify deportment/character grade status records without being logged in, provided they know or enumerate the target record IDs.

---

### 2.7 T-07: Grade Header Data Disclosure Without Authentication (MEDIUM)

**File:** `app/Http/Controllers/TeacherControllers/TeacherGradingV2.php`, line 289  
**Route:** `routes/web.php`, line 656 — **no middleware**

```php
Route::get('get/grade/header', 'TeacherControllers\TeacherGradingV2@get_grade_header');
```

```php
public static function get_grade_header(Request $request)
{
    // All parameters accepted from request
    $grade_header = DB::table('grades')
        ->where('sectionid', $sectionid)
        ->where('levelid', $gradelevelid)
        ->where('quarter', $quarter)
        ->where('syid', $syid)
        ->where('deleted', 0)
        ->where('subjid', $subjectid)
        ->get();

    return $grade_header;  // Full grade header records returned
}
```

**Impact:** Any user (including unauthenticated) can retrieve grade header metadata (grade IDs, section IDs, status, submitted flag, approval timestamps) for any section by supplying valid parameter combinations. This data enables precise attacks against T-01 and T-02.

---

### 2.8 T-08: Teacher Evaluation Routes Without Authentication (MEDIUM)

**Route:** `routes/web.php`, lines 580–585 — **zero middleware**

```
GET /teacherevaluation/schedule      → TeacherEvaluations@teachr_schedule
GET /teacherevaluation/checkEvaluation → TeacherEvaluations@check_evaluation
```

**Impact:** Teacher evaluation schedules and evaluation status can be read without authentication. Exposes when teacher evaluations are occurring, which teachers are being evaluated, and whether evaluations are complete. Information leakage useful for targeted social engineering.

---

### 2.9 T-09: Cross-Teacher Attendance IDOR (MEDIUM)

**File:** `app/Http/Controllers/TeacherControllers/ClassAttendanceController.php`, line 1508  
**Route:** `routes/web.php`, line 694 — inside `['auth', 'isTeacher', 'isDefaultPass']`

**Vulnerable code:**
```php
public function submitattendance(Request $request)
{
    foreach($request->get('datavalues') as $dataval) {
        $checkifexists = DB::table('studattendance')
            ->where('studid', $dataval['studid'])  // user-supplied studid
            ->whereDate('tdate', $dataval['tdate'])
            ->where('deleted','0')
            ->first();
        // No check that teacher is assigned to this student's section
        DB::table('studattendance')
            ->where('id', $checkifexists->id)
            ->update(['present' => $presentval, 'absent' => $absentval, ...]);
    }
}
```

**Impact:** Any authenticated teacher can mark attendance (present/absent/late) for students in sections they are **not** assigned to. Teacher A can manipulate Teacher B's class attendance records, including fabricating absences for students. The only constraint is knowing a valid `studid` — student IDs are sequential integers.

---

### 2.10 T-10: Virtual Classroom Assignment IDOR (MEDIUM)

**File:** `app/Http/Controllers/TeacherControllers/VirtualClassroomController.php`

**Vulnerable code — `editclassassignment` (no line shown, class method):**
```php
public function editclassassignment(Request $request)
{
    DB::table('virtualclassroomattach')
        ->where('id', $request->get('assignmentid'))  // no ownership check
        ->update([
            'title'         => $request->get('assignmenttitle'),
            'instructions'  => $request->get('assignmentinstruction'),
            'perfectscore'  => $request->get('perfectscore'),
            'duefrom'       => ...,
            'dueto'         => ...,
        ]);
    return back();
}

public function deleteassignment(Request $request)
{
    DB::table('virtualclassroomattach')
        ->where('id', $request->get('assignmentid'))  // no ownership check
        ->update(['deleted' => '1']);
    return back();
}
```

**Impact:** Any authenticated teacher can edit or delete another teacher's virtual classroom assignment by supplying the target's numeric `assignmentid`. IDs are sequential integers and enumerable. This disrupts class continuity and can cause student grade loss if assignments are deleted.

---

### 2.11 T-11: State-Changing Operations via HTTP GET (LOW)

Multiple grade and attendance write operations are exposed as GET routes:

| Route | Operation |
|---|---|
| `GET /gradesdetail/update` | DB UPDATE on `gradesdetail` |
| `GET /gradesheader/update` | DB UPDATE on `grades` |
| `GET /classattendance/submit` | DB INSERT/UPDATE on `studattendance` |
| `GET /classattendance/updateattendance_v1` | DB UPDATE on `studattendance` |
| `GET /posting/grade/post` | DB UPDATE — grade status |
| `GET /posting/grade/approve` | DB UPDATE — grade approval |

**Impact:** Using GET for mutations bypasses the expectation that HTTP GET is safe and idempotent. While Laravel enforces CSRF tokens only on POST/PUT/DELETE, these GET routes accept cross-origin requests via `<img src>` or `<iframe src>` tags, enabling CSRF-equivalent attacks from malicious websites (since GET requests include credentials from same-origin cookies). Severity is LOW because modern browsers send cookies only for cross-origin GET when `SameSite` is not `Strict`, but Lax (Laravel default) allows top-level navigations.

---

### 2.12 T-12: Client-Supplied Filename in File Operations (LOW)

**File:** `app/Http/Controllers/TeacherControllers/VirtualClassroomController.php`

```php
$file->move($clouddestinationPath, $file->getClientOriginalName());  // ← client name
$renamedfile = rename(
    $clouddestinationPath.'/'.$file->getClientOriginalName(),
    $clouddestinationPath.'/'.auth()->user()->email.'-'.$file->getClientOriginalName()
);
```

**Context:** The `addfiles()` method validates MIME types via `$request->validate(['files.*' => 'mimes:jpeg,jpg,...'])`. However, `getClientOriginalName()` is client-controlled. On Windows, Symfony's `UploadedFile::move()` uses `basename()` internally, limiting path traversal. The `rename()` call uses the concatenated path directly, but the directory is already constrained to `$clouddestinationPath`. Risk is LOW on standard deployments.

The `extension` column is populated from `getClientOriginalExtension()` (also client-supplied) and stored in the database, but no server-side execution occurs from the stored extension.

---

### 2.13 T-13: Mass Password Reset Without Role Check (CRITICAL)

**File:** `app/Http/Controllers/TeacherControllers/TeacherStudentCredentials.php`, function `update_password()`, line 608  
**Route:** `routes/web.php`, line 6622 — `GET /teacher/student/generate/password`  
**Middleware:** `['auth']` only — **no `isTeacher`**

**Vulnerable code:**
```php
// routes/web.php line 6618
Route::middleware(['auth'])->group(function () {
    Route::get('/teacher/student/generate/password',
        'TeacherControllers\TeacherStudentCredentials@update_password');
    Route::get('/teacher/student/reset/all',
        'TeacherControllers\TeacherStudentCredentials@update_all_password');
    // ...
});
```
```php
// TeacherStudentCredentials.php line 608
public static function update_password(Request $request) {
    $userid = $request->get('id');        // ← ANY user ID — no ownership check
    $passwordtype = $request->get('passwordtype');

    if ($passwordtype == 3) {
        $data = self::generatepassword($userid);  // assigns a random password
    } else {
        DB::table('users')
            ->where('id', $userid)    // ← target user ID from request, no validation
            ->update([
                'password'   => Hash::make('123456'),
                'isDefault'  => 1
            ]);
    }
}
```

**Impact:**
- Any authenticated user (student, parent, cashier) can reset the password of **any user account** in the system — including admin, principal, and teacher accounts — to `123456`.
- Supplying an admin's `user.id` forces their account back to the default password, then the attacker can log in as that admin.
- `update_all_password` (line 13, route `/teacher/student/reset/all`) bulk-resets ALL students in any section to `123456` — also no role check. This is a mass account takeover / denial-of-access attack.
- No `auth()->user()` ownership check; the commented-out `'updatedby' => auth()->user()->id` confirms it was intentionally removed.

**CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` — **9.9 CRITICAL** (Scope changed — can compromise admin accounts)

---

### 2.14 T-14: Plaintext Password Exposure via Credential Dump (HIGH)

**File:** `app/Http/Controllers/TeacherControllers/TeacherStudentCredentials.php`, function `student_creadentials()`, line 470  
**Route:** `routes/web.php`, line 6621 — `GET /teacher/student/credential/list`  
**Middleware:** `['auth']` only — **no `isTeacher`**

**Vulnerable code:**
```php
// Line 470 — returned to any authenticated caller
$users = DB::table('users')
    ->whereIn('email', $student_email)
    ->select('email', 'passwordstr', 'id', 'isDefault')  // ← passwordstr = CLEARTEXT password
    ->where('deleted', 0)
    ->get();

$item->student_credentials = $student_creds;  // included in JSON response
$item->parent_credentials  = $parent_creds;
```

**Context:** `passwordstr` is a cleartext copy of the most recently generated password, stored by `generatepassword()` (line 694: `'passwordstr' => $random_string`). It is returned in the API response so that a teacher can hand the printed credential to the student. The route has no teacher role check, so any authenticated user can call it with any `sectionid` and `syid` to retrieve cleartext passwords for all students and parents in that section.

**Impact:**
- Mass exposure of student and parent portal credentials (username + cleartext password).
- Combined with T-13, an attacker can enumerate credentials, then use them to log in to all student/parent accounts and manipulate enrollment, grade viewing, and financial data from the student portal.
- RA 10173 (Data Privacy Act) violation — plaintext storage of passwords is a reportable personal data breach.

**CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` — **6.5 HIGH**

---

### 2.15 T-15: Behavior Report Manipulation Without Role Check (MEDIUM)

**File:** `app/Http/Controllers/TeacherControllers/ObservableBahaviorController.php`, lines 392–660  
**Route:** `routes/web.php`, lines 7304–7327 — inside `['auth']` only group  
**Middleware:** `['auth']` only — **no `isTeacher` or `isGuidance`**

**Vulnerable endpoints:**
```
GET  /guidance/reportTable       → Returns all behavior incident reports (all students)
GET  /guidance/reportTable2      → Same — scheduled notifications
GET  /guidance/reportresolve     → Returns all resolved reports
GET  /guidance/report/resolve    → resolveReport() — marks/resolves any incident by ID
POST /teacher/behavior/submitBehavior → Files a behavior report for any student
```

**Vulnerable code — `submitBehavior` (no ownership check):**
```php
public static function submitBehavior(Request $request) {
    DB::table('guidance_behavior')->insert([
        'studentid'         => $request->get('id'),     // any student ID
        'behavior'          => $request->get('behavior'),
        'card'              => $request->get('card'),
        'actionrecommended' => $request->get('action'),
        'createdby'         => auth()->user()->id
    ]);
}
```

**Vulnerable code — `resolveReport` (no ownership check):**
```php
public static function resolveReport(Request $request) {
    DB::table('guidance_behavior')
        ->where('id', $request->get('id'))    // any report ID
        ->update([
            'resolve' => $request->get('resolve'),  // dismiss with any value
            'remark'  => $request->get('remarks'),
        ]);
}
```

**Impact:**
- Any authenticated user (including a student) can file a false behavior/disciplinary report against any other student.
- Any authenticated user can resolve (dismiss) any incident report — a student could clear their own real disciplinary record.
- All behavior incident reports are readable without teacher role — exposes sensitive student behavioral PII to any logged-in user.

---

## 3. Middleware Architecture Analysis

### `AuthenticateTeacher.php`
```php
public function handle($request, Closure $next)
{
    if (auth()->user()->type == 1 || Session::get('currentPortal') == 1) {
        return $next($request);
    }
    return back();
}
```

**Weaknesses:**
1. `Session::get('currentPortal') == 1` — any session that has had `currentPortal` set to `1` at any point passes this check, even if the user's type has since changed.
2. `auth()->user()->type` — relies on the `type` field in the `users` table. If user type is changed without invalidating active sessions, the old session continues to pass.
3. This middleware is **not applied** to the routes at lines 105–106, 291–330, 371–379, 580–585, and 656 — see §4.

### `AuthenticateDefaultPass.php`
```php
if (Hash::check('123456', auth()->user()->password)) {
    return response()->view('resetpass');
}
```
- Acts as a gate, not an authorization check. Only blocks users whose password is still the default `123456`.
- Does NOT verify user role or teacher assignment.

---

## 4. Route Mapping — Security Annotations

| Route | Middleware | Risk |
|---|---|---|
| `GET gradesdetail/update` | **NONE** | CRITICAL (T-01) |
| `GET gradesheader/update` | **NONE** | CRITICAL (T-02) |
| `GET posting/grade/getstudents` | **NONE** | HIGH (T-05) |
| `GET grades/report/mastersheet*` | **NONE** | HIGH (T-05) |
| `GET grades/report/gradingsheet*` | **NONE** | HIGH (T-05) |
| `GET grades/report/studentawards*` | **NONE** | HIGH (T-05) |
| `GET posting/grade/update-grade-status` | **NONE** | HIGH (T-06) |
| `GET posting/grade/get-*` | **NONE** | HIGH (T-06) |
| `GET posting/grade` | **NONE** | MEDIUM |
| `GET /teacherevaluation/schedule` | **NONE** | MEDIUM (T-08) |
| `GET /teacherevaluation/checkEvaluation` | **NONE** | MEDIUM (T-08) |
| `GET get/grade/header` | **NONE** | MEDIUM (T-07) |
| `GET posting/grade/post` | `auth, isDefaultPass` | CRITICAL (T-03) |
| `GET posting/grade/approve` | `auth, isDefaultPass` | CRITICAL (T-03) |
| `GET posting/grade/unpost` | `auth, isDefaultPass` | CRITICAL (T-03) |
| `GET posting/grade/pending` | `auth, isDefaultPass` | CRITICAL (T-03) |
| `GET posting/grade/subject/*` | `auth, isDefaultPass` | CRITICAL (T-03) |
| `GET teacher/submit/grades` | `auth, isDefaultPass` | HIGH (T-04) |
| `GET teacher/finalgrades/savegrades` | `auth, isDefaultPass` | HIGH (T-04) |
| `GET teacher/get/teacheingload` | `auth, isDefaultPass` | HIGH (T-04) |
| `GET /classattendance/submit` | `auth, isTeacher, isDefaultPass` | MEDIUM (T-09) |
| `GET /classattendance/updateattendance_v1` | `auth, isTeacher, isDefaultPass` | MEDIUM (T-09) |
| `GET /teacher/student/generate/password` | `auth` only | CRITICAL (T-13) |
| `GET /teacher/student/reset/all` | `auth` only | CRITICAL (T-13) |
| `GET /teacher/student/credential/list` | `auth` only | HIGH (T-14) |
| `GET /teacher/student/credential/advisory` | `auth` only | LOW |
| `GET /teacher/student/generate/parentaccount` | `auth` only | MEDIUM |
| `GET /teacher/student/generate/studentaccount` | `auth` only | MEDIUM |
| `GET /guidance/reportTable` | `auth` only | MEDIUM (T-15) |
| `GET /guidance/report/resolve` | `auth` only | MEDIUM (T-15) |
| `POST /teacher/behavior/submitBehavior` | `auth` only | MEDIUM (T-15) |

---

## 5. Controller Analysis

### TeacherGradingV2.php
- **`udpate_grade_detail()`** (line 1143): Dynamic column injection — see T-01.
- **`udpate_grade_header()`** (line 1185): Dynamic column injection — see T-02.
- **`get_grade_header()`** (line 289): No auth gate — see T-07.
- **`showGrades()`** (line 1228): `DB::table('semester')->where('id', $semid)->first()->id` — null dereference if no matching semester (BUG-T-04).
- **Line 58:** `DB::table('teacher')->where('userid', auth()->user()->id)->first()->id` — crashes with `Trying to get property of non-object` if no `teacher` record exists for the authenticated user (BUG-T-02).
- **Line 1935:** `return $e;` — serializes and returns the full PHP exception object including stack trace, file paths, and DB connection details (BUG-T-01).

### TeacherGradingV3.php
- **`approveGrade()`** (line 559): Delegates to `GradeStatus::approve_grade($quarter, $gsid)` — no internal ownership check.
- **`postGrade()`** (line 568): Delegates to `GradeStatus::post_grade()` — no ownership check.
- **`pendingGrade()`** (line 577): No ownership check.
- **Lines 356, 372:** `DB::table('teacher')->where('userid', auth()->user()->id)->first()->id` — null dereference (BUG-T-02).

### TeacherGradingV4.php
- **`approve_subject_grade()`** (line 532): Accepts `teacherid` from request but passes only `$gdid` to `IndividualGrading::approve_subject_grade($gdid)` — `teacherid` is never used or verified. See T-03.
- **`pending_subject_grade()`** (line 525): Same pattern — `teacherid` is silently ignored.
- **Line 719:** `DB::table('teacher')->where('userid', auth()->user()->id)->first()->id` — null dereference (BUG-T-02).

### TeacherFinalGrade.php
- **`submit_grades()`** (line 11): No teacher ownership check — see T-04.
- **`save_grades()`** (line 828): No teacher ownership check — see T-04. Also lacks `DB::transaction()` around multi-table update.
- **`gradestatus()`** (line 57): Creates grade headers if none exist; reachable by any authenticated user.

### ClassAttendanceController.php
- **`submitattendance()`** (line 1508): No section ownership check — see T-09.
- State-changing attendance operations via GET verbs throughout.

### VirtualClassroomController.php
- **`addfiles()`**: MIME validation present (`mimes:jpeg,jpg,...`). Client-supplied filename — see T-12.
- **`editclassassignment()`**: No ownership check — see T-10.
- **`deleteassignment()`**: No ownership check — see T-10.
- **`deleteattachment()`**: Uses `Crypt::decrypt()` on `attachmentid` — Laravel app-key protected, not an IDOR.

### TeacherStudentCredentials.php
- **`update_password()`** (line 608): Accepts any `userid` from request, resets to `123456` — see T-13.
- **`update_all_password()`** (line 13): Bulk resets entire section's passwords — no role check — see T-13.
- **`student_creadentials()`** (line 470): Returns `passwordstr` (cleartext password) in JSON response — see T-14.
- **`generatepassword()`** (line 658): Stores cleartext password in `users.passwordstr` — architectural concern underpinning T-14.

### ObservableBahaviorController.php
- **`submitBehavior()`** (line 392): No `isTeacher` check — any auth user files behavior reports — see T-15.
- **`resolveReport()`** (line 644): No ownership check — any auth user dismisses any incident by ID — see T-15.
- **`reportTable()`, `reportTable2()`, `reportResolve()`**: Return all student behavioral PII to any auth user.

### TeacherPendingGrade.php
- **Line 29:** `DB::table('teacher')->where('userid', auth()->user()->id)->first()->id` — null dereference (BUG-T-02).
- **Lines 331, 335:** `DB::table('sy')->where('isactive',1)->first()->id` and `DB::table('semester')->where('isactive',1)->first()->id` — null dereference if no active SY or semester configured (BUG-T-03).

---

## 6. File Upload Review

| Controller | Method | MIME Validation | Path Traversal Risk |
|---|---|---|---|
| `VirtualClassroomController` | `addfiles()` | ✅ `mimes:jpeg,jpg,png,gif,pdf,...` | LOW — `move()` uses basename |
| `VirtualClassroomController` | `createassignment()` | ✅ `mimes:jpeg,jpg,...` | LOW |
| `VirtualClassroomController` | `submitassignment()` | ✅ `mimes:jpeg,jpg,...` | LOW |

All three upload handlers use `$request->validate()` with an explicit MIME type allowlist before file operations. No PHP file uploads are permitted. The use of `rename()` with `getClientOriginalName()` is a concern but constrained by the pre-validated directory path.

---

## 7. Database Access Patterns

### Dynamic Column Updates (CRITICAL)
Both `udpate_grade_detail()` and `udpate_grade_header()` pass user-supplied input directly as a key in a Laravel `update()` array. Laravel's query builder does **not** validate or quote column names — it treats the key as a literal column identifier. This enables updating any column in the target table.

### No Raw SQL Injection
Grep across all 32 TeacherControllers found no instances of:
- `DB::raw(.*$variable)` 
- `->whereRaw(.*$variable)`
- `->selectRaw(.*$variable)` with user input

All other queries use parameterized query builder methods. SQL injection risk is otherwise LOW.

### Missing Transactions
`save_grades()` and `submit_grades()` in `TeacherFinalGrade.php` perform updates on both `grades` and `gradesdetail` without wrapping in `DB::transaction()`. A partial failure leaves the grade state inconsistent (BUG-T-05).

---

## 8. Frontend Security Review

### DataTables innerHTML Injection (Stored XSS)
**File:** `resources/views/teacher/tchrschedulingv1/indexv1.blade.php` and `index.blade.php`

DataTables `createdCell` callbacks construct HTML by directly concatenating API response fields into `innerHTML`:

```javascript
// indexv1.blade.php line 855
var text = '<a class="mb-0">'+rowData.sectionname+'</a>'
         + '<p class="text-muted mb-0">'+rowData.levelname+'</p>';
$(td)[0].innerHTML = text;
```

```javascript
// indexv1.blade.php line 1036 — data-attribute injection
$(td)[0].innerHTML = '<div><a href="javascript:void(0)" '
    + 'data-acadprogid="'+rowData.acadprogid+'" '
    + 'data-detailed="'+rowData.schedule[0].detailid+'" '
    + 'data-levelid="'+rowData.levelid+'" '
    // ... more unescaped fields
    + 'id="addsubjectcomponent" class="pl-2">...</div>'
```

**Impact:** If an admin (or anyone with write access to section/subject metadata) stores an XSS payload in `sectionname`, `levelname`, or `subjdesc`, it will execute in the browser of every teacher who views their schedule. This is a **stored XSS** vector. While it requires prior admin access to plant, it enables session hijacking, credential harvesting, and keylogging of teacher accounts.

---

## 9. Backend Bugs

### BUG-T-01: Exception Object Disclosure
**File:** `TeacherGradingV2.php`, line 1935  
```php
return $e;  // Returns serialized Exception object
```
Returns the full `Exception` object including: exception message, file path, line number, stack trace, and potentially database connection string details from PDO exceptions. Discloses internal architecture.  
**Fix:** Log the exception internally (`Log::error($e)`), return a generic error response.

---

### BUG-T-02: Null Dereference on Teacher Record Lookup
**Files and lines:**
- `TeacherGradingV2.php:58`
- `TeacherGradingV3.php:356, 372`
- `TeacherGradingV4.php:719`
- `TeacherPendingGrade.php:29`

```php
$teacherid = DB::table('teacher')
    ->where('userid', auth()->user()->id)
    ->first()->id;  // Fatal error if no teacher record exists
```

If a valid user (e.g., a student, admin) reaches these controller methods and has no corresponding `teacher` table record, PHP throws `Trying to get property 'id' of non-object`, causing a 500 error that may expose stack traces.  
**Fix:** `->first()` should be followed by a null check: `if (!$teacher) return response()->json(['error' => 'Teacher not found'], 404);`

---

### BUG-T-03: Null Dereference on Active School Year / Semester
**Files and lines:**
- `TeacherGradingV2.php:324, 328`
- `TeacherPendingGrade.php:331, 335`

```php
$syid  = DB::table('sy')->where('isactive', 1)->select('id')->first()->id;
$semid = DB::table('semester')->where('isactive', 1)->select('id')->first()->id;
```

If no school year or semester is set as `isactive=1`, `first()` returns `null`, and accessing `->id` throws a fatal error. This is a systemic operational bug that can make the entire grading module unavailable.  
**Fix:** Use `?->id` (PHP 8 null-safe operator) or an explicit null check with an error response.

---

### BUG-T-04: Null Dereference on Semester by ID
**File:** `TeacherGradingV2.php`, line 1240
```php
$activeSem = DB::table('semester')->where('id', $semid)->first()->id;
```
If `$semid` is an invalid or deleted ID, `first()` returns `null`.  
**Fix:** Add null guard before accessing `->id`.

---

### BUG-T-05: Missing DB Transactions in Grade Save Operations
**File:** `TeacherFinalGrade.php` — `save_grades()` and `submit_grades()`

Both functions perform updates on multiple tables (`grades` + `gradesdetail`) without wrapping in `DB::transaction()`. If the second update fails (connection drop, deadlock), the database is left in an inconsistent state (e.g., header marked submitted but detail records not updated).  
**Fix:**
```php
DB::transaction(function() use ($request) {
    DB::table('grades')->where(...)->update([...]);
    DB::table('gradesdetail')->where(...)->update([...]);
});
```

---

## 10. Frontend JS Bugs

### FE-T-01: Stored XSS via DataTables innerHTML
**Files:** `resources/views/teacher/tchrschedulingv1/indexv1.blade.php` (lines 855, 976, 997, 1007, 1018, 1036, 1038, 1052, 1481, 1492, 1502, 1643, 1654, 1666, 1668, 1672, 1674, 2249, 2261) and `index.blade.php` (lines 960, 1091, 1114, 1126, 1139, 1620, 1631, 1782)

DataTables cell rendering uses `innerHTML` with unsanitized database values for `sectionname`, `levelname`, `subjdesc`, `roomname`, etc.

**Fix:** Use `document.createTextNode()` or `textContent` for plain text values. For cells that require HTML (buttons with data attributes), sanitize each field with `DOMPurify.sanitize()` or use DOM construction instead of string concatenation:
```javascript
// Instead of:
$(td)[0].innerHTML = '<a>' + rowData.sectionname + '</a>';
// Use:
const a = document.createElement('a');
a.textContent = rowData.sectionname;
$(td)[0].appendChild(a);
```

---

## 11. Fix Recommendations

### Priority 1 — CRITICAL (Immediate)

**T-13: Add `isTeacher` middleware and scope `userid` to teacher's section**
```php
// routes/web.php — move inside isTeacher group
Route::middleware(['auth', 'isTeacher', 'isDefaultPass'])->group(function () {
    Route::get('/teacher/student/generate/password',
        'TeacherControllers\TeacherStudentCredentials@update_password');
    Route::get('/teacher/student/reset/all',
        'TeacherControllers\TeacherStudentCredentials@update_all_password');
});
```
```php
// TeacherStudentCredentials.php — validate userid belongs to a student in teacher's section
public static function update_password(Request $request) {
    $userid = $request->get('id');
    // Verify this user is a student in a section taught by auth()->user()
    $teacherid = DB::table('teacher')->where('userid', auth()->user()->id)->value('id');
    $teacherSections = DB::table('sectiondetail')->where('teacherid', $teacherid)->pluck('sectionid');
    $studentInSection = DB::table('studinfo')
        ->join('enrolledstud', 'studinfo.id', 'enrolledstud.studid')
        ->join('users', 'studinfo.userid', 'users.id')
        ->where('users.id', $userid)
        ->whereIn('enrolledstud.sectionid', $teacherSections)
        ->exists();
    if (!$studentInSection) abort(403);
    // ... proceed
}
```

**T-14: Remove `passwordstr` from API response; use one-time token instead**
```php
// Instead of returning passwordstr in student_creadentials(),
// generate a one-time token for credential handout and never return the raw password.
->select('email', 'id', 'isDefault')  // remove 'passwordstr'
```

**T-01 & T-02: Add middleware and remove dynamic column name**
```php
// routes/web.php — move inside proper middleware group
Route::middleware(['auth', 'isTeacher', 'isDefaultPass'])->group(function () {
    Route::post('gradesdetail/update', 'TeacherControllers\TeacherGradingV2@udpate_grade_detail');
    Route::post('gradesheader/update', 'TeacherControllers\TeacherGradingV2@udpate_grade_header');
});
```
```php
// TeacherGradingV2.php — whitelist allowed columns
function udpate_grade_detail(Request $request)
{
    $ALLOWED_COLUMNS = ['grade', 'grade_1', 'grade_2', 'grade_3', 'grade_4', 'qg'];

    foreach ($data as $item) {
        $col = $item['field'];
        if (!in_array($col, $ALLOWED_COLUMNS, true)) {
            continue; // or abort(422)
        }
        // Also verify the record belongs to a section assigned to auth()->user()
        DB::table('gradesdetail')
            ->where('id', $item['id'])
            ->where('studid', $item['studid'])
            ->take(1)
            ->update([$col => $item['grade'], ...]);
    }
}
```

**T-03: Add role check to grade workflow routes**
```php
Route::middleware(['auth', 'isTeacher', 'isDefaultPass'])->group(function () {
    Route::post('posting/grade/post',    'TeacherControllers\TeacherGradingV4@post_student_grade');
    Route::post('posting/grade/approve', 'TeacherControllers\TeacherGradingV4@approve_student_grade');
    // ...
});
```

### Priority 2 — HIGH (Within Sprint)

**T-04:** Move `teacher/finalgrades/*` routes inside `['auth', 'isTeacher', 'isDefaultPass']` group and add teacher ownership validation inside `save_grades()`.

**T-05 & T-06:** All grade report and deportment status routes must be placed inside the `['auth', ...]` middleware group at minimum.

### Priority 3 — MEDIUM (Next Sprint)

**T-09:** In `submitattendance()`, verify teacher is assigned to the section:
```php
$teacherSection = DB::table('teacher_assignments')
    ->where('teacherid', $teacherid)
    ->where('sectionid', $request->get('sectionid'))
    ->exists();
if (!$teacherSection) abort(403);
```

**T-10:** In `editclassassignment()` and `deleteassignment()`, add ownership check:
```php
$assignment = DB::table('virtualclassroomattach')
    ->where('id', $request->get('assignmentid'))
    ->where('userid', auth()->user()->id)  // ownership gate
    ->first();
if (!$assignment) abort(403);
```

### Priority 4 — LOW / Bug Fixes

- Wrap grade save operations in `DB::transaction()`.
- Replace all `->first()->property` patterns with null-safe checks.
- Replace `return $e;` with `Log::error($e); return ['status' => 0, 'message' => 'Internal error'];`.
- Change DataTables `innerHTML` concatenation to `textContent` or `DOMPurify`.
- Migrate state-changing GET routes to POST with CSRF tokens.
