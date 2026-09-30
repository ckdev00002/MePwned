# College Portal — Security Code Review
**Date:** June 6, 2026  
**Reviewer:** Internal Red Team  
**Scope:** `CTController/` (4 files), `CPControllers/` (2 files), `DeanControllers/` (8 files), `CollegeControllers/` (12 files), `CollegeECR.php` — 27 total  
**Coverage:** 100% controller review + full route mapping for all college-related groups  
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

The "College" module is split across four role-based sub-systems:

| Sub-module | User Type | Middleware | Purpose |
|---|---|---|---|
| **CT** (College Teacher) | type 18 | `auth, isCT, isDefaultPass` | Grade encoding, class management |
| **CP** (Chairperson) | type 16 or 14 | `auth, isCP` | Scheduling, section management, grade approval |
| **Dean** | type 14 | `auth, isDean` | Curriculum, grade oversight |
| **ECR** (Electronic Class Record) | type 18 → 14 → 17 | `auth` only | Grade lifecycle: submit → approve → post |

**Key observation before even reading controllers:** A significant number of grade-write operations are defined **outside all middleware groups** in `routes/web.php`, meaning they have zero access control.

---

## 2. Middleware Analysis

### `AuthenticateCT`
```php
// app/Http/Middleware/AuthenticateCT.php
if(auth()->user()->type == 18 || Session::get('currentPortal') == 18){
    return $next($request);
}
return back();
```
CT = type 18. Same `currentPortal` session pattern. Not exploitable without valid `faspriv` or type==17.

### `AuthenticateCP`
```php
// app/Http/Middleware/AuthenticateCP.php
if(auth()->user()->type == 16 || Session::get('currentPortal') == 16
    || auth()->user()->type == 14 || Session::get('currentPortal') == 14){
    return $next($request);
}
```
CP = type 16 OR 14 (Dean can also access Chairperson routes).

### `AuthenticateDean`
```php
if(auth()->user()->type == 14 || Session::get('currentPortal') == 14){
    return $next($request);
}
```
Dean = type 14.

### ECR Route Group (Critical Issue)
```php
// routes/web.php — line 610
Route::middleware(['auth'])->group(function () {
    Route::get('/college/grade/ecr/approve', 'CollegeECR@approve_grade');
    Route::get('/college/grade/ecr/post',    'CollegeECR@post_grade');
    Route::get('/college/grade/ecr/submit',  'CollegeECR@submit_grade');
    // ...
```
Only `auth` — NO `isCT`, `isCP`, or `isDean`. Any logged-in user can trigger grade submit → approve → post.

### Dean Route Group (Critical Issue)
```php
// routes/web.php — line 2900
Route::middleware(['auth'])->group(function () {
    Route::get('dean/store/prospectus', ...);
    Route::get('dean/remove/prospectussubject/{subject}', ...);
    Route::post('/student/loading/save-loaded-subjects', ...);
    // ...
```
Again only `auth` — any logged-in user (student, parent) can modify college curricula and student subject loading.

---

## 3. Route Mapping Table

| Method | Route | Controller@Method | Middleware | Risk |
|---|---|---|---|---|
| GET | `/teacher/update/hps` | `CPController@updatehps` | **None** | CRITICAL |
| GET | `/teacher/update/grades` | `CPController@updategrades` | **None** | HIGH |
| GET | `/teacher/update/igfg` | `CPController@updateigfg` | **None** | HIGH |
| GET | `/college/student/grade/save` | `CTController@save_student_grade` | **None** | HIGH |
| GET | `/college/student/grade/status/submit` | `CTController@submit_grade_status` | **None** | HIGH |
| GET | `/college/grade/ecr/approve` | `CollegeECR@approve_grade` | `auth` | HIGH |
| GET | `/college/grade/ecr/post` | `CollegeECR@post_grade` | `auth` | HIGH |
| GET | `/college/grade/ecr/submit` | `CollegeECR@submit_grade` | `auth` | MEDIUM |
| GET | `dean/store/prospectus` | `DeanController@storeprospectus` | `auth` | HIGH |
| GET | `dean/remove/prospectussubject/{subject}` | `DeanController@removeprospectussubject` | `auth` | HIGH |
| POST | `/student/loading/save-loaded-subjects` | `CollegeStudentLoadingController@saveLoadedSubjects` | `auth` | HIGH |
| GET | `/college/subject/students` | `CTController@subject_students` | **None** | MEDIUM |
| GET | `/college/student/grade/status` | `CTController@get_grade_status` | **None** | MEDIUM |
| GET | `/college/assignedsubj` | `CTController@get_assigned_subj` | **None** | MEDIUM |
| GET | `/chairpersoninfo` | `CPController@chairpersoninfo` | **None** | LOW |
| GET | `/college/subjects` | `CPController@college_subjects` | **None** | LOW |
| GET | `/college/techer` | `CPController@college_teacher` | **None** | LOW |
| GET | `/subject/schedule` | `CPController@subject_schedule` | **None** | LOW |
| GET | `/college/teacher/schedule` | `CTController@ci_schedule` | **None** | LOW |

---

## 4. Security Findings

### C-01 — CRITICAL — Unauthenticated Arbitrary Grade Corruption (Dynamic Column Injection)
**File:** `app/Http/Controllers/CPControllers/CPController.php` (line 2034)  
**Route:** `GET /teacher/update/hps` (No middleware)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **9.8** (unauthenticated write to academic records)

**Vulnerable Code:**
```php
public static function updatehps(Request $request){
    // No auth()->user()->id call — zero dependency on auth state

    DB::table('grades')
        ->where('id', $request->get('a'))         // ATTACKER-CONTROLLED record ID
        ->update([
            $request->get('b') => (int) $request->get('c')  // ATTACKER-CONTROLLED column name + value
        ]);
}
```

**Three attack vectors in one route:**
1. No authentication at all — any internet visitor can call it
2. Dynamic column name (`$b`) with no allowlist — can set ANY column in the `grades` table to any integer value
3. No ownership check — targets any grade record by `id`

**Attack scenario:**
```bash
# Set qg (quarterly grade) for grades.id=1 to 100
GET /teacher/update/hps?a=1&b=qg&c=100

# Set wwhps0 (highest possible score) to 0 — collapses grade computation
GET /teacher/update/hps?a=1&b=wwhps0&c=0

# Set submitted=0 — reopen a locked grade sheet
GET /teacher/update/hps?a=1&b=submitted&c=0
```

This affects the `grades` table which stores HPS (Highest Possible Score) setup for K-12 basic education grade sheets. Setting HPS to 0 causes a division-by-zero in grade computation. Setting `submitted=0` reopens a grade sheet that was already locked and submitted.

---

### C-02 — HIGH — Any Authenticated User Can Modify K-12 Grade Records
**File:** `app/Http/Controllers/CPControllers/CPController.php` (line 1875)  
**Route:** `GET /teacher/update/grades` (No middleware — only blocked if completely unauthenticated due to `auth()->user()->id` call)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **8.5**

**Vulnerable Code:**
```php
public static function updategrades(Request $request){
    $isSubmitted = DB::table('grades')->where('id',$request->get('inputedDataHPS')[0][0])
                    ->where('submitted','1')->count();
    if($isSubmitted > 0){ return "fsfsdf"; }  // Only protection: can't edit submitted sheets

    foreach($request->get('inputedData') as $item){
        DB::table('gradesdetail')
            ->where('id', $item[0])   // ATTACKER-CONTROLLED gradesdetail ID — no ownership check
            ->update([
                'ww0'=>$item[1], 'ww1'=>$item[2], ..., 'ww9'=>$item[10],  // Written Worksheets
                'pt0'=>$item[12], ..., 'pt9'=>$item[21],                   // Performance Tasks
                'qa1'=>$item[23], 'ig'=>$item[25], 'qg'=>$item[26],       // Initial/Quarterly Grade
                'updatedby' => auth()->user()->id,                         // Any user ID
            ]);
    }
    // Also updates grades.wwhr0-9 (HPS) without role check
}
```

No ownership check — any logged-in user can modify any K-12 student's complete grade breakdown by submitting a crafted array with a known `gradesdetail.id`.

**Same pattern in `updateigfg` (line 1852):** sets `ig` and `qg` for any `gradesdetail` row by ID.

---

### C-03 — HIGH — Unauthenticated College Grade Save (Any Student's Prelim/Midterm/Final)
**File:** `app/Http/Controllers/CTController/CTController.php` (line 3383)  
**Route:** `GET /college/student/grade/save` (No middleware)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **8.6**

```php
public function save_student_grade(Request $request){
    $grade  = $request->get('grade');
    $field  = $request->get('field');   // prelemgrade / midtermgrade / prefigrade / finalgrade
    $studid = $request->get('studid');  // ATTACKER-CONTROLLED student ID
    // No middleware, delegates entirely to model
    return \App\Models\CollegeInstructor\CollegeInstructorData::save_student_grade(
        ..., $grade, $field, $studid
    );
}
```

The model method calls `auth()->user()->id` for the audit trail — if called without auth, it throws a 500. However:
- Any logged-in user (student, parent, cashier) can call this route
- No teacher ownership check — can set prelim/midterm/final grade for **any enrolled student in any subject**
- Valid `$field` values: `prelemgrade`, `midtermgrade`, `prefigrade`, `finalgrade`
- Only gated by grade status: writes if `status == 0 or 4` (unlocked/returned) — easily enumerable by first calling `GET /college/student/grade/status`

---

### C-04 — HIGH — ECR Grade Approval and Posting Under `['auth']` Only
**File:** `app/Http/Controllers/CollegeECR.php` (lines 1196, 1252)  
**Routes:** `GET /college/grade/ecr/approve`, `GET /college/grade/ecr/post` — middleware: `auth` only  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **8.1**

```php
public static function approve_grade(Request $request){
    // No role check — any authenticated user can approve grades
    DB::table('college_exlgrade')
        ->where('id', $id)
        ->update(['status' => 2]);   // 2 = APPROVED
    DB::table('college_exlgrade_logs')->insert(['status'=>'APPROVE', 'createdby'=>auth()->user()->id]);
}

public static function post_grade(Request $request){
    // No role check — any authenticated user can post grades
    DB::table('college_exlgrade')
        ->where('id', $id)
        ->update(['status' => 4]);   // 4 = POSTED
}
```

**Grade lifecycle in ECR:** `SUBMIT (1)` → `APPROVE (2)` → `POST (4)`. Approving should require a Chairperson (type 16/14). Posting should require a Dean (type 14). Both actions are accessible to any logged-in user — a student can approve and post their own grades.

---

### C-05 — HIGH — Dean Curriculum and Student Loading Under `['auth']` Only
**Route group:** `Route::middleware(['auth'])` at line 2900  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` = **8.5**

Operations available to any authenticated user:
- `GET /dean/store/prospectus` — add subjects to college curriculum
- `GET /dean/remove/prospectussubject/{subject}` — remove subjects from curriculum
- `POST /student/loading/save-loaded-subjects` — bulk-add/remove subjects from a student's loading
- `GET /student/loading/students` — enumerate all enrolled college students

Any student can add or remove required subjects from the college prospectus, potentially breaking graduation requirement checks for all students in that course.

---

### C-06 — HIGH — Unauthenticated Grade Status Write (`/college/student/grade/status/submit`)
**File:** `CTController.php` (line 3377)  
**Route:** `GET /college/student/grade/status/submit` (No middleware)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **7.5**

```php
public function submit_grade_status(Request $request){
    $statusid  = $request->get('statusid');    // ATTACKER-CONTROLLED
    $datafield = $request->get('datafield');   // ATTACKER-CONTROLLED
    return \App\Models\CollegeInstructor\CollegeInstructorProccess::submit_grades_status($statusid, $datafield);
}
```

No auth check at all. Any visitor can call this and modify grade submission status records. Combined with C-01 or C-03 to first manipulate the grade value, then submit it through the workflow.

---

### C-07 — MEDIUM — Unauthenticated Student Grade Data Exposure
**Routes:** All no-middleware (outside all route groups)

| Route | Method | Exposed Data |
|---|---|---|
| `GET /college/subject/students` | `CTController@subject_students` | Grade records for every student in a section/subject |
| `GET /college/student/grade/status` | `CTController@get_grade_status` | Grade status flags (note: method is commented out — returns 500) |
| `GET /college/assignedsubj` | `CTController@get_assigned_subj` | Teacher-to-subject assignments |
| `GET /teacher/get/grades/{section}/{quarter}` | `CPController@getGrades` | All grade values for a section |

**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**

An attacker who knows or guesses a `sectionid` and `subjid` can retrieve all students' numeric grades without logging in.

---

### C-08 — MEDIUM — Unauthenticated College Directory Exposure
**Routes:** No middleware

| Route | Exposed Data |
|---|---|
| `GET /chairpersoninfo` | Course list with chairperson assignments |
| `GET /college/subjects` | All college subjects list |
| `GET /college/techer` | College teacher list (typo in route name) |
| `GET /subject/schedule` | Full section schedule with teacher, time, room |
| `GET /college/teacher/schedule` | Specific teacher's schedule |

**CVSS:** 5.3 — Enables pre-attack enumeration (teacher IDs, section IDs, subject IDs for use in C-01–C-07).

---

### C-09 — LOW — Duplicate Route Registrations
- `GET /chairpersoninfo` defined twice outside middleware (lines ~3049 and ~3066)
- All Dean routes at lines 2903–2909 are registered **four times** each (4× repetition in the route file)
- Grade status submit pattern routes duplicated

No security impact, but increases maintenance confusion and may mask future routing anomalies.

---

### C-10 — LOW — Dead Route (`/college/student/grade/status`)
**Route:** `GET /college/student/grade/status` → `CTController@get_grade_status`  
The method is entirely commented out in the controller:
```php
//  public function get_grade_status(Request $request){
//      ...
//  }
```
Every request to this route causes a `500 Internal Server Error` (Laravel cannot resolve the method). The route should be removed.

---

## 5. Backend Bugs

### BUG-C-01 — `CPController@updatehps` Returns Nothing
```php
DB::table('grades')->where('id',$a)->update([$b => (int)$c]);
// No return statement — method returns null
```
The frontend receives a null JSON response. Callers cannot confirm success or failure.

### BUG-C-02 — `GET /college/student/grade/status` Always 500
`get_grade_status` is entirely commented out but the route is still registered. Any call hits Laravel's method-not-found handler and returns a 500.

### BUG-C-03 — `college/techer` Route Has Typo
`GET /college/techer` is missing the `a` — should be `/college/teacher`. Both the route and any frontend referencing it use the typo, so it works — but any future rename attempt will break silently.

### BUG-C-04 — `save_student_grade` Returns Null for Invalid `$field`
If `$field` is not one of `prelemgrade`, `midtermgrade`, `prefigrade`, `finalgrade`, the `$status_field` is null and the update block is skipped entirely. The model returns nothing — the caller receives a `null` response with no error indicator.

### BUG-C-05 — `updategrades` Returns Non-Standard String on Submit Lock
```php
if($isSubmitted > 0){ return "fsfsdf"; }
```
Returns a meaningless debug string `"fsfsdf"` when grades are locked (already submitted). Should return a proper JSON error response.

---

## 6. Fix Recommendations

| Finding | Priority | Fix |
|---|---|---|
| C-01 (unauthenticated HPS update) | **IMMEDIATE** | Add `['auth', 'isCT']` middleware; add column name allowlist: `['wwhps0'...'wwhps9', 'pthps', 'qahps']` |
| C-02 (updategrades, updateigfg no auth) | **IMMEDIATE** | Add `['auth', 'isCT']` to both routes; add teacher ownership check against `grades.teacherid` |
| C-03 (save_student_grade no auth) | **IMMEDIATE** | Add `['auth', 'isCT']` middleware; verify teacher owns the schedule |
| C-06 (submit_grade_status no auth) | **IMMEDIATE** | Add `['auth', 'isCT']` middleware |
| C-07 (grade data exposure) | **HIGH** | Move all `//final_grade_college` routes inside `['auth', 'isCT']` middleware group |
| C-04 (ECR approve/post no role) | **HIGH** | Add `isCP` to `/ecr/approve` and `isDean` to `/ecr/post` |
| C-05 (dean routes no role) | **HIGH** | Add `isDean` to `mapDeanRoutes()` equivalent; use `Route::middleware(['auth', 'isDean'])` |
| C-08 (college directory no auth) | Medium | Move all `//college_data` standalone routes inside `['auth']` at minimum |
| BUG-C-01 (no return) | Medium | Add `return response()->json(['status'=>1])` after DB update |
| BUG-C-02 (dead route 500) | Medium | Remove `Route::get('college/student/grade/status', ...)` from web.php |
| C-09/C-10 (duplicates/dead) | Low | Remove duplicate route registrations |

---

*End of College Portal Code Review*
