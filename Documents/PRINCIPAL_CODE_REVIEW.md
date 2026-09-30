# Principal Portal — Security Code Review
**Date:** June 09, 2026  
**Reviewer:** Internal Red Team  
**Scope:** `PrincipalControllers/` (11 files), `AuthenticatePrincipal.php`, `TeacherGradingV4.php` (grade post/approve methods), route group analysis  
**Coverage:** 100% — all Principal routes mapped, all controller methods reviewed  
**Status:** Complete

---

## Table of Contents
1. [Scope & Methodology](#1-scope--methodology)
2. [Middleware Analysis](#2-middleware-analysis)
3. [Route Mapping Table](#3-route-mapping-table)
4. [Security Findings](#4-security-findings)
5. [Backend Bugs](#5-backend-bugs)
6. [Frontend Issues](#6-frontend-issues)
7. [Fix Recommendations](#7-fix-recommendations)

---

## 1. Scope & Methodology

The Principal module handles K-12 report card workflows (grade posting, approval, SF9 printing), deportment (conduct) grading, section management, student awards/honors, and class scheduling. It sits at the intersection of teacher-submitted grades and final official report cards — making access control failures here directly affect academic record integrity.

### Files Reviewed
| File | Lines | Purpose |
|---|---|---|
| `PrincipalController.php` | ~900 | Core operations: SF9, signatories, awards, enrolled students |
| `DeportmentStatus.php` | ~900 | Deportment grade status management |
| `ScheduleController.php` | ~300 | Class schedule plot and print |
| `PrincipalSummaryController.php` | ~80 | Summary views (mostly stubbed) |
| `DynamicPDFController.php` | — | SF9/SF6 PDF generation |
| `HomeroomConductController.php` | — | Homeroom conduct records |
| `AwardSetupController.php` | — | Awards and recognition setup |
| `TeacherGradingV4.php` | 550+ | Grade post/approve/unpost/pending (shared with Teacher module) |
| `AuthenticatePrincipal.php` | 50 | Role middleware — **never used in routes** |

---

## 2. Middleware Analysis

### `AuthenticatePrincipal` — Defined But Never Applied
```php
// app/Http/Middleware/AuthenticatePrincipal.php
public function handle($request, Closure $next, ...$roles)
{
    if (auth()->user()->type == 2 || Session::get('currentPortal') == 2) {
        return $next($request);
    }
    else if (collect($roles)->contains('princoor') && $usertype->refid == 20) {
        return $next($request);
    }
    // else redirect('/')
}
```

The middleware correctly checks `type == 2` (Principal) or `currentPortal == 2`. It is registered in `Kernel.php` as `isPrincipal`. **It is used in zero routes across all route files.** Every Principal controller endpoint is reached through `['auth']`, `['auth','isDefaultPass']`, or no middleware at all.

### `isDefaultPass` — Not a Role Check
```php
// Used on grade post/approve routes instead of isPrincipal
Route::middleware(['auth', 'isDefaultPass'])->group(function () {
    Route::get('posting/grade/post', 'TeacherControllers\TeacherGradingV4@post_student_grade');
    Route::get('posting/grade/approve', 'TeacherControllers\TeacherGradingV4@approve_student_grade');
    // ...
```

`isDefaultPass` verifies the user has changed their default password. It performs no role check. Any authenticated user who has changed their default password — including students and parents — can call grade post and approve endpoints.

### No Middleware — DeportmentStatus Write Routes
Eight `DeportmentStatus` routes are registered outside all middleware groups:
```php
// routes/web.php lines 318–328 — outside any group
Route::get('/posting/grade/deportment-status', 'PrincipalControllers\DeportmentStatus@show');
Route::get('/posting/grade/get-deportment-details', ...@get_deportment_details');
Route::get('/posting/grade/get-student-list', ...@get_student_list');
Route::get('/posting/grade/get-student-status', ...@get_student_status');
Route::get('/posting/grade/filter-student-status', ...@filter_student_status');
Route::get('/posting/grade/load-class-table', ...@loadtable');
Route::get('/posting/grade/update-grade-status', ...@update_gradestatus');     // WRITE
Route::get('/posting/grade/update-stud-gradstatus', ...@update_specific_gradestatus'); // WRITE
```

The last two perform DB writes with no authentication whatsoever.

---

## 3. Route Mapping Table

| Method | Route | Controller@Method | Middleware | Risk |
|---|---|---|---|---|
| GET | `/posting/grade/update-grade-status` | `DeportmentStatus@update_gradestatus` | **None** | **CRITICAL** |
| GET | `/posting/grade/update-stud-gradstatus` | `DeportmentStatus@update_specific_gradestatus` | **None** | **CRITICAL** |
| GET | `posting/grade/post` | `TeacherGradingV4@post_student_grade` | `auth, isDefaultPass` | **HIGH** |
| GET | `posting/grade/approve` | `TeacherGradingV4@approve_student_grade` | `auth, isDefaultPass` | **HIGH** |
| GET | `posting/grade/unpost` | `TeacherGradingV4@unpost_student_grade` | `auth, isDefaultPass` | **HIGH** |
| GET | `posting/grade/pending` | `TeacherGradingV4@pending_student_grade` | `auth, isDefaultPass` | **HIGH** |
| GET | `/setup/signatories/create/sf9` | `PrincipalController@create_sf9_signatory` | `auth` | **HIGH** |
| GET | `/setup/signatories/update/sf9` | `PrincipalController@update_sf9_signatory` | `auth` | **HIGH** |
| GET | `/setup/signatories/delete/sf9` | `PrincipalController@delete_sf9_signatory` | `auth` | **HIGH** |
| POST | `/save/average/grade` | `PrincipalController@saveAverageType` | `auth` | **MEDIUM** |
| GET | `/principalPortalSectionProfile/{id}` | `PrincipalController@loadSectionProfile` | `auth` | **MEDIUM** |
| GET | `/principal/ps/gradestatus/delete` | `PrincipalController@ps_gradestatus_delete` | `auth` | **MEDIUM** |
| GET | `principal/setup/schedule/removesched` | `ScheduleController@removesched` | `auth` | MEDIUM |
| GET | `/posting/grade/deportment-status` | `DeportmentStatus@show` | **None** | LOW |
| GET | `/posting/grade/get-deportment-details` | `DeportmentStatus@get_deportment_details` | **None** | LOW |
| GET | `/posting/grade/load-class-table` | `DeportmentStatus@loadtable` | **None** | LOW |

---

## 4. Security Findings

### PR-01 — CRITICAL — `isPrincipal` Middleware Never Applied; All Routes Under `['auth']` Only
**File:** `routes/web.php`, `AuthenticatePrincipal.php`  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = **8.8**

`isPrincipal` middleware is registered in `Kernel.php` and correctly written. However, it is called in **zero routes** anywhere in the application. The consequence is that the entire Principal portal operates on `['auth']` alone — meaning any logged-in user can access it:

- `POST /save/average/grade` — any user can change the grade averaging formula applied to all report cards
- `GET /setup/signatories/create/sf9`, `update/sf9`, `delete/sf9` — any user can add, modify, or delete the name and title of the signatory printed on all SF9 report cards
- `GET /principal/ps/gradestatus/delete` — any user can delete grade status records
- `GET principal/section/students/enrolled` — any user reads the full enrolled student list
- `GET principal/grades/status` — any user reads grade submission status across all sections
- `GET /principalAwardsAndRecognitions` — any user reads honor roll data

The `['auth']` requirement is the only barrier — a student logged into their own portal can call all of these endpoints directly.

---

### PR-02 — CRITICAL — Deportment Grade Status Writes With No Middleware
**File:** `DeportmentStatus.php` (lines 698–756)  
**Route:** `GET /posting/grade/update-grade-status`, `GET /posting/grade/update-stud-gradstatus` — **No middleware**  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **7.5**

Both methods write to the `student_deportment` and `deportment_hps` tables with attacker-supplied parameters and no authentication:

```php
// update_gradestatus — completely unauthenticated
public function update_gradestatus(Request $request){
    $idarray = $request->array;   // attacker-controlled list of student IDs
    foreach ($idarray as $id) {
        DB::table('student_deportment')
            ->where('studid', $id)
            ->where('syid', $request->syid)
            ->where('sectionid', $request->sectionid)
            ->where('quarter_ID', $request->quarter_ID)
            ->update([
                'gradestatus' => $request->status,  // attacker sets status (1-5)
            ]);
    }
    DB::table('deportment_hps')          // also writes HPS table
        ->where('id', $request->hpsid)
        ->update(['gradestatus' => $request->status]);
}

// update_specific_gradestatus — completely unauthenticated
public function update_specific_gradestatus(Request $request){
    DB::table('student_deportment')
        ->where('id', $request->studid)  // any student's conduct record
        ->where('syid', $request->sy)
        ->where('quarter_ID', $request->quarter)
        ->update(['gradestatus' => $request->status]);
}
```

An unauthenticated attacker can set any student's deportment (conduct) grade status to any value — including status 5 (Posted) — without any teacher or principal ever reviewing it.

---

### PR-03 — HIGH — Grade Post/Approve/Unpost Under `isDefaultPass` Only (No Role Check)
**File:** `TeacherGradingV4.php` (lines 94–530)  
**Route:** `GET posting/grade/post`, `posting/grade/approve`, `posting/grade/unpost`, `posting/grade/pending` — `['auth', 'isDefaultPass']`  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **8.1**

`isDefaultPass` only checks whether the authenticated user has already changed their default password. It does not verify that the user is a Principal (type 2) or holds any administrative role. Any teacher, student, cashier, or parent who has changed their default password can call these endpoints:

```php
// Any authenticated user (with changed default password) can call:
Route::get('posting/grade/post',     'TeacherGradingV4@post_student_grade');
Route::get('posting/grade/approve',  'TeacherGradingV4@approve_student_grade');
Route::get('posting/grade/unpost',   'TeacherGradingV4@unpost_student_grade');
Route::get('posting/grade/pending',  'TeacherGradingV4@pending_student_grade');
```

A teacher whose grades were rejected can self-approve and self-post their own grade submissions by calling these endpoints directly.

---

### PR-04 — HIGH — SF9 Report Card Signatory Modifiable by Any Authenticated User
**File:** `PrincipalController.php` (line ~900)  
**Route:** `GET /setup/signatories/create/sf9`, `/update/sf9`, `/delete/sf9` — `['auth']`  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **8.1**

The signatory records control the name and title printed on official SF9 school forms. Under `['auth']` with no role check, any logged-in user can:
- Create a new signatory for any `acadprogid` and `syid`
- Update the existing signatory name/title
- Delete the signatory entirely

A student can call `GET /setup/signatories/update/sf9?id=1&name=Attacker&title=Principal` to replace the signatory on official report cards for the current school year.

---

### PR-05 — MEDIUM — IDOR in `loadSectionProfile` via Silently Swallowed Decrypt Exception
**File:** `PrincipalController.php` (line ~103)  
**Route:** `GET /principalPortalSectionProfile/{id}` — `['auth']`  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:M/I:N/A:N` = **4.3**

```php
public function loadSectionProfile($id)
{
    try {
        $id = Crypt::decrypt($id);
    } catch (\Exception $e) {
        // EMPTY — exception silently discarded
    }
    // $id is now the raw plaintext integer if decryption failed
    $sectioninfo = DB::table('sections')->where('sections.id', $id)->...->first();
    return view('principalsportal.pages.section.sectioninfo')->with('sectionInfo', $sectioninfo);
}
```

When a plain integer is passed in the URL (`/principalPortalSectionProfile/1`, `/principalPortalSectionProfile/2`, ...), the `Crypt::decrypt()` call throws and is silently caught. The original integer `$id` is then used directly in the query. Any authenticated user can enumerate all section profiles by incrementing the integer.

---

### PR-06 — MEDIUM — Unauthenticated Routes Call `auth()->user()->id` (Crash on External Access)
**File:** `DeportmentStatus.php`, `PrincipalController.php`  
**Routes:** `GET /posting/grade/get-deportment-details`, `GET /posting/grade/get-student-list` — No middleware  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` = **5.3**

Multiple routes are outside all middleware but their handlers call `auth()->user()->id` or rely on session data:

```php
// get_deportment_details — no middleware, but calls:
$teacherID = DB::table('teacher')
    ->where('userid', auth()->user()->id)   // THROWS if unauthenticated
    ->first()->id;
```

An unauthenticated request to these endpoints will produce a 500 Internal Server Error that may expose stack trace information in non-production error configurations. In production, it generates error log noise and makes the endpoint appear broken rather than unauthorized.

---

## 5. Backend Bugs

### BUG-PR-01 — Persistent Typo: "Aproved" / "Succesfully" Across Multiple Files
**Severity:** Low | **Files:** `DeportmentStatus.php`

The grade status string for status 4 is misspelled as `"Aproved"` (missing 'p') in at least three places. This misspelling is serialized into API responses, stored in HTML attributes, and displayed in the UI:

```php
// get_student_status() — API response field
array_push($status, (object)['id' => 4, 'text' => 'Aproved', 'isactive' => 0]);

// loadtable() — HTML generation
$status = "Aproved";     // displayed as badge label to users
$color  = "primary";

// update_gradestatus() — success message
'message' => 'Succesfully Approved!',   // also "Succesfully" (should be "Successfully")
```

The same pattern appears in the Female student loop at the bottom of `loadtable()`.

---

### BUG-PR-02 — Null Dereference in `loadtable()` When `deportment_hps` Record Doesn't Exist
**Severity:** Medium | **File:** `DeportmentStatus.php` (~line 360)

```php
$deportmentID = DB::table('deportment_hps')
    ->where('syid', $request->syid)
    ->where('sectionid', $request->sectionid)
    ->where('quarter_ID', $request->quarterid)
    ->where('deleted', 0)
    ->select('deportment_setupid')
    ->first();                         // returns null if no record

$values = DB::table('deportment_values')
    ->where('deportment_setupID', $deportmentID->deportment_setupid)  // THROWS: "Trying to get property of non-object"
    ->where('deleted', '0')
    ->get();
```

If no `deportment_hps` row exists for the requested section/school year/quarter, `$deportmentID` is `null` and the next line throws a fatal error. This is not caught. The same issue appears for the `$hps` variable a few lines above.

---

### BUG-PR-03 — `store_error()` Calls `auth()->user()->id` — Double Fault When Unauthenticated
**Severity:** Medium | **File:** `PrincipalController.php`

```php
public static function store_error($e)
{
    DB::table('zerrorlogs')->insert([
        'error' => $e,
        'createdby' => auth()->user()->id,  // throws if no auth session
        // ...
    ]);
}
```

If an exception is caught and `store_error()` is called during an unauthenticated request (e.g., from a no-middleware route), it throws a secondary `TypeError`/`BadMethodCallException`, masking the original error and producing an unhelpful 500 response.

---

### BUG-PR-04 — `loadAverageType()` No Null Check on DB Result
**Severity:** Medium | **File:** `PrincipalController.php`

```php
public static function loadAverageType(Request $request)
{
    $check = DB::table('signatory')
        ->where('form', 'report_card_average_type')
        ->first();              // returns null if not yet set up

    return $check->name;        // THROWS: "Trying to get property of non-object"
}
```

On a fresh school year or before any average type is configured, this method throws a fatal error. Should be: `return $check?->name ?? null;` or a proper null check.

---

### BUG-PR-05 — `print_award()` Saves `.docx` to Working Directory (Race Condition)
**Severity:** Medium | **File:** `PrincipalController.php` (~line 800)

```php
$document->saveAs('Cert_award_' . $student->lastname . '_' . $student->firstname . '.docx');
$file_url = 'Cert_award_' . $student->lastname . '_' . $student->firstname . '.docx';
header("Content-disposition: attachment; filename=" . $file_url);
readfile($file_url);
unlink($file_url);   // deleted after sending
```

The `.docx` file is saved to the current working directory (likely `public/`), not to `storage/`. If two users request award certificates concurrently for students with the same first/last name (e.g., two "Juan Dela Cruz" in different sections), both requests write to the same filename, and one user receives the other's certificate. The `unlink()` after `readfile()` can also fail if the file was already deleted by a concurrent request.

---

### BUG-PR-06 — Unescaped Student Name Output in `loadtable()` HTML (Stored XSS)
**Severity:** Medium | **File:** `DeportmentStatus.php` (~line 425)

```php
$deportment_values .= '<td>'
    . $student->lastname . ', ' . $student->firstname   // NO escaping
    . '<span class="badge badge-'.$color.' mr-2">' . $status . '</span>'
    . '</td>';
```

Student `lastname` and `firstname` values are inserted directly into the HTML string without `htmlspecialchars()`. If a student's name contains `<script>alert(1)</script>`, it executes when a principal loads the deportment table. Since student names come from the enrollment process and are stored in the DB, this is a stored XSS vector.

---

### BUG-PR-07 — `$status` and `$color` Variables Declared Uninitialized in Female Student Loop
**Severity:** Low | **File:** `DeportmentStatus.php` (~line 580)

```php
// Female student section of loadtable()
$status;   // bare expression — NOT assignment, NOT initialization
$color;    // same — stale values from previous iteration may leak

if ($student->gradestatus == 1) { $status = "Not Submitted"; $color = "secondary"; }
else if ($student->gradestatus == 2) { $status = "Submitted"; $color = "success"; }
// ...
```

If `gradestatus` is an unexpected value (e.g., 0 or null), `$status` and `$color` hold whatever was last assigned in the **previous student's iteration**, causing incorrect badge labels and colors to be displayed for that student.

---

### BUG-PR-08 — `count($items) != null` Logic Error
**Severity:** Low | **File:** `DeportmentStatus.php` (~line 400)

```php
if (count($items) != null) {
    // build column headers
}
```

In PHP, `count([])` returns `0`. Because PHP type-juggles `0 == null` as `true`, this condition evaluates to `false` for empty arrays — which accidentally works. However, the intent is clearly `count($items) > 0`. The current form is misleading, confusing to maintainers, and fragile (PHP 8 deprecated `null` comparisons in some contexts).

---

## 6. Frontend Issues

### FE-PR-01 — "Aproved" Status Label Shown to Users (UI Quality)
The grade status badge in the deportment table renders `"Aproved"` in the principal's view whenever a grade batch reaches status 4. This appears on every section's deportment table and in the grade status selector dropdown.

### FE-PR-02 — Grade Status Badges Use Inconsistent Color Semantics
In `loadtable()`:
- Status 2 (Submitted) = `badge-success` (green) — implies final/done
- Status 4 (Approved) = `badge-primary` (blue)
- Status 5 (Posted) = `badge-info` (light blue)

Green (success) for "Submitted" is misleading — submitted grades still require principal approval. Users may misread "Submitted" as "finalized."

### FE-PR-03 — `PrincipalSummaryController::summarytotalnumberofstudents()` — Entire Implementation Commented Out
**File:** `PrincipalSummaryController.php`

The method body contains ~80 lines of commented-out code and returns only an empty view. All data queries are disabled. If the summary view renders, it shows a blank page with no student count data. The commented code indicates this was once working and was disabled without removal.

### FE-PR-04 — Award Certificate Filename Not Sanitized
**File:** `PrincipalController.php`

```php
$file_url = 'Cert_award_' . $student->lastname . '_' . $student->firstname . '.docx';
header("Content-disposition: attachment; filename=" . $file_url);
```

The `Content-Disposition` filename is not quoted. If a student's name contains spaces or special characters, the header value becomes malformed. RFC 6266 requires the filename parameter to be quoted: `filename="..."`. Some browsers may fail to download or save the file correctly.

---

## 7. Fix Recommendations

| Finding | Priority | Fix |
|---|---|---|
| PR-01 (`isPrincipal` never used) | **IMMEDIATE** | Apply `['auth', 'isPrincipal']` to all Principal route groups; move grade post/approve to `['auth', 'isPrincipal']` |
| PR-02 (deportment write — no auth) | **IMMEDIATE** | Move `update-grade-status` and `update-stud-gradstatus` inside `['auth', 'isPrincipal']` group |
| PR-03 (grade post under `isDefaultPass`) | **IMMEDIATE** | Replace `['auth', 'isDefaultPass']` with `['auth', 'isPrincipal']` for grade posting routes |
| PR-04 (SF9 signatory under `['auth']`) | **IMMEDIATE** | Move signatory CRUD inside `['auth', 'isPrincipal']` |
| PR-05 (IDOR in loadSectionProfile) | High | Re-throw or return 404 on decrypt failure; use `abort(404)` in catch block |
| PR-06 (auth() calls on unauth routes) | Medium | Add `['auth']` at minimum to all DeportmentStatus routes |
| BUG-PR-01 (typos) | Low | Find-replace: `"Aproved"` → `"Approved"`, `"Succesfully"` → `"Successfully"` |
| BUG-PR-02 (null dereference in loadtable) | High | Add `if (!$deportmentID) return response()->json([...error...], 400)` |
| BUG-PR-03 (store_error double fault) | Medium | Add `auth()->check() ?` guard before `auth()->user()->id` |
| BUG-PR-04 (loadAverageType null) | Medium | Add null check: `return $check?->name ?? null` |
| BUG-PR-05 (print_award race) | Medium | Save to `storage/app/temp/<uuid>.docx`; use random filename; delete after send |
| BUG-PR-06 (XSS in loadtable) | High | Wrap all student data with `htmlspecialchars()` before string concatenation |
| BUG-PR-07 (uninitialized vars) | Low | Initialize `$status = ''` and `$color = ''` before each loop iteration |
| FE-PR-04 (filename header) | Low | Quote the filename: `"Content-disposition: attachment; filename=\"{$file_url}\""` |

---

*End of Principal Portal Code Review*
