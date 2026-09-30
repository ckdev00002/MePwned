# Auxiliary Modules — Full Code Review
## TESDA · Admission · Guidance · Document Tracking · Library
**Date:** June 13, 2026  
**Target:** `routes/tesda.php`, `routes/admission.php`, `routes/guidance.php`, `routes/documenttracking.php`, `routes/library.php` + associated controllers  
**Methodology:** Static analysis — route configuration, middleware, authentication, IDOR, CSRF exposure  
**Scope:** Authentication gaps, access control, unauthenticated data exposure, PII handling

---

## Table of Contents
1. [Module Overview](#1-module-overview)
2. [Route Configuration Summary](#2-route-configuration-summary)
3. [Security Findings](#3-security-findings)
4. [Backend Bug Findings](#4-backend-bug-findings)
5. [Fix Recommendations](#5-fix-recommendations)

---

## 1. Module Overview

Five auxiliary modules are loaded via `RouteServiceProvider` with only `middleware('web')` at the provider level. Each module may or may not define internal auth groups:

| Module | Route File | Prefix | Internal Auth |
|---|---|---|---|
| TESDA | `routes/tesda.php` | `tesda/` | **None — 0 routes protected** |
| Admission | `routes/admission.php` | `admission/` | Partial — public applicant flow + `['auth']` admin group |
| Guidance | `routes/guidance.php` | `guidance/` | `['auth']` only — no role check |
| Document Tracking | `routes/documenttracking.php` | `doctrack/` | `['auth']` only — no role check |
| Library | `routes/library.php` | `library/` | Partial — public catalogue + `['auth']` + `['auth', 'admin']` |

---

## 2. Route Configuration Summary

### TESDA — Zero Authentication

The entire `tesda.php` file contains no `Route::middleware()` groups. Every route runs with no authentication:

```
GET  /tesda/getStudent                              → TesdaStudentInformationController@GetStudentInformation
POST /tesda/addStudent                              → TesdaStudentInformationController@AddStudentInformation
GET  /tesda/studentInformation/{id}                 → TesdaStudentInformationController@StudentInformation
GET  /tesda/enroll/{id}                             → TesdaStudentInformationController@GetStudentInformationToEnroll
GET  /tesda/printCOR/{id}                           → TesdaStudentInformationController@tesdaPrintCor
GET  /tesda/printTOR/{id}                           → TesdaStudentInformationController@tesdaPrintTor
GET  /tesda/printCORall                             → TesdaStudentInformationController@tesdaPrintCor
GET  /tesda/printTORall                             → TesdaStudentInformationController@tesdaPrintTorAll
DELETE /tesda/delete-student/{id}                   → TesdaStudentInformationController@delete_student
PUT  /tesda/update-student-enrolled/{id}            → TesdaStudentInformationController@update_student_enrolled
DELETE /tesda/delete-signatories/{id}               → TesdaStudentInformationController@delete_signatory
GET  /tesda/course_setup/add/course_type            → TesdaCourseSetupController@...
GET  /tesda/course_setup/delete/course              → TesdaCourseSetupController@...
GET  /tesda/batch_setup/delete/batch                → TesdaBatchSetupController@...
GET  /tesda/batch_setup/delete/batch/scheduledetail → TesdaBatchSetupController@...
POST /tesda/enrollment/save                         → StudentController@tesda_enrollment_save
POST /tesda/enrollment/delete                       → StudentController@tesda_enrollment_delete
GET  /tesda/pdf/national_certificate                → TesdaCertificationController@exportNationalCertToPdf
GET  /tesda/pdf/honorable_dismissal/{id}            → TesdaCertificationController@exportHonorableDismissalCertToPdf
GET  /tesda/pdf/honorable_dismissal_all             → TesdaCertificationController@exportHonorableDismissalCertToPdf
POST /tesda/trainer/systemgrades/submit_grades      → TesdaTrainerController@submit_grades
```
**80+ routes total — all unauthenticated.**

### Admission — Mixed (Intentional Public Routes + Admin Auth Group)

Public applicant flow (intentionally unauthenticated — for external applicants):
```
Route::view('/admission/pooling-entry', ...)
Route::post('/admission/save-student-info', ...)    ← stores applicant PII
Route::post('/admission/update-student-info', ...)  ← updates any applicant's data (IDOR)
Route::get('/admission/save-answer', ...)           ← stores exam answer via GET
Route::get('/admission/submit-test', ...)           ← submits exam via GET
Route::get('/admission/diagnostictest', ...)
Route::get('/admission/verify-pooling', ...)
```

Admin group (`['auth']` only, no role check):
```
GET /admission/get-applicants, /edit-applicant, /accept-student, /decline-student,
    /verify-student, /delete-applicant, /retaketest
```

### Guidance — `['auth']` Only, No Role Check

Every guidance route is under `['auth']` but no `isGuidance` or equivalent middleware. Any authenticated user (student, teacher, cashier, parent) can:
```
GET  /guidance/delete-testquestion     → delete exam questions
GET  /guidance/delete-category         → delete exam categories
GET  /guidance/delete-examdate         → delete exam dates
GET  /guidance/delete-passingrate      → delete passing rate setups
GET  /guidance/delete-referral         → delete counseling referrals
GET  /guidance/activatePassingrate     → activate any passing rate setup
POST /guidance/add-entrance-exam       → create entrance exam setups
POST /guidance/add-testquestion        → create exam questions
```
All destructive operations use GET verbs (no CSRF protection).

### Document Tracking — `['auth']` Only, No Role Check, State-Changing GETs

```
GET  /doctrack/forward-document    → forwards any document to any signatory
GET  /doctrack/receive-document    → marks any document as received
GET  /doctrack/reject-document     → rejects any document
GET  /doctrack/close-document      → closes any document permanently
```
All operations accept document IDs from the request with no ownership check. Any authenticated user can forward, reject, or close any document in the system.

### Library — Partially Intentional, Mostly Secure

Public (intentional for catalogue visitors):
```
GET  /library/books          → all library books (low-sensitivity public data)
GET  /library/get-book       → specific book details
View /library/catalogue-view → public catalogue page
```

Auth-only (sensitive) routes are under `['auth', 'admin']` — the library has its own separate `admin` middleware, making it better structured than most other modules.

Minor issues:
```
GET /library/pinbook         → state-changing GET (pins a book without auth)
GET /library/request-reset   → password reset without auth (library-specific users only)
```

---

## 3. Security Findings

---

### AUX-01 — CRITICAL — `tesda.php`: Entire TESDA Portal is Unauthenticated (Same Root Cause as Bookkeeper)
**File:** `app/Providers/RouteServiceProvider.php`, `routes/tesda.php`  
**Category:** Broken Access Control (OWASP A01)

`RouteServiceProvider::mapTesdaRoutes()` loads `tesda.php` with only `middleware('web')` — identical to the Bookkeeper finding (BK-01). No `auth` group exists anywhere in `tesda.php`:

```php
// RouteServiceProvider.php
protected function mapTesdaRoutes()
{
    Route::prefix('tesda')
        ->middleware('web')    // ← no 'auth'
        ->group(base_path('routes/tesda.php'));
}
```

Any internet user — without a login — can:
- **List all TESDA students:** `GET /tesda/getStudent` → full name, contact, address, enrollment history
- **View any student's full profile:** `GET /tesda/studentInformation/{id}` → complete PII
- **Print any student's COR:** `GET /tesda/printCOR/{id}` → official document containing student data
- **Print all CORs and TORs:** `GET /tesda/printCORall`, `GET /tesda/printTORall`
- **Print honorable dismissal certificates:** `GET /tesda/pdf/honorable_dismissal/{id}`
- **Create students:** `POST /tesda/addStudent`
- **Enroll students:** `POST /tesda/enrollment/save`
- **Delete students:** `DELETE /tesda/delete-student/{id}`
- **Delete enrollment records:** `POST /tesda/enrollment/delete`
- **Modify enrollment:** `PUT /tesda/update-student-enrolled/{id}`
- **Delete signatories:** `DELETE /tesda/delete-signatories/{id}`
- **Submit trainer grades:** `POST /tesda/trainer/systemgrades/submit_grades`
- **Delete batch schedules, course types, competencies**

**Fix:** Same as BK-01 — one line change:
```php
protected function mapTesdaRoutes()
{
    Route::prefix('tesda')
        ->middleware(['web', 'auth'])    // add 'auth', and role-specific middleware
        ->group(base_path('routes/tesda.php'));
}
```

---

### AUX-02 — HIGH — Admission: Unauthenticated IDOR on `update-student-info`
**File:** `GuidanceController/AdmissionController.php` — `student_info_update()`, `routes/admission.php`  
**Category:** Insecure Direct Object Reference (OWASP A01)

`POST /admission/update-student-info` accepts an `id` parameter from the request with no ownership verification:

```php
public function student_info_update(Request $request)
{
    // validates fields but NOT ownership
    $student = DB::table('admission_student_information')
        ->where('id', $request->id)    // ← attacker-controlled
        ->where('deleted', 0)
        ->first();

    DB::table('admission_student_information')
        ->where('id', $request->id)
        ->update($request->except(['_token', 'id']));
}
```

Any internet visitor (no login required) who knows an applicant's sequential integer ID can overwrite their name, contact number, date of birth, grade level, exam slot, and academic program. The applicant will then take the wrong exam type or have their registration corrupted.

---

### AUX-03 — HIGH — Admission: Exam Answers Manipulable by Any Internet Visitor
**File:** `GuidanceController/AdmissionController.php` — `save_answer()`, `routes/admission.php`  
**Category:** Broken Access Control / Exam Integrity (OWASP A01)

`GET /admission/save-answer` stores an exam answer for a given `studid` and `questionid`, both supplied by the caller:

```php
public function save_answer(Request $request)
{
    $validatedData = $request->validate([
        'id'     => 'required|integer',    // question ID — attacker-controlled
        'studid' => 'required|integer',    // student ID — attacker-controlled
        'answer' => 'required|string'
    ]);

    DB::table('admission_answer_history')
        ->updateOrInsert(
            ['questionid' => $request->id, 'studid' => $request->studid],
            ['answer' => $request->answer, 'status' => $request->status, 'points' => $request->points]
        );
}
```

Any internet visitor can:
1. Submit answers for any student's exam by providing their `studid`
2. Override correct answers with wrong ones to lower a target student's score
3. Submit answers with `points` pre-filled to inflate a student's score (since `points` is caller-supplied and not server-validated against the answer key)

**Additionally:** This is a GET route (`Route::get('/save-answer', ...)`), meaning exam answers are logged in web server access logs, browser history, and proxy caches as URL query strings.

---

### AUX-04 — HIGH — Admission: Mass Assignment in `student_info_save` — Attacker Controls All Inserted Fields
**File:** `GuidanceController/AdmissionController.php` — `student_info_save()`  
**Category:** Mass Assignment (OWASP A04)

```php
$studentId = DB::table('admission_student_information')
    ->insertGetId(
        $request->except(['_token']) + [
            'created_at' => now('Asia/Manila'),
            'poolingnumber' => $poolingnumber,
            'sy' => DB::table('sy')->where('isactive', 1)->value('id'),
        ]
    );
```

`$request->except(['_token'])` passes **all POST fields except `_token`** directly into the INSERT. Any column in `admission_student_information` that is not explicitly excluded can be set by the caller. If the table has columns like `status`, `accepted`, `verified`, `deleted`, or `isactive`, an attacker can set them directly at registration time — for example, submitting `status=2` to skip the verification step or `accepted=1` to self-accept their application.

---

### AUX-05 — MEDIUM — Guidance: Any Authenticated User Can Delete Exam Setup and Referrals (No Role Check)
**File:** `routes/guidance.php`  
**Category:** Broken Access Control (OWASP A01)

All guidance routes are under `['auth']` only. There is no `isGuidance` or equivalent middleware. Any student, teacher, or cashier who is logged in can call:

```bash
GET /guidance/delete-testquestion?id=1   → deletes exam question ID 1
GET /guidance/delete-category?id=2       → deletes exam category
GET /guidance/delete-examdate?id=3       → deletes scheduled exam date
GET /guidance/delete-passingrate?id=4    → deletes passing rate configuration
GET /guidance/delete-referral?id=5       → deletes a counseling referral record
GET /guidance/activatePassingrate?id=6   → activates any passing rate setup
```

A student who discovers these endpoints can delete all upcoming exam dates (preventing other applicants from scheduling), destroy referral records, or corrupt the passing rate configuration.

**Additionally:** All these operations use GET routes — a malicious link or `<img>` tag CSRF attack can trigger them silently when any authenticated user visits a page.

---

### AUX-06 — MEDIUM — Document Tracking: Any Authenticated User Can Forward, Reject, or Close Any Document
**File:** `routes/documenttracking.php`, `DocumentTrackingController/TrackingController.php`  
**Category:** Broken Access Control / Missing Ownership Check (OWASP A01)

All document operations are under `['auth']` with no role or ownership check:

```php
Route::get('/forward-document', 'TrackingController@forwardDocument');
Route::get('/reject-document',  'TrackingController@rejectDocument');
Route::get('/close-document',   'TrackingController@closeDocument');
Route::get('/receive-document', 'TrackingController@receiveDocument');
```

Any authenticated user can:
- Forward any document to any signatory (`forwardDocument`) — bypasses the defined routing workflow
- Reject any document (`rejectDocument`) — without being the intended recipient
- Close any document permanently (`closeDocument`) — no ownership check against the document's creator or current holder

These are all GET routes — CSRF attack via `<img src="/doctrack/close-document?id=99">` silently closes any document when an authenticated user loads a malicious page.

---

### AUX-07 — LOW — Library: `pinbook` Is a State-Changing GET Without Authentication
**File:** `routes/library.php`  
**Category:** Cross-Site Request Forgery risk (OWASP A01)

```php
Route::get('/pinbook', 'LibraryController\LibraryBookController@pin_book');
```

`GET /library/pinbook` modifies database state (pins a book for a user) without requiring authentication. This is a minor finding — pinned books are low-sensitivity — but it demonstrates the recurring GET-for-state-change pattern.

---

## 4. Backend Bug Findings

---

### BUG-AUX-01 — `diagnostic_view()` Calls `->first()` Without Null Check, Then Immediately Accesses Property
**File:** `GuidanceController/AdmissionController.php` — `diagnostic_view()`  
**Severity:** Medium Bug

```php
$result = DB::table('admission_student_information')
    ->where('poolingnumber', $request->poolingnumber)
    ->...->first();

if ($result->acadprog_id == 6) { ... }   // ← crashes if $result is null

// The null check comes AFTER the property access:
if (!$result) {
    return redirect()->back()->with('error', 'Student not found.');
}
```

If `poolingnumber` doesn't match any record, `->first()` returns null. The `$result->acadprog_id` access throws a fatal error **before** the `if (!$result)` guard is reached. Any applicant who submits an invalid pooling number gets a 500 error.

---

### BUG-AUX-02 — TESDA `seedtesda` Route Runs `db:seed --force` With Minimal Auth Check
**File:** `routes/tesda.php`  
**Severity:** High Bug

```php
Route::get('/seedtesda', function () {
    if (!Auth::check()) {
        abort(403, 'Unauthorized');
    }
    Artisan::call('db:seed --force');
    return 'TesdaSeeder has been executed successfully!';
});
```

This route executes `db:seed --force` — which runs all database seeders, potentially overwriting production data — with only a basic `Auth::check()` guard. Any authenticated user of any role can visit `GET /tesda/seedtesda` and trigger a full database seed operation. There is no superadmin check, no production environment guard, and no confirmation step.

---

## 5. Fix Recommendations

### Immediate (Critical)
1. **AUX-01:** Add `['web', 'auth']` to `mapTesdaRoutes()` in `RouteServiceProvider.php`. Further restrict to a TESDA-specific role if one exists.
2. **AUX-02 / AUX-03:** Admission `update-student-info` must verify that the caller owns the record (via session token issued during registration). `save-answer` must verify `studid` matches the session's registered applicant ID — not an arbitrary attacker-supplied value.
3. **BUG-AUX-02:** Remove `GET /tesda/seedtesda` entirely from production. Database seeding is a deployment-time operation only.

### Short-Term
4. **AUX-04:** Replace `$request->except(['_token'])` with an explicit array of allowed fields in `student_info_save()`.
5. **AUX-05:** Add guidance-specific middleware (or at minimum check `auth()->user()->type` against the guidance officer role) before all exam setup and referral management routes.
6. **AUX-06:** Add an ownership/signatory check in document tracking routes — verify that `auth()->user()` is the current document holder or designated signatory before allowing forward/reject/close.

### Hardening
7. **AUX-03:** Move `save-answer` from GET to POST; validate `points` server-side against the answer key rather than accepting caller-supplied values.
8. **AUX-05 / AUX-06:** Convert all state-changing guidance and document tracking routes from GET to POST.
9. **BUG-AUX-01:** Move the `if (!$result)` null check in `diagnostic_view()` to before the first property access.
