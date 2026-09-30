# Work Log — es_ldcu Security Review
**Date:** June 3, 2026  
**Analyst:** Internal Red Team  
**Session Focus:** Student Portal Analysis

---

## 09:02 — Started the day. Confirmed analysis docs location.

Checked the workspace and found the `Analysis Docs/` folder at the root. Previous sessions already produced 9 documents (SuperAdmin × 3, Teacher × 3, Finance × 3 / CashierV2 × 3). Made note to follow same naming convention.

Quick check of what's already in the folder:
- `SUPERADMIN_CODE_REVIEW.md`, `SUPERADMIN_EXECUTIVE_SUMMARY.md`, `SUPERADMIN_POC.md` ✅
- `TEACHER_CODE_REVIEW.md`, `TEACHER_EXECUTIVE_SUMMARY.md`, `TEACHER_POC.md` ✅
- `CASHIERV2_*`, `FINANCEV2_*` (done by others) ✅

---

## 09:05 — Identified student controller files.

Navigated to `app/Http/Controllers/StudentControllers/`. Found 8 files:
1. `StudentController.php` — looks like the main hub (~1700+ lines)
2. `EnrollmentInformation.php` — large, handles billing/schedule/photo
3. `BillingInformationController.php` — ledger and financial history
4. `ScholarshipController.php` — scholarship application features
5. `StudentBehaviorController.php` — behavior records (small)
6. `StudentGradeEvaluation.php` — college grade eval
7. `StudentSeverEventController.php` — server-sent events for attendance
8. `StudentInformation.php` — admin-facing, not student portal

---

## 09:08 — Read student middleware.

Checked `AuthenticateStudent.php`. It's clean — strict `type==7` check, no bypass paths unlike `AuthenticateTeacher` which had the `currentPortal` session bypass we found last session. This means `isStudent` is harder to bypass directly.

Reminded myself: even if the middleware is correct, the question is always "what routes **skip** the middleware?"

---

## 09:12 — Started tracing routes in web.php.

Grepped for `StudentControllers` in web.php. Got back 60+ matches. Had to look at the surrounding middleware groups carefully. Started reading from line 100 downward.

Found 3 routes at lines 109–111 with **no middleware at all** and a comment:
> `// Public mobile API — no session auth required; studid passed as query param`

Red flag. The developer explicitly disabled auth on these. Need to confirm what data they return.

---

## 09:18 — Confirmed unauthenticated IDOR on mobile API.

Read `BillingInformationController@getStudentLedger`:
- Takes `studid` directly from `$request->input('studid')` 
- Returns full financial data: name, program, balance, school fees, ledger
- No auth check if `studid` is provided (the `auth()->check()` block only runs when `studid` is null)

Same pattern in `EnrollmentInformation@class_schedule` and `@enrollment_reportcard`.

This is a clean unauthenticated IDOR — no account needed, just guess sequential studid values. Flagged as ST-03 and ST-04.

---

## 09:25 — Found the SMS injection endpoint.

Was scanning through route groups and spotted `POST /student/notify_individual_student` under `['cors']` only. Checked the `Cor.php` middleware — it only adds `Access-Control-Allow-Origin: *` headers. Zero authentication.

Checked the method: inserts directly into `tapbunker` with `receiver = $request->get('phone')`. The message is hardcoded to the school's enrollment announcement. But the phone number is fully attacker-controlled.

Anyone in the world can send that enrollment SMS to any number, repeatedly. This will exhaust SMS credits and could be used to harass people.

Route comment: `"// Added by clyde"`. Classic — dev shortcut, `cors`-only route, left in production. Flagged as ST-02.

---

## 09:32 — Read ScholarshipController.php.

Most methods are normal. Got to `uploadrequirement()`:

```php
$newFileName = time() . '.' . $file->getClientOriginalExtension();
$destinationPath = public_path('scholarship/');
$file->move($destinationPath, $newFileName);
```

No validation. Extension from `getClientOriginalExtension()` is 100% attacker-controlled. File goes to `public/scholarship/` — web-accessible. This is the exact same file upload RCE pattern as `PoC-9` from the SuperAdmin review (PreSchoolGrading controller). But this one is under `['auth']` only, meaning any user type (teacher, student, cashier) can upload a PHP shell.

Also found `delscholarship()` — no ownership check. Any authenticated user can delete any scholarship application by ID. Flagged ST-06.

---

## 09:40 — Checked `StudentController.php` for pre-enrollment password logging.

Was reading `student_preenrollment_submit()` around line 1494. Found:

```php
DB::table('updatelogs')->insert([
    'type' => 1,
    'sql'  => $logs . $request->get('password'),  // ← password appended to SQL log
    ...
]);
```

The `submitinfo()` method had this same pattern but it was **commented out**. In `student_preenrollment_submit()`, it is **NOT commented out**. So student passwords submitted via the pre-enrollment form get stored in plaintext in `updatelogs`. Flagged as ST-05.

---

## 09:48 — Checked survey form routes — no middleware.

Lines 242–243 in web.php, both survey routes are completely outside any middleware group:
```php
Route::get('/student/submit/form', 'StudentControllers\StudentController@submitSurvey');
Route::get('/student/view/surveyForm', 'StudentControllers\StudentController@surveyForm');
```

The method immediately calls `auth()->user()->id` so unauthenticated access causes a 500. Not directly exploitable, but it's a missing middleware configuration — a reminder that security by 500-error is not real security. If error handling is ever relaxed, this becomes a data write endpoint (it updates `studinfo` and inserts into `leasf`). Flagged as ST-08.

---

## 09:54 — Read `StudentSeverEventController.php`.

The SSE responses build HTML by concatenating raw database values:
```php
$datastring .= '<td width=20%>' . $item->subjcode . '</td>';
```

These are admin-set values so the practical XSS risk is low. But flagged as FE-ST-01 for completeness.

Also noted the `tapstate({id})` route — the `$studentInfo` parameter is passed to `AttendanceReport::todaySchoolAttendance()`. An authenticated student could check another student's tap data by guessing their studid. Flagged as BUG-ST-04.

---

## 10:02 — Looked at the `['auth']`-only block carefully (lines 113–150).

This block has routes that should be student-only. Any authenticated user can call them. The controllers try to self-scope via:
```php
str_replace('S', '', auth()->user()->email)
```
But for non-student accounts (teachers, admins) this either fails with a 500 or produces unintended lookups. Not a clean self-scope. Flagged as ST-07.

Also noticed the pre-enrollment routes are defined **twice** in the same middleware group (lines 205–211 and 222–228). Laravel silently ignores the duplicate. Flagged as ST-10.

---

## 10:10 — Finished reading all 8 controllers. Started documenting.

Total findings identified:
- ST-01: RCE via file upload (scholarship) — CRITICAL
- ST-02: Unauthenticated SMS injection — CRITICAL  
- ST-03: Unauthenticated financial IDOR — HIGH
- ST-04: Unauthenticated grades IDOR — HIGH
- ST-05: Password in audit log — HIGH
- ST-06: Scholarship delete IDOR — HIGH
- ST-07: Missing isStudent on core routes — MEDIUM
- ST-08: Survey routes no auth — MEDIUM
- ST-09: Photo upload no content validation — LOW
- ST-10: Duplicate route definitions — LOW
- BUG-ST-01 through BUG-ST-05, FE-ST-01

---

## 10:22 — Wrote `STUDENT_CODE_REVIEW.md`.

Full line-by-line documentation of all 10 findings with code excerpts, CVSS scores, and fix recommendations. Also documented 5 backend bugs and 1 frontend bug. Included the route mapping table and middleware analysis.

---

## 10:37 — Wrote `STUDENT_EXECUTIVE_SUMMARY.md`.

Risk table, 4 attack chains (A through D), comparison to other portals, compliance impact (RA 10173, FERPA, PCI-DSS), and remediation roadmap. The key insight captured: Student portal is the only module with **fully unauthenticated** attack surface — no account needed to access financial data, grades, and class schedules.

---

## 10:51 — Wrote `STUDENT_POC.md`.

7 PoCs with working curl/Python exploits and fix code for each:
- PoC-ST-1: 4-step RCE via scholarship upload → webshell → .env dump
- PoC-ST-2: Automated SMS flood script
- PoC-ST-3: Python mass financial data extraction with CSV output
- PoC-ST-4: Grade dump via unauthenticated API
- PoC-ST-5: SQL to extract plaintext passwords from updatelogs
- PoC-ST-6: Bash loop to delete all scholarship applications
- PoC-ST-7: Demonstration of privilege confusion on auth-only routes

---

## 10:58 — Writing this work log.

Wrapping up the student portal session. All 3 analysis documents created and verified.

**Key takeaways from this session:**
1. The unauthenticated mobile API (`/api/mobile/*`) is the single worst issue — it was an intentional design decision (comment in code confirms it), but nobody assessed the privacy implications
2. The scholarship file upload RCE follows the exact same unvalidated extension pattern as the SuperAdmin `PreSchoolGrading` finding — suggests this is a copy-paste pattern used by multiple developers across the codebase
3. The SMS injection is a `cors`-only dev endpoint left in production — the "Added by clyde" comment is a clue that no formal code review was done
4. Password logging in `updatelogs` is a recurring pattern — similar commented-out code appears in `submitinfo()` suggesting it was once used everywhere and only partially cleaned up

**Next session:** Principal portal or Registrar portal (pending direction from user)

---

*Log created: June 3, 2026 — es_ldcu Student Portal Security Review*
