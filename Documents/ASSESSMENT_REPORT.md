# Security Code Review — Full Assessment Report
**Project:** `es_ldcu` — School Management System  
**Prepared by:** Internal Red Team  
**Classification:** Internal — Confidential

---

## Overall Summary

| Metric | Count |
|---|---|
| **Modules Reviewed** | 11 |
| **Total Security Findings** | 105 |
| **Critical** | 17 |
| **High** | 35 |
| **Medium** | 27 |
| **Low / Info** | 26 |
| **Backend Bugs** | 25 |
| **Frontend Issues** | 4 |

> Finance V2 and Cashier V2 were reviewed by a separate team member. All other modules were reviewed by the primary analyst.

---

## Module Overview

| # | Module | Risk | Findings | Critical | High | Medium | Low |
|---|---|---|---|---|---|---|---|
| 1 | SuperAdmin | **CRITICAL** | 12 | 2 | 4 | 4 | 2 |
| 2 | Teacher | **CRITICAL** | 15 | 1 | 5 | 5 | 4 |
| 3 | Finance V2 | **CRITICAL** | 9 | 4 | 3 | 2 | 0 |
| 4 | Cashier V2 | **CRITICAL** | 14 | 2 | 5 | 3 | 4 |
| 5 | Student | **CRITICAL** | 10 | 1 | 3 | 3 | 3 |
| 6 | Registrar | **CRITICAL** | 9 + 4 bugs | 2 | 3 | 2 | 2 |
| 7 | College (CT/CP/Dean/ECR) | **CRITICAL** | 10 + 5 bugs | 1 | 5 | 2 | 2 |
| 8 | Parent | HIGH | 7 + 3 bugs | 0 | 2 | 2 | 3 |
| 9 | Admin | **CRITICAL** | 8 + 2 bugs | 3 | 4 | 1 | 0 |
| 10 | Principal | **CRITICAL** | 6 + 7 bugs + 4 FE | 2 | 2 | 2 | 0 |
| 11 | Director | **CRITICAL** | 6 + 4 bugs | 3 | 2 | 1 | 0 |

---

---

## Module 1 — SuperAdmin Portal

**Risk Level:** CRITICAL  
**Scope:** `SuperAdminController/` (17 controllers), `AuthenticateSuperAdmin.php`, all superadmin route groups in `routes/web.php`

### Security Findings

| ID | Severity | Title |
|---|---|---|
| SA-01 | **CRITICAL** | Arbitrary file upload via school logo endpoint — web shell upload possible |
| SA-02 | **CRITICAL** | `currentPortal` session flag bypass — access SuperAdmin portal by setting session variable |
| SA-03 | HIGH | Dynamic SQL column injection in `updatemodulestatus` — attacker-controlled column name |
| SA-04 | HIGH | Unauthenticated user enumeration via `validate_student_name` |
| SA-05 | HIGH | Session impersonation — `switchUser` allows SuperAdmin to permanently impersonate any account |
| SA-06 | HIGH | File inclusion path traversal in report template loading |
| SA-07 | MEDIUM | Mass assignment exposure in student profile update |
| SA-08 | MEDIUM | Unvalidated redirect after login |
| SA-09 | MEDIUM | Sensitive data in Laravel logs (student IDs, grades) |
| SA-10 | MEDIUM | CSRF not enforced on destructive GET routes |
| SA-11 | LOW | School information endpoint returns internal system metadata |
| SA-12 | LOW | Error messages expose table/column names in query failures |

### Finding Details

**SA-01 — CRITICAL — Arbitrary File Upload (Web Shell)**  
The school logo upload endpoint accepts files without server-side MIME validation. Only the client-supplied content-type or file extension is checked. An attacker with access to the SuperAdmin portal can upload a `.php` file disguised as a logo image, then access it via the web-accessible `public/` path to execute arbitrary PHP code on the server.

**SA-02 — CRITICAL — `currentPortal` Session Bypass**  
`AuthenticateSuperAdmin` checks `Session::get('currentPortal') == 1` alongside `auth()->user()->type == 17`. Any authenticated user (including a student or teacher) who manipulates their `currentPortal` session variable to `1` gains SuperAdmin-level route access. This is exploitable via any endpoint that modifies session state.

**SA-03 — HIGH — Dynamic SQL Column Injection**  
`updatemodulestatus` accepts a column name directly from the request parameter and passes it into an Eloquent `update()` call as a key. The column name is never validated against an allowlist. An attacker can write to arbitrary columns in the `modules` table, including privilege-related fields.

**SA-04 — HIGH — Unauthenticated User Enumeration**  
`validate_student_name` is accessible without authentication and returns whether a given name exists in the student database. An attacker can enumerate student names and IDs to confirm enrollment status, supporting subsequent targeted attacks.

**SA-05 — HIGH — Session Impersonation via `switchUser`**  
SuperAdmins can permanently switch their session to act as any other user account. There is no re-authentication step and no audit trail beyond a basic log entry. Once switched, the session persists until manually reverted — allowing prolonged impersonation.

**SA-06 — HIGH — Path Traversal in Report Template Loading**  
Report template file paths are partially constructed from request parameters. Insufficient sanitization allows traversal sequences (`../`) to reference files outside the intended template directory, potentially reading sensitive files from the server filesystem.

### Backend Bugs
- File upload does not validate MIME type server-side; only client-supplied extension is checked
- Module status update uses raw column name from request parameter with no allowlist; no transaction wrapping on multi-row updates

---

## Module 2 — Teacher Portal

**Risk Level:** CRITICAL  
**Scope:** `TeacherControllers/` (11 controllers), `AuthenticateTeacher.php`, all teacher route groups

### Security Findings

| ID | Severity | Title |
|---|---|---|
| T-01 | **CRITICAL** | `GET /gradesdetail/update` — unauthenticated grade detail modification for any student |
| T-02 | HIGH | Unauthenticated deportment grade update — any user sets conduct grades |
| T-03 | HIGH | `currentPortal` session bypass on `isTeacher` middleware |
| T-04 | HIGH | Horizontal privilege escalation — teacher reads/modifies grades outside their assigned sections |
| T-05 | HIGH | Grade transmutation table writable by any authenticated user |
| T-06 | HIGH | Class schedule delete with no ownership check (IDOR) |
| T-07 | MEDIUM | Attendance records modifiable by non-assigned teacher |
| T-08 | MEDIUM | Subject assignment endpoints under `['auth']` only |
| T-09 | MEDIUM | Student list endpoint returns data for unenrolled students |
| T-10 | MEDIUM | GET requests used for all state-changing operations (no CSRF barrier) |
| T-11 | MEDIUM | File export (Excel/PDF) with no pagination — DoS via large dataset |
| T-12 | LOW | Teacher TID exposed in enrollment list response |
| T-13 | LOW | Grade submission timestamp writable from client |
| T-14 | LOW | No rate limiting on grade submission endpoint |
| T-15 | LOW | Unused debug parameters accepted in grading endpoints |

### Finding Details

**T-01 — CRITICAL — Unauthenticated Grade Detail Modification**  
`GET /gradesdetail/update` is registered outside all middleware groups. It accepts `gradeid`, `quarter`, and `value` from query parameters and directly updates the `gradesdetail` table. There is no authentication check, no ownership verification, and no audit trail. Any internet visitor can modify any student's component grade by knowing or guessing a `gradeid`.

**T-02 — HIGH — Unauthenticated Deportment Grade Update**  
The endpoint that updates student conduct/deportment grades is similarly outside all middleware. An unauthenticated request with a valid `studid` and `quarter` sets the deportment score to an attacker-supplied value.

**T-03 — HIGH — `currentPortal` Bypass**  
`isTeacher` middleware accepts `Session::get('currentPortal') == 1` as an alternative to `type == 1`. A student or parent who sets this session variable bypasses the teacher role check and accesses all teacher-gated endpoints.

**T-04 — HIGH — Cross-Section Grade Access**  
Grade read and write endpoints for teachers accept arbitrary `sectionid` and `subjid` parameters without verifying that the authenticated teacher is actually assigned to that section and subject. A teacher can read and modify grades for sections they do not teach.

**T-05 — HIGH — Grade Transmutation Table Writable by Any Auth User**  
The transmutation setup (which maps raw scores to final grades) is writable via `['auth']`-only endpoints. Any logged-in user can alter the grading scale for any subject, affecting how all scores in that subject are converted to final grades.

### Backend Bugs
- Grade submission timestamp accepted from client — timestamps can be backdated or future-dated
- Attendance update endpoints use GET method with no CSRF protection
- Excel/PDF export endpoints do not cap record count — requesting all records triggers memory exhaustion

---

## Module 3 — Finance V2

**Risk Level:** CRITICAL  
**Scope:** `Financev2Controller/`, billing, adjustments, accounts receivable, PDF generation  
*(Reviewed by separate team member)*

### Security Findings

| ID | Severity | Title |
|---|---|---|
| FV2-01 | **CRITICAL** | Symmetric AES encryption key exposed in frontend `<meta>` tag — all masked financial data decryptable |
| FV2-02 | **CRITICAL** | DomPDF `enable_php = true` across all PDF controllers — latent RCE if any template data is unescaped |
| FV2-03 | **CRITICAL** | Student financial data sent to third-party AI service without consent — RA 10173 violation |
| FV2-04 | **CRITICAL** | Financial void/reversal PIN bypass — PIN check screen exists but underlying action executes without verification |
| FV2-05 | HIGH | Plaintext PIN storage in `fin_pin` table — any DB access exposes all void authorization PINs |
| FV2-06 | HIGH | Accounts Receivable grand total uses iterative N+1 DB calls — crashes under peak student load |
| FV2-07 | HIGH | Stored XSS — item names and student names rendered unescaped in Finance staff view |
| FV2-08 | MEDIUM | Missing ownership check on billing record access (IDOR between students) |
| FV2-09 | MEDIUM | Finance adjustment history filterable by any student ID without role check |

### Finding Details

**FV2-01 — CRITICAL — AES Key in `<meta>` Tag**  
The FinanceV2 module uses client-side AES encryption to mask financial figures in the browser. The encryption key is embedded in a `<meta>` tag in the page source, visible to any user who inspects the HTML. Anyone who views the page source can decrypt all "masked" financial data displayed in the module.

**FV2-02 — CRITICAL — DomPDF PHP Execution Enabled**  
`enable_php = true` and `isPhpEnabled = true` are set in every PDF-generating controller in the module. This setting allows PHP code within PDF HTML templates to execute with full server privileges. If any Blade template uses `{!! $variable !!}` with user-controlled data (several instances of `{!! $signatoriesHtml !!}` were found), it becomes a direct Remote Code Execution vector. The current template's `getSignatoriesHtml()` method uses `htmlspecialchars()`, but this is one developer oversight away from full compromise.

**FV2-03 — CRITICAL — Student PII Sent to Third-Party AI**  
An AI assistant feature in the Finance module captures whatever financial data is currently visible on screen — including student names, IDs, balances, and payment history — and transmits it to a free external AI service. No data processing agreement exists. This is a likely violation of RA 10173 (Data Privacy Act of the Philippines) and any applicable FERPA obligations for US-affiliated accreditation bodies.

**FV2-04 — CRITICAL — Void/Reversal PIN Bypass**  
The PIN entry dialog for financial void and reversal operations presents a UI that suggests PIN verification is required before the action proceeds. However, the backend action endpoint executes immediately upon request regardless of whether a PIN was submitted or verified. The PIN check is a frontend-only illusion.

### Backend Bugs
- Accounts receivable totals calculated via PHP loop of individual DB queries (N+1 pattern) instead of a single aggregate query; fails for schools with >500 enrolled students
- PIN verification logic is entirely disconnected from the protected action at the controller level

---

## Module 4 — Cashier V2

**Risk Level:** CRITICAL  
**Scope:** `CashierV2Controller/`, payment processing, official receipt issuance, void/suspension, queue display  
*(Reviewed by separate team member)*

### Security Findings

| ID | Severity | Title |
|---|---|---|
| CV2-01 | **CRITICAL** | `serverPrint` spawns `mshta.exe` via `shell_exec` — OS command exposure, no cashier-role check |
| CV2-02 | **CRITICAL** | DomPDF `enable_php = true` in 3 PDF-print methods — latent RCE |
| CV2-03 | HIGH | Zero role-based access control — any authenticated user can process payments, void, delete |
| CV2-04 | HIGH | Plaintext PIN storage (`chrng_pin.pin_code`) — any DB access exposes all void authorization PINs |
| CV2-05 | HIGH | IDOR — `serverPrint` allows any authenticated user to print any receipt by OR number |
| CV2-06 | HIGH | IDOR — suspended sale DELETE has no ownership check |
| CV2-07 | HIGH | Stored DOM XSS — `displayNonTuitionItems()` injects unsanitized DB values into HTML |
| CV2-08 | HIGH | Stored DOM XSS — `loadSuspendedSales()` injects `customer_name`/`student_name` into HTML |
| CV2-09 | MEDIUM | AES key exposed in `<meta>` tag of `app2.blade.php` — same shared key as Finance V2 |
| CV2-10 | MEDIUM | `$e->getMessage()` returned in 20+ JSON error responses — DB query and stack info leaked |
| CV2-11 | MEDIUM | `students()` endpoint — `per_page` parameter uncapped — resource exhaustion |
| CV2-12 | LOW | Queue display routes expose queue numbers publicly (accepted design, but noted) |
| CV2-13 | LOW | `DiscountsContoller.php` filename typo — dead mutation methods not routed |
| CV2-14 | LOW | 414 `console.log()` statements leak payment amounts, student IDs, and OR numbers in browser console |

### Finding Details

**CV2-01 — CRITICAL — OS Command Execution via `serverPrint`**  
`serverPrint()` uses `shell_exec()` or `popen()` to launch `mshta.exe` (Windows HTML Application Host) on the server to silently print receipts. The endpoint accepts a receipt ID as a parameter, performs no cashier-role check, and invokes a legacy Windows scripting engine. `mshta.exe` is a well-known Living-off-the-Land binary with a long exploitation history — spawning it from a web-facing PHP process on a production server is an unacceptable risk independent of the access control failure.

**CV2-03 — HIGH — No Role-Based Access Control**  
The `isCashier` middleware exists and is registered in `Kernel.php`. However, cashier transaction endpoints (process payment, void, delete suspended sale, generate OR) use only `['auth']`. Any teacher, registrar, or student who knows the endpoint URLs can post transactions to the official receipt ledger.

**CV2-07 / CV2-08 — HIGH — Stored DOM XSS**  
Both `displayNonTuitionItems()` and `loadSuspendedSales()` build HTML strings by concatenating raw database values (item names, student names) without `htmlspecialchars()`. A student or staff member with a name or item description containing `<script>` tags causes that script to execute in the browser of any cashier who loads the affected page.

### Backend Bugs
- 414 `console.log()` calls in production JavaScript — payment amounts, student IDs, and OR numbers visible to any user who opens browser developer tools
- `DiscountsContoller.php` typo in filename means dead code is present but unreachable via routes

---

## Module 5 — Student Portal

**Risk Level:** CRITICAL  
**Scope:** `StudentControllers/` (8 files), `AuthenticateStudent.php`, all student route groups

### Security Findings

| ID | Severity | Title |
|---|---|---|
| S-01 | **CRITICAL** | IDOR in billing ledger — students access other students' full payment histories by manipulating `studid` |
| S-02 | HIGH | Unauthenticated SMS notification trigger — external party can spam students |
| S-03 | HIGH | Photo upload stores file via base64 decode with no server-side MIME validation |
| S-04 | HIGH | Sensitive academic schedule and grades returned without student ownership verification |
| S-05 | MEDIUM | `currentPortal` session bypass on `isStudent` middleware |
| S-06 | MEDIUM | Scholarship application accepts arbitrary file type in document upload |
| S-07 | MEDIUM | Server-sent events (attendance feed) accessible to any authenticated session |
| S-08 | LOW | Student SID exposed in all enrollment response objects |
| S-09 | LOW | Enrollment history paginated endpoint returns data for withdrawn students |
| S-10 | LOW | GET used for student profile update — no CSRF protection |

### Finding Details

**S-01 — CRITICAL — IDOR in Billing Ledger**  
The billing history endpoint accepts `studid` as a query parameter and returns that student's complete payment ledger — all charges, payments, discounts, and balances. There is no check that `studid` matches the authenticated session's student. A logged-in student can query any other student's financial records by incrementing the `studid` value.

**S-02 — HIGH — Unauthenticated SMS Trigger**  
An SMS notification endpoint is registered outside all middleware groups. It accepts a student ID and message type and triggers an SMS via the school's SMS gateway. Any internet visitor can call this endpoint to send arbitrary-count SMS messages to any enrolled student, incurring SMS charges and harassing students.

**S-03 — HIGH — Base64 Photo Upload Without MIME Validation**  
The student photo upload endpoint accepts a base64-encoded file. It decodes the base64 string and writes it to the filesystem without checking the actual file content or MIME type. If the submitted base64 encodes a `.php` file and the storage path is web-accessible, the uploaded file can be accessed directly to execute PHP code.

### Backend Bugs
- Attendance SSE stream does not terminate on session expiry; abandoned connections accumulate
- Base64 photo upload writes the file before validating content type; partial cleanup on failure can leave orphaned files

---

## Module 6 — Registrar Portal

**Risk Level:** CRITICAL  
**Scope:** `RegistrarControllers/` (legacy, 10+ files), `RegistrarV2Controller/` (50+ controllers), `AuthenticateRegistrar.php`, `routes/registrarv2.php`

### Security Findings

| ID | Severity | Title |
|---|---|---|
| R-01 | **CRITICAL** | `GET /debugger/fix-account-conflict` — unauthenticated; resets and recreates student login accounts with default password `123456` — any internet visitor can log in as any student |
| R-02 | **CRITICAL** | Unauthenticated full student database dump via `PreRegistrationController` |
| R-03 | HIGH | Entire RegistrarV2 module (50+ controllers, college/course/grading CRUD) under `['auth']` only |
| R-04 | HIGH | Commented-out authentication guard in `PreRegistrationControllerV2` — `early/enrollment/submit` executes without any auth check |
| R-05 | HIGH | Stored XSS — student names rendered unescaped in registrar search results |
| R-06 | MEDIUM | Debug SF10 endpoint with hardcoded private student data accessible in production |
| R-07 | MEDIUM | RegistrarV2 academic configuration CRUD (delete college, delete course, reset grading period) under `['auth']` only |
| R-08 | LOW | Photo upload in student requirements does not validate image dimensions |
| R-09 | LOW | Registrar session reused across multiple academic year contexts without re-validation |

### Finding Details

**R-01 — CRITICAL — Unauthenticated Account Reset via Debug Endpoint**  
`/debugger/fix-account-conflict` was left in production with no authentication. It accepts a student ID, looks up the student's record, deletes any conflicting `users` table entries, and creates a new login with password `123456`. After calling this endpoint with a known student ID, the attacker can log in as that student with the predictable default password.

**R-02 — CRITICAL — Unauthenticated Student Database Dump**  
A `PreRegistrationController` endpoint returns paginated student records (name, ID, address, birthdate, contact information) without requiring authentication. The entire enrolled student database can be exported in batches by incrementing the `page` parameter.

**R-03 — HIGH — RegistrarV2 50+ Controllers Under `['auth']` Only**  
The entire RegistrarV2 module — which includes CRUD for colleges, courses, grading periods, SF10 templates, student requirements categories, and enrollment configurations — is registered in `routes/registrarv2.php` under the `web` middleware group only. `RouteServiceProvider` applies no role middleware. Any authenticated user (a student, teacher, or cashier) can call destructive operations such as course deletion or grading period reset.

**R-05 — HIGH — Stored XSS in Registrar Search**  
The registrar student search results are rendered using unescaped Blade output (`{!! $student->name !!}` or equivalent). If a student's name contains HTML tags (entered during registration), those tags execute as JavaScript in the browser of any registrar staff member who searches for that student.

### Backend Bugs (4)
- Missing JOIN condition in student search query causes cross-student record leakage when multiple students share similar names
- SF10 debug route returns hardcoded private test student data (name, section, grades) in production
- `RouteServiceProvider` maps RegistrarV2 routes to `web` middleware group without appending `isRegistrar`
- Pre-registration form allows duplicate student ID submission with no uniqueness check at the controller level

---

## Module 7 — College Portal (CT / CP / Dean / ECR)

**Risk Level:** CRITICAL  
**Scope:** `CTController/` (~3,400 lines), `CPControllers/`, `DeanControllers/` (8 files), `CollegeECR.php`, role middleware for CT/CP/Dean

### Security Findings

| ID | Severity | Title |
|---|---|---|
| C-01 | **CRITICAL** | `GET /teacher/update/hps` fully unauthenticated with dynamic column injection — any internet visitor corrupts any student's grade component |
| C-02 | HIGH | `updategrades` and `updateigfg` — K-12 grade records modifiable by any authenticated user |
| C-03 | HIGH | ECR grade approval and posting under `['auth']` only — a student can approve and post their own final college grade |
| C-04 | HIGH | Entire Dean module (curriculum management, student loading, prospectus) under `['auth']` only |
| C-05 | HIGH | College class schedule creation and deletion under `['auth']` only — any user modifies timetables |
| C-06 | HIGH | `currentPortal` session bypass on `isCT` and `isCP` middleware |
| C-07 | MEDIUM | CT grade save does not verify that the subject belongs to the teacher's assigned section |
| C-08 | MEDIUM | College enrollment status readable by any authenticated user |
| C-09 | LOW | CT grading period configuration writable by any authenticated user |
| C-10 | LOW | Dean report endpoints return full student roster without section-level scoping |

### Finding Details

**C-01 — CRITICAL — Unauthenticated Dynamic Column Injection**  
`CPController::updatehps` accepts two request parameters: `column` (the grade component column name, e.g., `prelim_grade`, `midterm_grade`) and `value` (the score). The `column` value is inserted directly into the Eloquent `update()` call as the key:
```php
DB::table('grades')->where('id', $id)->update([$request->column => $request->value]);
```
There is no middleware on this route and no allowlist validation on `column`. An attacker can:
1. Write to any column in the `grades` table — including `final_grade`, `deleted`, `createdby`
2. Set a student's `final_grade` to any value without any authentication

**C-03 — HIGH — Student Self-Approves and Posts Own Final Grade**  
College grade approval (ECR function) and grade posting are registered in `RouteServiceProvider` under the `web` group only — no `isECR` or role middleware. The ECR AJAX endpoints accept a grade record ID. A logged-in college student can call the approve and post endpoints with their own grade record ID, moving their grade from "for review" directly to "officially posted" without any faculty or registrar review.

**C-04 — HIGH — Dean Module Under `['auth']` Only**  
The Dean module covers curriculum management (adding/deleting subjects from prospectus), student prospectus loading, and course-level academic configuration. All 8 Dean controllers are registered without role middleware. Any authenticated user — including a student — can add or delete subjects from a college program's curriculum.

### Backend Bugs (5)
- `CPController::updatehps` uses raw column name from request with no allowlist (core of C-01)
- ECR endpoints registered in `RouteServiceProvider` append only the `web` middleware group
- Dean course deletion endpoint does not check for enrolled students before deleting a course
- CT grade submission does not validate that grade values fall within the configured HPS range
- College schedule conflict detection runs only on the frontend — no server-side conflict check

---

## Module 8 — Parent Portal

**Risk Level:** HIGH  
**Scope:** `ParentControllers/` (3 files), `AuthenticateParent.php`, all parent route groups

### Security Findings

| ID | Severity | Title |
|---|---|---|
| P-01 | HIGH | 7 grade/billing/attendance endpoints outside all middleware — `studentInfo` session key shared with Student portal bypasses `isParent` entirely |
| P-02 | HIGH | `POST /parentEnterAmount` outside all middleware — fake payment records accepted, including negative amounts |
| P-03 | MEDIUM | Receipt upload validates only file extension (not content) — MIME type bypass possible |
| P-04 | MEDIUM | Billing history returns records for any `studid` in request — no parent-child ownership verification |
| P-05 | LOW | `AuthenticateParent` lacks `currentPortal` session check — inconsistent with all other portal middlewares |
| P-06 | LOW | Parent profile photo update route outside `isParent` middleware |
| P-07 | INFO | SSE attendance stream accessible to any active session holding a `studentInfo` key |

### Finding Details

**P-01 — HIGH — Session Key Collision Between Parent and Student Portals**  
Both `AuthenticateParent` (type 7) and `AuthenticateStudent` (type 9) read the student's ID from `Session::get('studentInfo')`. Seven data endpoints that use this session key are placed outside all middleware. A logged-in student can access these endpoints directly (bypassing `isParent`) because they hold the same session key. The affected endpoints include grade viewing, billing summary, class schedule, and attendance history.

**P-02 — HIGH — Unauthenticated Fake Payment Submission**  
`POST /parentEnterAmount` is outside all middleware groups. It inserts a payment record into the billing table with the submitted amount, reference number, and receipt image path. There is no authentication check and no amount validation. A visitor can submit negative payment amounts, which would incorrectly reduce a student's balance in the billing ledger.

**P-03 — MEDIUM — File Extension Bypass on Receipt Upload**  
Receipt image uploads use `$file->getClientOriginalExtension()` to determine the stored filename extension. This value comes from the client-supplied filename and is not validated against the actual file content. A malicious file can be uploaded with a `.jpg` extension while containing PHP code. Whether this is executable depends on the server's web root configuration, but the input path is not safe.

### Backend Bugs (3)
- `parentEnterAmount` accepts negative and zero amounts with no server-side range check
- Receipt file path stored in DB before upload is confirmed successful — path reference can point to a non-existent file
- `studentInfo` session key collision: if a student logs in and a parent is already logged in on the same device/session store, the parent's child-context is overwritten

---

## Module 9 — Admin Portal (Administrator / AdminAdmin)

**Risk Level:** CRITICAL  
**Scope:** `AdministratorControllers/` (11 files), `AdminadminController/`, `Cor.php` (the `cors` middleware), `AuthenticateAdmin.php`, `AuthenticateAdminAdmin.php`

### Background: The `cors` Middleware

The `cors` route alias maps to `App\Http\Middleware\Cor`, which contains the entirety of its logic:
```php
return $next($request)
    ->header('Access-Control-Allow-Origin', '*')
    ->header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
```
It adds HTTP headers and passes every request through. It provides **zero authentication**. Every route in a `['cors']`-only group is fully accessible to any internet visitor without credentials.

### Security Findings

| ID | Severity | Title |
|---|---|---|
| A-01 | **CRITICAL** | `GET /administrator/setup/accounts/updatepass?tid=<email>` — resets any account's password to `123456`, no authentication |
| A-02 | **CRITICAL** | `GET /administrator/setup/accounts/list` — returns `passwordstr` (plaintext stored passwords) for all staff, no authentication |
| A-03 | **CRITICAL** | `GET /administrator/setup/accounts/create/account` — creates staff/admin accounts with attacker-controlled user type, no authentication |
| A-04 | HIGH | `update_fas_priv_ajax` — modifies portal access privileges (`faspriv` table) for any user, no authentication; audit trail is attacker-controlled |
| A-05 | HIGH | `update_active` — activates or deactivates any staff account, no authentication |
| A-06 | HIGH | `GET /reportcard/grade/status/approve` and `/post` — K-12 grade approve/post outside all middleware |
| A-07 | HIGH | Sync routes (`synnew`, `syncupdate`, `syncdelete`) perform DB writes with no authentication |
| A-08 | MEDIUM | `GET /studentmasterlist`, `GET /cashtransaction`, `GET /targetcollection` — AdminAdmin reports with no middleware |

### Finding Details

**A-01 — CRITICAL — Unauthenticated Password Reset for Any Account**  
`FNSAccountController::change_password` takes a teacher ID (`tid`, which is their email address) from the request and runs:
```php
DB::table('users')->where('email', $tid)->update([
    'password'  => Hash::make('123456'),
    'isDefault' => 1,
]);
```
No authentication. No current password required. No ownership check. By calling `GET /administrator/setup/accounts/updatepass?tid=admin@school.edu`, an attacker resets the target account's password to the well-known default `123456` and logs in immediately. This affects all user types including SuperAdmin, Registrar, and Finance accounts.

**A-02 — CRITICAL — Plaintext Password Dump**  
`FNSAccountController::list` builds a query that includes `'passwordstr'` — a column that stores user passwords in plain text — in its SELECT clause. The endpoint is under CORS-only middleware. A single GET request with `?status=1&length=9999` returns a JSON payload containing the plaintext password for every active staff member in the school.

**A-03 — CRITICAL — Unauthenticated Account Creation with Arbitrary Role**  
`create_fas_account` inserts a new `teacher` record and corresponding `users` record. The `utype` (user type) is read directly from `$request->get('utype')` with no validation. An attacker can create an account with user type 17 (SuperAdmin) or type 6 (Admin) and immediately log in with the generated TID and default password `123456`.

**A-04 — HIGH — Unauthenticated Portal Privilege Grant**  
`update_fas_priv_ajax` modifies the `faspriv` table, which controls which portal(s) each user can access. When the request is unauthenticated, it falls through to `$updateuserid = $request->get('updateuserid')` — the audit trail's actor field is attacker-supplied. An attacker can grant themselves or any user access to any portal, or remove access from legitimate administrators.

### Backend Bugs (2)
- `list()` uses `@json_encode()` (with `@` error suppressor) — JSON encoding errors are silently swallowed and produce a null response
- `generateaccount()` calls `auth()->user()->id` inside a conditional block that can be reached from an unauthenticated request; throws a `BadMethodCallException` for TESDA trainer accounts, leaving orphaned `users` records

---

## Module 10 — Principal Portal

**Risk Level:** CRITICAL  
**Scope:** `PrincipalControllers/` (11 files), `TeacherGradingV4.php` (grade post/approve methods), `AuthenticatePrincipal.php`

### Background: The Missing Middleware

`AuthenticatePrincipal` is a correctly-written middleware registered in `Kernel.php` as `isPrincipal`. It checks `auth()->user()->type == 2` or `Session::get('currentPortal') == 2`. It is used in **zero routes** across all route files. Every Principal controller endpoint is reached through `['auth']`, `['auth', 'isDefaultPass']`, or no middleware — meaning any logged-in user has full Principal-level access.

### Security Findings

| ID | Severity | Title |
|---|---|---|
| PR-01 | **CRITICAL** | `isPrincipal` middleware registered but never applied — entire Principal module accessible to any authenticated user |
| PR-02 | **CRITICAL** | `GET /posting/grade/update-grade-status` and `update-stud-gradstatus` — deportment conduct writes with no middleware at all |
| PR-03 | HIGH | Grade post/approve/unpost under `['auth', 'isDefaultPass']` only — teachers self-approve and self-post their own grades |
| PR-04 | HIGH | SF9 report card signatory CRUD under `['auth']` only — any student can overwrite the principal's name on all official SF9 forms |
| PR-05 | MEDIUM | IDOR in `loadSectionProfile` — `Crypt::decrypt()` exception silently swallowed; plain integer IDs enumerate all section profiles |
| PR-06 | MEDIUM | Unauthenticated deportment routes crash on `auth()->user()->id` call — 500 error with potential stack trace |

### Finding Details

**PR-01 — CRITICAL — All Principal Operations Accessible to Any Auth User**  
Because `isPrincipal` is never applied, the following operations are reachable by any logged-in user regardless of role:
- `POST /save/average/grade` — changes the grade averaging formula applied to all report cards
- `GET /setup/signatories/create/sf9`, `update/sf9`, `delete/sf9` — adds, modifies, or deletes the signatory printed on all SF9 report cards
- `GET /principal/ps/gradestatus/delete` — deletes grade status workflow records
- `GET /principalAwardsAndRecognitions` — reads student honors data
- `GET principal/section/students/enrolled` — reads full enrolled student list for any section
- `GET /searchStudentWithHonors` — reads student rankings with general averages

**PR-02 — CRITICAL — Unauthenticated Deportment Grade Write**  
Both `update_gradestatus` and `update_specific_gradestatus` in `DeportmentStatus.php` are outside all middleware:
```php
// update_gradestatus — no middleware
public function update_gradestatus(Request $request) {
    foreach ($request->array as $id) {
        DB::table('student_deportment')
            ->where('studid', $id)->where('syid', $request->syid)
            ->where('sectionid', $request->sectionid)
            ->where('quarter_ID', $request->quarter_ID)
            ->update(['gradestatus' => $request->status]);  // 1–5, attacker-supplied
    }
    DB::table('deportment_hps')->where('id', $request->hpsid)
        ->update(['gradestatus' => $request->status]);
}
```
An unauthenticated request can set any batch of students' conduct grade status to any value — including 5 (Posted).

**PR-04 — HIGH — SF9 Signatory Writeable by Any Auth User**  
The `signatory` table record controls what name and title appear on every printed SF9 report card. Under `['auth']` with no role check, any logged-in user can call `GET /setup/signatories/update/sf9?id=1&name=X&title=Y` to change the printed principal name on all subsequently generated report cards for the current school year.

### Backend Bugs (7)
- `loadtable()` in `DeportmentStatus.php` — null dereference when `deportment_hps` record does not exist for the requested section/sy/quarter; `$deportmentID->deportment_setupid` throws "Trying to get property of non-object"
- `store_error()` in `PrincipalController.php` — calls `auth()->user()->id` in the error log insert; throws a secondary exception when called from an unauthenticated context, masking the original error
- `loadAverageType()` — calls `$check->name` without null guard; throws if no average type has been configured yet
- `print_award()` — saves `.docx` to `cwd` (public root) with a predictable filename; concurrent requests for students with the same name overwrite each other's files
- `loadtable()` — student `lastname` and `firstname` inserted into HTML string via concatenation without `htmlspecialchars()`; stored XSS via student names
- Female student loop — `$status;` and `$color;` declared as bare expressions (not initialized); stale values from the previous male student's iteration bleed through if a grade status value is unexpected
- `count($items) != null` — PHP type coercion makes `0 == null` true, so empty `$items` arrays pass through as expected by accident; intent is `count($items) > 0`

### Frontend Issues (4)
- Grade status 4 consistently labelled `"Aproved"` (missing second 'p') in API responses, HTML badges, and the grade status dropdown — visible to the principal on all deportment tables
- Status 2 ("Submitted") uses Bootstrap `badge-success` (green) — misleads users into thinking the grade is finalized when it still requires principal approval
- `PrincipalSummaryController::summarytotalnumberofstudents()` returns only an empty view; the entire data-fetching implementation (~80 lines) is commented out — the summary page is blank
- Award certificate `Content-Disposition` header: `filename=` is not quoted — filenames containing spaces cause malformed headers; RFC 6266 requires `filename="..."`

---

## Module 11 — Director Portal

**Risk Level:** CRITICAL  
**Scope:** `DirectorControllers/DirectorFinanceReportsController.php`, `AdminAdminController.php` (CORS-group methods), `routes/web.php` CORS group at lines 6834–6854

### Security Findings

| ID | Severity | Title |
|---|---|---|
| DR-01 | **CRITICAL** | Hardcoded production database credentials (`ckgroup_dev` / `Sels2019`) plus server IP (`141.164.36.7`) in source code — repeated 4× — direct MySQL access to the entire multi-school hosted platform; CVSS 10.0 |
| DR-02 | **CRITICAL** | `GET /passData?action=getemployees` unauthenticated — dumps all employee PII including home addresses, DOB, email, employment status, education history, and portal access list |
| DR-03 | **CRITICAL** | All 4 Director finance dashboards (cashier transactions, collections, accounts receivable, expenses) accessible without authentication |
| DR-04 | HIGH | `CURLOPT_SSL_VERIFYPEER => false` on all inter-school Guzzle HTTP calls — all inter-school data exchange is MITM-able |
| DR-05 | HIGH | Finance, HR, academic, and enrollment admin dashboards all in the same CORS-only group — no authentication |
| DR-06 | MEDIUM | Dynamic DB connection switch controlled by session `schoolid` — no validation or ownership check |

### Finding Details

**DR-01 — CRITICAL (CVSS 10.0) — Hardcoded Production Credentials**  
The following block appears identically in all four methods of `DirectorFinanceReportsController.php`:
```php
Config::set("database.connections.mysql", [
    'driver'   => 'mysql',
    "host"     => env('DB_HOST', '141.164.36.7'),  // production server IP as fallback
    "database" => $schoolInfo->db,
    "username" => "ckgroup_dev",                    // HARDCODED
    "password" => "Sels2019",                       // HARDCODED
    "port"     => '3306',
]);
```
Anyone with access to the repository can extract these credentials and connect directly to the production MySQL server hosting all schools on the platform. Once connected, they can enumerate all school databases, read and write all student, financial, and staff records, and extract credentials for every user account — all without interacting with the web application.

**DR-02 — CRITICAL — Unauthenticated Employee PII via `passData`**  
`GET /passData?action=getemployees` returns — with zero authentication — a JSON array of all active employees including:
- Full name, gender, date of birth
- Home address and personal email
- Employment status and hire date
- Complete education history (degrees, institutions)
- List of all portal access privileges (`faspriv`)
- Real-time attendance status for the current day (via `getemployeeattendance`)

**DR-04 — HIGH — SSL Verification Disabled**  
```php
$guzzleClient = new \GuzzleHttp\Client(['curl' => [
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_HEADER         => true,
]]);
```
Every outbound HTTP call from the Director portal to remote school instances uses this client. A network-positioned attacker can intercept these calls and serve forged financial data, causing the Director to see fabricated collection totals, cashier transactions, or account receivable balances.

**DR-06 — MEDIUM — Session-Driven DB Switch**  
```php
$schoolInfo = DB::table('schoollist')->where('id', Session::get('schoolid'))->first();
if ($schoolInfo->islocal == 0) {
    Config::set("database.connections.mysql", [
        "database" => $schoolInfo->db,  // determined by session value
        "username" => "ckgroup_dev",
        "password" => "Sels2019",
    ]);
}
```
The active database for the request is selected based on `Session::get('schoolid')`. If an authenticated attacker manipulates their session's `schoolid` (e.g., via the unauthenticated `GET /viewschool/{id}` in the same CORS group), they redirect all their subsequent database queries to a different school's database using the shared credentials.

### Backend Bugs (4)
- All four finance methods have an empty `else {}` block — when `?action=` is provided, the method returns `null` (empty HTTP 200 response), confusing any client expecting a response body
- Null dereference on first line of every method: `$schoolInfo = DB::table('schoollist')->where('id', Session::get('schoolid'))->first()` — if `schoolid` is not in session, `$schoolInfo` is null and `$schoolInfo->islocal` throws immediately
- Database credentials copy-pasted into 4 separate method bodies — any future credential rotation must update 4 locations; missing one leaves a stale credential
- `date_format(date_create($request->get('datefrom')), 'Y-m-d 00:00')` in `passData` — `date_create()` returns `false` for invalid date strings; calling `date_format(false, ...)` throws `TypeError` in PHP 8+

---

---

## Cross-Cutting Issues

The following vulnerabilities appear across multiple modules and indicate systemic problems in the codebase architecture.

### 1. `cors` Middleware Misidentified as Authentication
**Affected modules:** Admin, Director

`App\Http\Middleware\Cor` adds only `Access-Control-Allow-Origin: *` and passes every request through. It provides zero authentication. It was applied to faculty/staff account management routes (Admin portal) and Director finance routes, creating a large unauthenticated attack surface. The `cors` alias name suggests to developers that it is sufficient for cross-origin API endpoints, but no authentication is actually present.

**Root cause fix:** Rename the middleware to `AddCorsHeaders` to clarify its non-security function. Apply `['auth', <role>]` in addition to CORS headers for all protected endpoints.

---

### 2. `['auth']` Without Role Check as the Sole Gate for Privileged Operations
**Affected modules:** Registrar (RegistrarV2), College (Dean, ECR), Principal (all routes), Admin (some routes)

Laravel's `auth` middleware confirms only that a session exists and maps to a valid user — it performs no role check. Multiple modules use `['auth']` as their only middleware for operations that should be restricted to a specific role (registrar, dean, principal, admin). A student, teacher, cashier, or parent who knows the URL can call these endpoints directly.

**Root cause fix:** Every route group serving a specific portal role must include that portal's role middleware: `['auth', 'isRegistrar']`, `['auth', 'isDean']`, `['auth', 'isPrincipal']`, etc. The role middlewares already exist in `Kernel.php` for most of these.

---

### 3. `currentPortal` Session Flag Bypass
**Affected modules:** SuperAdmin, Teacher, College, Admin

Multiple role-check middlewares include a condition like:
```php
if (auth()->user()->type == X || Session::get('currentPortal') == X) {
    return $next($request);
}
```
The `currentPortal` session variable controls portal-switching for users who hold multiple roles. However, several portal-switching flows do not re-validate that the user's account is actually authorized for the requested portal before setting the session variable. A user who sets `currentPortal` to a privileged value via a misconfigured switching endpoint gains access to that portal's routes without holding the corresponding user type.

**Root cause fix:** The `currentPortal` alternative path in each middleware should be bounded by the same type check: `(auth()->user()->type == X || (Session::get('currentPortal') == X && /* verify user holds privilege X */))`.

---

### 4. Plaintext Credential Storage
**Affected modules:** Finance V2, Cashier V2, Admin

Three separate storage patterns expose credentials in plain text:
1. `fin_pin` and `chrng_pin` tables store financial authorization PINs as plain text (Finance V2, Cashier V2)
2. `users.passwordstr` stores user login passwords as plain text (Admin — returned in unauthenticated list endpoint)
3. DB credentials for the hosted platform hardcoded in PHP source (Director)

Any of the following exposes all stored credentials: a database backup, a rogue DBA, a SQL injection vulnerability, or source code repository access.

**Root cause fix:** Hash PINs with `bcrypt` or `argon2`; remove or encrypt `passwordstr`; move DB credentials to `.env`.

---

### 5. `DomPDF enable_php = true`
**Affected modules:** Finance V2, Cashier V2

PHP code execution inside PDF HTML templates is enabled application-wide across both financial modules. The current templates use `htmlspecialchars()` in the signatory method, but `{!! !!}` (unescaped Blade) appears in multiple template files. A single future change that introduces unescaped user-controlled content into a PDF template becomes an immediate Remote Code Execution vector.

**Root cause fix:** Set `enable_php = false` and `isPhpEnabled = false` in all DomPDF configurations. This is a one-line change per controller and eliminates the risk entirely.

---

### 6. Unauthenticated Grade Manipulation Routes
**Affected modules:** Teacher, College, Principal, Admin

Grade modification endpoints (write component scores, approve batch, post to official record) appear outside authentication in at least four separate modules. This creates redundant paths for grade manipulation that cannot all be discovered and patched through a single code change. The grade system's security depends on every individual endpoint being correctly gated.

| Route | Module | Auth | Operation |
|---|---|---|---|
| `GET /gradesdetail/update` | Teacher | None | Write grade component |
| `GET /teacher/update/hps` | College | None | Write grade via column injection |
| `GET /posting/grade/update-grade-status` | Principal | None | Write deportment status |
| `GET /reportcard/grade/status/approve` | Admin | None | Approve K-12 grade batch |
| `GET /reportcard/grade/status/post` | Admin | None | Post K-12 grade batch |
| `GET posting/grade/approve` | Principal | `isDefaultPass` only | Approve individual grade |
| `GET posting/grade/post` | Principal | `isDefaultPass` only | Post individual grade |

---

## Immediate Actions Required

> These items must be addressed before any further production deployment or user-facing release.

| Priority | Finding(s) | Action |
|---|---|---|
| 1 | DR-01 | **Rotate `ckgroup_dev` database password immediately.** Audit git history — if credentials were ever committed to a remote repository, treat the password as already compromised regardless of rotation. Move all DB credentials to `.env`. |
| 2 | A-01 | **Disable `GET /administrator/setup/accounts/updatepass`** or add `['auth', 'isAdmin:admin']`. This route resets any account's password to a known value with zero authentication. |
| 3 | A-02 | **Remove `passwordstr` from `FNSAccountController@list` SELECT**. The column must not be transmitted in any response. |
| 4 | A-01 through A-08, DR-02 through DR-05 | **Replace `['cors']` middleware with `['auth', <role>]`** on all account management and Director finance routes. The `cors` middleware provides no authentication. |
| 5 | PR-01 | **Apply `['auth', 'isPrincipal']`** to every Principal route group. The middleware is written and registered — it just needs to be used. |
| 6 | R-01 | **Remove or gate `GET /debugger/fix-account-conflict`** behind `['auth', 'isSuperAdmin:superadmin']`. This endpoint resets student accounts to a known password. |
| 7 | C-01 | **Add an allowlist validation on `$request->column`** in `CPController::updatehps` and add `['auth', 'isCP']` to the route. Currently any internet visitor can write to any column in the grades table. |
| 8 | FV2-02, CV2-02 | **Set `enable_php = false`** in all DomPDF configurations across Finance V2 and Cashier V2. One-line fix per controller. |
| 9 | DR-04 | **Re-enable SSL certificate verification** — remove `CURLOPT_SSL_VERIFYPEER => false` from all Guzzle client configurations. |
| 10 | T-01, C-01, PR-02, A-06 | **Add authentication middleware to all grade-modification routes** listed in Cross-Cutting Issue #6. |

---

*End of Full Security Assessment Report*  
*Detailed per-module documents (CODE_REVIEW, EXECUTIVE_SUMMARY, POC) available in `Analysis Docs/`*
