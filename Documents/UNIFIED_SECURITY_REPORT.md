# Security Code Review — Unified Assessment Report
**Project:** `es_ldcu` — School Management System  
**Reporting Period:** May 27, 2026 – June 10, 2026  
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
| **Total Estimated Hours** | ~58 |
---

## Module Overview — Sorted by Date

| # | Module | Date | Risk | Findings | Critical | High |
|---|---|---|---|---|---|---|
| 1 | SuperAdmin | May 27–28 | **CRITICAL** | 12 | 2 | 4 |
| 2 | Teacher | May 28–29 | **CRITICAL** | 15 | 1 | 5 |
| 3 | Finance V2 | May 29 | **CRITICAL** | 9 | 4 | 3 |
| 4 | Cashier V2 | May 29 | **CRITICAL** | 14 | 2 | 5 |
| 5 | Student | June 3 | **CRITICAL** | 10 | 1 | 3 |
| 6 | Registrar | June 6 | **CRITICAL** | 9 + 4 bugs | 2 | 3 |
| 7 | College (CT/CP/Dean/ECR) | June 6 | **CRITICAL** | 10 + 5 bugs | 1 | 5 |
| 8 | Parent | June 8 | HIGH | 7 + 3 bugs | 0 | 2 |
| 9 | Admin | June 9 | **CRITICAL** | 8 + 2 bugs | 3 | 4 |
| 10 | Principal | June 9 | **CRITICAL** | 6 + 7 bugs + 4 FE | 2 | 2 |
| 11 | Director | June 10 | **CRITICAL** | 6 + 4 bugs | 3 | 2 |

---

---

## Module 1 — SuperAdmin Portal
**Date:** May 28, 2026 | **Risk Level:** CRITICAL 

**Scope:** `SuperAdminController/` (17 controllers), `AuthenticateSuperAdmin.php`, all superadmin route groups

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

**Key Bugs:** File upload does not validate MIME type server-side; module status update uses raw column name from request parameter with no allowlist.

---

## Module 2 — Teacher Portal
**Date:** May 28–29, 2026 | **Risk Level:** CRITICAL 

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

---

## Module 3 — Finance V2
**Date:** May 29, 2026 | **Risk Level:** CRITICAL | **Hours:** ~7.0 *(reviewed by separate team member)*

**Scope:** `Financev2Controller/`, Finance V2 billing, adjustments, accounts receivable, PDF reports

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

**Key Bugs:** Accounts receivable totals calculated via loop rather than DB aggregation; PIN verification logic disconnected from action it protects.

---

## Module 4 — Cashier V2
**Date:** May 29, 2026 | **Risk Level:** CRITICAL | **Hours:** ~6.5 *(reviewed by separate team member)*

**Scope:** `CashierV2Controller/`, payment processing, receipt printing, void/suspension workflow, queue display

### Security Findings

| ID | Severity | Title |
|---|---|---|
| CV2-01 | **CRITICAL** | `serverPrint` spawns `mshta.exe` via `shell_exec` — OS command exposure, no cashier-role check |
| CV2-02 | **CRITICAL** | DomPDF `enable_php = true` in 3 PDF-print methods — latent RCE |
| CV2-03 | HIGH | Zero role-based access control — any authenticated user can process payments, void, delete |
| CV2-04 | HIGH | Plaintext PIN storage (`chrng_pin.pin_code`) — same issue as Finance V2 |
| CV2-05 | HIGH | IDOR — `serverPrint` allows any authenticated user to print any receipt by OR number |
| CV2-06 | HIGH | IDOR — suspended sale DELETE has no ownership check |
| CV2-07 | HIGH | Stored DOM XSS — `displayNonTuitionItems()` injects unsanitized DB values into HTML |
| CV2-08 | HIGH | Stored DOM XSS — `loadSuspendedSales()` injects `customer_name`/`student_name` into HTML |
| CV2-09 | MEDIUM | AES key exposed in `<meta>` tag of `app2.blade.php` — same key as Finance V2 |
| CV2-10 | MEDIUM | `$e->getMessage()` returned in 20+ JSON error responses — stack/query info leaked |
| CV2-11 | MEDIUM | `students()` endpoint — `per_page` parameter uncapped — resource exhaustion |
| CV2-12 | LOW | Queue display routes expose queue numbers publicly (noted as intentional design) |
| CV2-13 | LOW | `DiscountsContoller.php` filename typo — dead mutation methods not routed |
| CV2-14 | LOW | 414 `console.log()` calls leak payment amounts, student IDs, and reference numbers in browser console |

---

## Module 5 — Student Portal
**Date:** June 3, 2026 | **Risk Level:** CRITICAL | **Hours:** 5.5

**Scope:** `StudentControllers/` (8 files), `AuthenticateStudent.php`, all student route groups

### Security Findings

| ID | Severity | Title |
|---|---|---|
| S-01 | **CRITICAL** | IDOR in billing ledger — students access other students' payment histories by manipulating `studid` |
| S-02 | HIGH | Unauthenticated SMS notification trigger — external party can spam students |
| S-03 | HIGH | Photo upload stores file via base64 decode with no server-side MIME validation |
| S-04 | HIGH | Sensitive academic schedule/grades returned without student ownership verification |
| S-05 | MEDIUM | `currentPortal` session bypass on `isStudent` middleware |
| S-06 | MEDIUM | Scholarship application accepts arbitrary file type in document upload |
| S-07 | MEDIUM | Server-sent events (attendance feed) accessible to any authenticated session |
| S-08 | LOW | Student SID exposed in all enrollment response objects |
| S-09 | LOW | Enrollment history paginated endpoint returns data for withdrawn students |
| S-10 | LOW | GET used for student profile update (no CSRF protection) |

**Key Bugs:** Base64 photo upload creates files with `.php` extension if content-type header is not validated; attendance SSE stream does not close on session expiry.

---

## Module 6 — Registrar Portal
**Date:** June 6, 2026 | **Risk Level:** CRITICAL | **Hours:** 4.25

**Scope:** `RegistrarControllers/` (legacy), `RegistrarV2Controller/` (50+ controllers), `AuthenticateRegistrar.php`

### Security Findings

| ID | Severity | Title |
|---|---|---|
| R-01 | **CRITICAL** | `GET /debugger/fix-account-conflict` — unauthenticated; creates student accounts with default password `123456` — anyone can log in as any student |
| R-02 | **CRITICAL** | Unauthenticated full student database dump (`PreRegistrationController`) |
| R-03 | HIGH | Entire RegistrarV2 module (50+ controllers) under `['auth']` only — any logged-in user deletes academic configs |
| R-04 | HIGH | Commented-out authentication in `PreRegistrationControllerV2` — `early/enrollment/submit` runs unprotected |
| R-05 | HIGH | Stored XSS — student names rendered unescaped in registrar search results |
| R-06 | MEDIUM | Debug SF10 endpoint with hardcoded test student data accessible in production |
| R-07 | MEDIUM | `RegistrarV2` college/course/grade configuration CRUD under `['auth']` only |
| R-08 | LOW | Photo upload in student requirements does not validate image dimensions |
| R-09 | LOW | Registrar session reused across multiple academic year contexts without re-validation |

**Key Bugs (4):** Missing JOIN in student search returns cross-student data leakage; SF10 debug route returns hardcoded private student data; `RouteServiceProvider` registers RegistrarV2 under `web` middleware only.

---

## Module 7 — College Portal (CT / CP / Dean / ECR)
**Date:** June 6, 2026 | **Risk Level:** CRITICAL | **Hours:** 5.0

**Scope:** `CTController/`, `CPControllers/`, `DeanControllers/` (8 files), `CollegeECR.php`, `AuthenticateCT`, `AuthenticateCP`, `AuthenticateDean`

### Security Findings

| ID | Severity | Title |
|---|---|---|
| C-01 | **CRITICAL** | `GET /teacher/update/hps` fully unauthenticated with dynamic column injection — any internet visitor corrupts any student's grade |
| C-02 | HIGH | `updategrades` and `updateigfg` — K-12 grade records modifiable by any authenticated user |
| C-03 | HIGH | ECR grade approval and posting under `['auth']` only — student can approve and post their own final grade |
| C-04 | HIGH | Entire Dean module (curriculum, student loading, prospectus) under `['auth']` only |
| C-05 | HIGH | College class schedule creation/deletion under `['auth']` only — any user modifies timetables |
| C-06 | HIGH | `currentPortal` session bypass on `isCT` and `isCP` middleware |
| C-07 | MEDIUM | CT grade save does not validate that the subject belongs to the teacher's section |
| C-08 | MEDIUM | College enrollment status readable by any authenticated user |
| C-09 | LOW | CT grading period configuration writable by any authenticated user |
| C-10 | LOW | Dean report endpoints return full student roster without section-level scoping |

**Key Bugs (5):** `CPController::updatehps` uses raw column name from request with no allowlist (SQL column injection); ECR endpoints registered in `RouteServiceProvider` without role middleware; Dean `[auth]`-only endpoints include course deletion.

---

## Module 8 — Parent Portal
**Date:** June 8, 2026 | **Risk Level:** HIGH | **Hours:** 4.0

**Scope:** `ParentControllers/` (3 files), `AuthenticateParent.php`, all parent route groups

### Security Findings

| ID | Severity | Title |
|---|---|---|
| P-01 | HIGH | 7 grade/billing/attendance endpoints outside all middleware — `studentInfo` session shared with Student type bypasses `isParent` |
| P-02 | HIGH | `POST /parentEnterAmount` outside all middleware — fake payment submissions accepted with negative/zero amounts |
| P-03 | MEDIUM | Receipt upload accepts unvalidated file extension (only extension checked, not content) |
| P-04 | MEDIUM | Billing history returns records for any `studid` in request — no parent-child ownership check |
| P-05 | LOW | `AuthenticateParent` lacks `currentPortal` session check — inconsistent with other portal middlewares |
| P-06 | LOW | Parent profile photo update outside `isParent` middleware |
| P-07 | INFO | SSE attendance stream accessible to parent session of any child in the school |

**Key Bugs (3):** `parentEnterAmount` accepts negative amounts with no server-side validation; receipt file stored with unvalidated extension from `getClientOriginalExtension()`; `studentInfo` session key collision between type-7 (parent) and type-9 (student) allows cross-session access.

---

## Module 9 — Admin Portal (Administrator / AdminAdmin)
**Date:** June 9, 2026 | **Risk Level:** CRITICAL | **Hours:** 4.5

**Scope:** `AdministratorControllers/` (11 files), `AdminadminController/`, `Cor.php` middleware, `AuthenticateAdmin.php`, `AuthenticateAdminAdmin.php`

### Security Findings

| ID | Severity | Title |
|---|---|---|
| A-01 | **CRITICAL** | `GET /administrator/setup/accounts/updatepass?tid=<email>` — resets **any** account password to `123456`, fully unauthenticated (`cors` middleware = CORS headers only, zero auth) |
| A-02 | **CRITICAL** | `GET /administrator/setup/accounts/list` — returns `passwordstr` (plaintext passwords) for all staff, fully unauthenticated |
| A-03 | **CRITICAL** | `GET /administrator/setup/accounts/create/account` — creates staff accounts with attacker-controlled `utype`, fully unauthenticated |
| A-04 | HIGH | `update_fas_priv_ajax` — modifies portal access privileges for any user, no auth; audit trail attacker-controlled |
| A-05 | HIGH | `update_active` — activates/deactivates any staff account, no auth |
| A-06 | HIGH | `GET /reportcard/grade/status/approve` and `/post` — K-12 grade approve/post outside all middleware |
| A-07 | HIGH | Sync routes (`synnew`/`syncupdate`/`syncdelete`) write to DB with no auth |
| A-08 | MEDIUM | `/studentmasterlist`, `/cashtransaction`, `/targetcollection` — AdminAdmin reports, no middleware |

**Key Bugs (2):** `list()` uses suppressed `@json_encode()` masking encoding errors; `generateaccount()` calls `auth()->user()->id` in unauthenticated context crashing for TESDA trainer accounts.

---

## Module 10 — Principal Portal
**Date:** June 9, 2026 | **Risk Level:** CRITICAL | **Hours:** 4.5

**Scope:** `PrincipalControllers/` (11 files), `TeacherGradingV4.php` (grade post/approve methods), `AuthenticatePrincipal.php`

### Security Findings

| ID | Severity | Title |
|---|---|---|
| PR-01 | **CRITICAL** | `isPrincipal` middleware written and registered but applied to **zero routes** — entire Principal module runs on `['auth']` only; any logged-in user has full Principal access |
| PR-02 | **CRITICAL** | `GET /posting/grade/update-grade-status` and `update-stud-gradstatus` — deportment conduct writes, **no middleware at all** |
| PR-03 | HIGH | Grade post/approve/unpost under `['auth', 'isDefaultPass']` only — teachers self-approve and self-post their own grades |
| PR-04 | HIGH | SF9 report card signatory CRUD under `['auth']` only — any student overwrites the principal's printed name on all official SF9 forms |
| PR-05 | MEDIUM | IDOR in `loadSectionProfile` — decrypt exception silently swallowed; plain integer IDs enumerate all section profiles |
| PR-06 | MEDIUM | Unauthenticated deportment routes crash with 500 on `auth()->user()->id` calls |

**Key Bugs (7):** Null dereference in `loadtable()` when `deportment_hps` missing; `store_error()` throws secondary exception when unauthenticated; `loadAverageType()` crashes on null DB result; award `.docx` race condition in public directory; stored XSS via unescaped student names in deportment HTML table; `$status`/`$color` uninitialized in female student loop; `count($items) != null` logic error.

**Frontend Issues (4):** "Aproved" typo in grade status badges; misleading green badge for "Submitted" status; Summary page entirely blank (full implementation commented out); `Content-Disposition` filename not quoted in award certificate download.

---

## Module 11 — Director Portal
**Date:** June 10, 2026 | **Risk Level:** CRITICAL | **Hours:** 2.5

**Scope:** `DirectorControllers/DirectorFinanceReportsController.php`, `AdminAdminController.php` (CORS-group methods)

### Security Findings

| ID | Severity | Title |
|---|---|---|
| DR-01 | **CRITICAL** | **Hardcoded production database credentials** (`ckgroup_dev`/`Sels2019`) + server IP (`141.164.36.7`) in source code — 4× copy-pasted — direct MySQL access to entire multi-school hosted platform (CVSS 10.0) |
| DR-02 | **CRITICAL** | `GET /passData?action=getemployees` — unauthenticated dump of all employee PII (address, DOB, email, employment status, education history, portal access) |
| DR-03 | **CRITICAL** | All 4 Director finance dashboards (cashier transactions, collections, accounts receivable, expenses) accessible without authentication |
| DR-04 | HIGH | `CURLOPT_SSL_VERIFYPEER => false` on all inter-school Guzzle HTTP calls — MITM-able |
| DR-05 | HIGH | Finance/HR/academic/enrollment admin dashboards all in same CORS-only group — no auth |
| DR-06 | MEDIUM | Dynamic DB connection switch driven by session `schoolid` — no input validation |

**Key Bugs (4):** Empty `else{}` blocks in all 4 methods (null response on `?action=`); null dereference when `schoolid` not in session; credentials copy-pasted 4× (rotation risk); `date_create()` on invalid date string throws `TypeError` in PHP 8+.

---

---

## Cross-Cutting Issues

The following issues appear **across multiple modules** and represent systemic problems in the codebase:

### 1. `cors` Middleware Misidentified as Authentication
The custom `Cor` middleware (`App\Http\Middleware\Cor`) adds only `Access-Control-Allow-Origin: *` headers. It provides **zero authentication**. It was applied to faculty/staff account management (Admin portal), Director finance reports, AdminAdmin dashboards, and `passData` — making all of them fully unauthenticated. Any internet visitor with the URL has access.

**Affected modules:** Admin, Director

### 2. `['auth']` Without Role Check Used as the Sole Gate for Privileged Operations
Multiple modules use `['auth']` — which only confirms the user is logged in — as the only middleware on operations that should require specific roles. This means a student, teacher, or parent can call registrar, principal, dean, or admin endpoints by knowing the URL.

**Affected modules:** Registrar (RegistrarV2), College (Dean, ECR), Principal (all routes), Admin (some routes)

### 3. `currentPortal` Session Flag Bypass
Several role middleware classes check `Session::get('currentPortal')` alongside the user type. A user who sets this session variable (e.g., via a portal-switching flow that lacks proper validation) can masquerade as a different role type.

**Affected modules:** SuperAdmin, Teacher, Admin

### 4. Plaintext PIN / Password Storage
Financial authorization PINs are stored in plaintext in the `chrng_pin` and `fin_pin` tables. The staff password plaintext is stored in the `passwordstr` column of the `users` table and returned in the unauthenticated `FNSAccountController@list` response.

**Affected modules:** Finance V2, Cashier V2, Admin

### 5. `DomPDF enable_php = true`
PHP execution within PDF templates is enabled in multiple controllers across Finance V2 and Cashier V2. While current templates appear to escape data, any future template modification that uses `{!! !!}` with user-controlled data becomes immediate RCE.

**Affected modules:** Finance V2, Cashier V2

### 6. Unauthenticated Grade Manipulation Routes
Grade modification operations (write, approve, post) appear outside authentication in at least three separate modules: Teacher (grade detail update), College (HPS column injection), Principal (deportment write), and Admin (grade approve/post).

**Affected modules:** Teacher, College, Principal, Admin

---

## Immediate Actions Required

The following require same-day remediation regardless of release schedule:

| Priority | Action |
|---|---|
| 1 | **Rotate `ckgroup_dev` database password immediately** — credentials are in source code (DR-01) |
| 2 | **Disable or authenticate `GET /administrator/setup/accounts/updatepass`** — unauthenticated password reset for any account (A-01) |
| 3 | **Remove `passwordstr` from `FNSAccountController@list` SELECT** — plaintext passwords in unauthenticated response (A-02) |
| 4 | **Replace `['cors']` with `['auth', <role>]` on all account management and Director finance routes** — core CORS misuse (A-01 through A-08, DR-02 through DR-05) |
| 5 | **Apply `['auth', 'isPrincipal']` to all Principal route groups** — middleware written but never used (PR-01) |
| 6 | **Re-enable SSL verification** — `CURLOPT_SSL_VERIFYPEER => false` on all inter-school calls (DR-04) |
| 7 | **Disable `DomPDF enable_php`** in Finance V2 and Cashier V2 — one-line fix, eliminates latent RCE (FV2-02, CV2-02) |
| 8 | **Audit git history** for DR-01 credentials — if ever pushed to a remote repository, treat password as compromised regardless of rotation |

---

*End of Unified Security Assessment Report*  
*Individual module documents (CODE_REVIEW, EXECUTIVE_SUMMARY, POC) available in `Analysis Docs/`*
