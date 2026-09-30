# Security Code Review — Workload Report
**Project:** es_ldcu — School Management System Security Assessment  
**Prepared by:** [Analyst]  
**Reporting Period:** May 27, 2026 – June 13, 2026  
**Purpose:** Workload summary for submission to supervisor / project lead

---

## Overview

This report summarizes the work completed during the security code review of the `es_ldcu` school management system. The assessment was conducted module by module, covering the SuperAdmin portal, Teacher portal, Student portal, Registrar portal, College portal (CT/CP/Dean/ECR), Principal portal, Director portal, Admin portal (Administrator/AdminAdmin), Parent portal, HR Portal, Accounting Portal, Bookkeeper Portal, and five auxiliary modules (TESDA, Admission, Guidance, Document Tracking, Library). Each module underwent static analysis of controllers, route mapping, middleware review, and documentation of security findings, backend bugs, and frontend issues.

---

## Module Breakdown

### 1. SuperAdmin Portal
**Dates:** May 28, 2026  
**Hours:** 8.0 hours  
**Documents Produced:** `SUPERADMIN_CODE_REVIEW.md`, `SUPERADMIN_EXECUTIVE_SUMMARY.md`, `SUPERADMIN_POC.md`  

| Task | Hours |
|---|---|
| Explored and mapped SuperAdmin route structure in `routes/web.php` | 1.0 |
| Read and analyzed `SuperAdminController/` (17 controllers) line by line | 3.0 |
| Reviewed middleware stack — `isAdmin`, `isSuperAdmin`, session flag bypass | 0.5 |
| Investigated file upload handling and web shell upload paths | 0.5 |
| Documented dynamic column injection in `updatemodulestatus` | 0.5 |
| Reviewed session impersonation logic (`switchUser`) | 0.5 |
| Reviewed user enumeration via `validate_student_name` | 0.5 |
| Wrote `SUPERADMIN_CODE_REVIEW.md` (15 findings, backend bugs) | 1.0 |
| Wrote `SUPERADMIN_EXECUTIVE_SUMMARY.md` and `SUPERADMIN_POC.md` | 0.5 |

**Findings:** 12 security findings (2 CRITICAL, 4 HIGH, 4 MEDIUM, 2 LOW)  
**Key Issues Identified:** Arbitrary file upload → web shell via school logo, session flag bypass allowing admin access without credentials, dynamic SQL column injection via module status update endpoint, unauthenticated user enumeration.

---

### 2. Teacher Portal
**Dates:** May 28–29, 2026  
**Hours:** 6.0 hours  
**Documents Produced:** `TEACHER_CODE_REVIEW.md`, `TEACHER_EXECUTIVE_SUMMARY.md`, `TEACHER_POC.md`

| Task | Hours |
|---|---|
| Mapped all teacher-related routes in `routes/web.php` | 0.5 |
| Reviewed middleware — `isTeacher`, `currentPortal` session bypass mechanism | 0.5 |
| Read and analyzed `TeacherControllers/` (11 controllers, ~4,000 lines) | 2.5 |
| Investigated grade tampering via `gradesdetail/update` — no ownership check | 0.5 |
| Investigated deportment grade manipulation without auth | 0.5 |
| Reviewed class schedule and attendance controller patterns | 0.5 |
| Wrote all three Teacher portal documents | 1.0 |

**Findings:** 15 security findings (1 CRITICAL, 5 HIGH, 5 MEDIUM, 4 LOW)  
**Key Issues Identified:** Unauthenticated grade modification (any user can tamper grades via `GET /gradesdetail/update`), unauthenticated deportment grade update, horizontal privilege escalation in teacher-to-student data exposure, `currentPortal` session flag bypassing `isTeacher` middleware.

---

### 3. Student Portal
**Dates:** June 3, 2026  
**Hours:** 5.5 hours  
**Documents Produced:** `STUDENT_CODE_REVIEW.md`, `STUDENT_EXECUTIVE_SUMMARY.md`, `STUDENT_POC.md`

| Task | Hours |
|---|---|
| Located and catalogued all student controllers (8 files) | 0.25 |
| Mapped student-related routes and middleware stack | 0.5 |
| Read `StudentController.php` (~1,700 lines) | 1.0 |
| Read `EnrollmentInformation.php` — billing, class schedule, photo | 1.0 |
| Read `BillingInformationController.php` | 0.5 |
| Identified insecure direct object reference patterns in billing history | 0.5 |
| Investigated photo upload endpoint — base64 to filesystem | 0.25 |
| Documented server-sent events handler for attendance | 0.25 |
| Reviewed scholarship application controller | 0.25 |
| Wrote all three Student portal documents | 1.0 |

**Findings:** 10 security findings (1 CRITICAL, 3 HIGH, 3 MEDIUM, 3 LOW)  
**Key Issues Identified:** IDOR in billing records (students can access other students' ledgers by manipulating request parameters), unauthenticated SMS notification trigger, unrestricted PHP file execution path in photo upload, sensitive academic data returned without ownership verification.

---

### 4. Registrar Portal
**Dates:** June 4–6, 2026  
**Hours:** 4.25 hours  
**Documents Produced:** `REGISTRAR_CODE_REVIEW.md`, `REGISTRAR_EXECUTIVE_SUMMARY.md`, `REGISTRAR_POC.md`

| Task | Hours |
|---|---|
| Mapped registrar route groups — legacy block + RegistrarV2 module | 0.25 |
| Traced middleware: `isRegistrar`, `isAdmission`, `isDefaultPass` | 0.25 |
| Reviewed `RouteServiceProvider.php` — confirmed RegistrarV2 uses `web` only | 0.25 |
| Read `DebuggerController.php` — found `fixAccountConflict` unauthenticated | 0.5 |
| Read `PreRegistrationController.php` — traced commented-out auth logic | 0.5 |
| Read `PreRegistrationControllerV2.php` — traced `early/enrollment/submit` | 0.5 |
| Read `RegistrarFunctionController.php` — HTML injection, missing JOIN | 0.5 |
| Read `RegistrarFormsController.php` — debug SF10 endpoint with hardcoded data | 0.25 |
| Read `StudentRequirementsController.php` — photo upload security | 0.25 |
| Reviewed `routes/registrarv2.php` — confirmed full CRUD under `['auth']` only | 0.5 |
| Scanned 50+ RegistrarV2 controllers for additional access control issues | 0.25 |
| Wrote `REGISTRAR_CODE_REVIEW.md` | 0.5 |
| Wrote `REGISTRAR_EXECUTIVE_SUMMARY.md` and `REGISTRAR_POC.md` | 0.5 |

**Findings:** 9 security findings (2 CRITICAL, 3 HIGH, 2 MEDIUM, 2 LOW) + 4 backend bugs  
**Key Issues Identified:** Unauthenticated endpoint creates student accounts with default password (`fixAccountConflict`) — anyone can log in as any student after calling it. Unauthenticated full student database dump. Entire RegistrarV2 module (50+ controllers, CRUD for colleges/courses/grading) under `['auth']` only — any logged-in user can delete academic configurations. Stored XSS via unescaped student names in search results.

---

### 5. College Portal (CT / CP / Dean / ECR)
**Dates:** June 6, 2026  
**Hours:** 5.0 hours  
**Documents Produced:** `COLLEGE_CODE_REVIEW.md`, `COLLEGE_EXECUTIVE_SUMMARY.md`, `COLLEGE_POC.md`

| Task | Hours |
|---|---|
| Identified College sub-modules: CT (type 18), CP (type 16), Dean (type 14), ECR | 0.25 |
| Mapped all college-related routes — CT group, CP group, Dean group, ECR group | 0.5 |
| Reviewed `AuthenticateCT`, `AuthenticateCP`, `AuthenticateDean` middleware | 0.25 |
| Confirmed ECR and Dean route groups under `['auth']` only in RouteServiceProvider | 0.25 |
| Read `CTController.php` (~3,400 lines) — grade save, grade submission methods | 1.25 |
| Read `CPController.php` — found `updatehps` fully unauthenticated with dynamic column | 0.75 |
| Read `CollegeECR.php` — traced approve/post grade methods under wrong middleware | 0.5 |
| Read `DeanControllers/` (8 files) — curriculum and student loading under `['auth']` only | 0.5 |
| Wrote `COLLEGE_CODE_REVIEW.md` (10 findings, 5 bugs) | 0.5 |
| Wrote `COLLEGE_EXECUTIVE_SUMMARY.md` and `COLLEGE_POC.md` | 0.25 |

**Findings:** 10 security findings (1 CRITICAL, 5 HIGH, 2 MEDIUM, 2 LOW) + 5 backend bugs  
**Key Issues Identified:** Fully unauthenticated dynamic column injection in `grades` table (`GET /teacher/update/hps`) — any internet visitor can corrupt any student's grade with a single GET request. Any authenticated user can modify K-12 grade records (`updategrades`, `updateigfg`). ECR grade approval and posting under `['auth']` only — student can approve and post their own final grade. Entire Dean curriculum and student loading module under `['auth']` only.

---

### 6. Principal Portal
**Date:** June 09, 2026  
**Hours:** 4.5 hours  
**Documents Produced:** `PRINCIPAL_CODE_REVIEW.md`, `PRINCIPAL_EXECUTIVE_SUMMARY.md`, `PRINCIPAL_POC.md`

| Task | Hours |
|---|---|
| Confirmed `isPrincipal` middleware registered in Kernel but used in zero routes | 0.25 |
| Mapped all Principal-related routes — 3 middleware groups + 8 unprotected routes | 0.5 |
| Read `AuthenticatePrincipal.php` — middleware logic confirmed correct but unused | 0.25 |
| Read `DeportmentStatus.php` (~900 lines) — unauthenticated grade-write methods, null deref, XSS, typos | 1.5 |
| Read `PrincipalController.php` (~900 lines) — signatory CRUD, IDOR in section profile, race condition in print_award | 1.25 |
| Read `TeacherGradingV4.php` grade post/approve methods (lines 94–530) | 0.25 |
| Read `ScheduleController.php`, `PrincipalSummaryController.php` (commented-out implementation) | 0.25 |
| Wrote all three Principal portal documents | 0.25 |

**Findings:** 6 security findings (2 CRITICAL, 2 HIGH, 2 MEDIUM) + 7 bugs + 4 frontend issues  
**Key Issues Identified:** `isPrincipal` middleware is written but never applied — entire Principal module runs on `['auth']` only. Deportment conduct grade writes are fully unauthenticated. Any teacher can self-approve and self-post their own grades. Any authenticated user can overwrite the signatory printed on all official SF9 report cards. Stored XSS via unescaped student names in the deportment HTML table. Multiple null-pointer crashes and a file race condition in award certificate generation.

---

### 7. Director Portal
**Dates:** June 10, 2026  
**Hours:** 2.5 hours  
**Documents Produced:** `DIRECTOR_CODE_REVIEW.md`, `DIRECTOR_EXECUTIVE_SUMMARY.md`, `DIRECTOR_POC.md`

| Task | Hours |
|---|---|
| Mapped all Director-related routes in `['cors']` group (lines 6834–6854 of web.php) | 0.25 |
| Read `DirectorFinanceReportsController.php` (~400 lines, 4 methods) — found hardcoded credentials | 0.75 |
| Read `AdminAdminController@passData` (~200 lines of action handling) — confirmed PII exposure scope | 0.75 |
| Confirmed CORS middleware = no auth; SSL disabled on all Guzzle calls | 0.25 |
| Wrote all three Director portal documents | 0.5 |

**Findings:** 6 security findings (3 CRITICAL, 2 HIGH, 1 MEDIUM) + 4 bugs  
**Key Issues Identified:** Hardcoded production database credentials (`ckgroup_dev`/`Sels2019`) plus server IP in source code — highest single finding CVSS (10.0) in the entire engagement. Unauthenticated `passData` endpoint dumps all employee PII including home addresses, DOB, emails, and portal access. All Director finance dashboards (cashier transactions, collections, accounts receivable, expenses) under CORS-only middleware. SSL certificate verification disabled on all inter-school HTTP communication.

---

### 8. Admin Portal (Administrator / AdminAdmin)
**Dates:** June 9, 2026  
**Hours:** 4.5 hours  
**Documents Produced:** `ADMIN_CODE_REVIEW.md`, `ADMIN_EXECUTIVE_SUMMARY.md`, `ADMIN_POC.md`

| Task | Hours |
|---|---|
| Mapped all admin-related routes — `['cors']` group, `['isAdminAdmin']` group, unmiddlewared routes | 0.5 |
| Reviewed `Cor.php` middleware — confirmed zero authentication (CORS headers only) | 0.25 |
| Reviewed `AuthenticateAdmin.php` and `AuthenticateAdminAdmin.php` | 0.25 |
| Read `FNSAccountController.php` — `change_password`, `list`, `create_fas_account`, `update_fas_priv_ajax`, `update_active`, `generateaccount` methods | 2.0 |
| Confirmed unauthenticated password reset resets to known default (`123456`) | 0.25 |
| Confirmed `list()` returns `passwordstr` (plaintext) in JSON response | 0.25 |
| Confirmed `create_fas_account` accepts attacker-controlled `utype` (user type) | 0.25 |
| Verified K-12 grade approve/post routes completely outside all middleware | 0.25 |
| Verified `/studentmasterlist`, `/cashtransaction`, `/targetcollection` — no middleware | 0.25 |
| Wrote all three Admin portal documents | 0.25 |

**Findings:** 8 security findings (3 CRITICAL, 4 HIGH, 1 MEDIUM) + 2 backend bugs  
**Key Issues Identified:** `cors` middleware provides zero authentication — all 18+ faculty/staff account management routes are fully unauthenticated. Unauthenticated password reset (`GET /administrator/setup/accounts/updatepass?tid=<email>`) resets any account to `123456`. Unauthenticated staff account list returns `passwordstr` (plaintext passwords). Unauthenticated account creation with attacker-controlled user type. K-12 grade approval/posting outside all middleware. AdminAdmin enrollment and cash transaction reports outside all middleware.

---

### 7. Parent Portal
**Dates:** June 9, 2026  
**Hours:** 4.0 hours  
**Documents Produced:** `PARENT_CODE_REVIEW.md`, `PARENT_EXECUTIVE_SUMMARY.md`, `PARENT_POC.md`

| Task | Hours |
|---|---|
| Mapped all parent-related routes — identified 10 routes outside all middleware | 0.5 |
| Reviewed `AuthenticateParent` middleware — noted missing `currentPortal` check | 0.25 |
| Read `LoginController.php` — confirmed both type=7 and type=9 share `studentInfo` session key | 0.5 |
| Read `ParentsController.php` (~1,450 lines) — traced all unprotected methods | 1.5 |
| Read `ParentServerEventController.php` | 0.25 |
| Traced `parentEnterAmount` — confirmed no amount validation, unvalidated extension | 0.5 |
| Wrote all three Parent portal documents | 0.5 |

**Findings:** 7 security findings (2 HIGH, 2 MEDIUM, 2 LOW, 1 INFO) + 3 backend bugs  
**Key Issues Identified:** 7 grade/billing/attendance data endpoints outside all middleware — students bypass `isParent` via shared `studentInfo` session key. Online payment submission (`POST /parentEnterAmount`) outside all middleware — fake payment records with negative amounts accepted. Receipt upload uses unvalidated file extension.

---

### 10. HR Portal
**Date:** June 11, 2026  
**Hours:** 4.5 hours  
**Documents Produced:** `HR_CODE_REVIEW.md`, `HR_EXECUTIVE_SUMMARY.md`, `HR_POC.md`

| Task | Hours |
|---|---|
| Located HR middleware (`AuthenticateHumanResource.php`) and analyzed null dereference + refid bypass | 0.5 |
| Mapped all HR route groups in `routes/web.php` — two `isHumanResource` groups + two `['auth', 'web']` groups | 0.5 |
| Read `HREmployeesController.php` — PII export, N+1 queries, addnewemployeesave flow | 0.75 |
| Read `HREmployeeProfileController.php` — IDOR on employeeid, debug endpoint, auto-insert side effect | 0.75 |
| Read `HREmployeeCredentialsController.php` — file upload, client extension, web-accessible storage | 0.5 |
| Read `HRAttendanceController.php` — GET verb on state-changing routes, no ownership checks | 0.5 |
| Read `HRAttendanceuploadController.php` — last-name-only matching, destructive delete-then-insert | 0.5 |
| Read `HRPayrollV3Controller.php` — voidpayslip, editpayslip, batchgenerateemployeepayroll | 0.5 |
| Wrote `HR_CODE_REVIEW.md`, `HR_EXECUTIVE_SUMMARY.md`, `HR_POC.md` | 1.0 |

**Findings:** 12 security findings (1 CRITICAL, 6 HIGH, 4 MEDIUM, 1 LOW) + 7 backend bugs  
**Key Issues Identified:** `isHumanResource` middleware bypassed via `refid == 26` — any authenticated user can gain full HR access by manipulating the `currentPortal` session variable. HR notification routes (send, read, reply, attach) accessible to any authenticated user — no HR role check. Employee self-service routes (DTR, leave, payroll, overtime) accessible to any authenticated user via IDOR on employee ID. Credential file upload stores files in `public/` with client-controlled extension — PHP web shell upload path to RCE. Any HR user can void any released payslip with no secondary authorization or approval workflow. Attendance upload matches employees by last name only — crafted Excel file can overwrite any target employee's punch records. Employee export delivers statutory IDs (SSS, TIN, PhilHealth, Pag-IBIG) for all employees in a single request.

---

### 11. Accounting Portal
**Date:** June 11, 2026  
**Hours:** 3.5 hours  
**Documents Produced:** `ACCOUNTING_CODE_REVIEW.md`, `ACCOUNTING_EXECUTIVE_SUMMARY.md`, `ACCOUNTING_POC.md`

| Task | Hours |
|---|---|
| Read `AuthenticateAccounting.php` — identified refid bypass, no-return path, null dereference | 0.25 |
| Mapped both `['auth', 'isAccounting']` route groups in `routes/web.php` (lines 1746–1877, 4354–4400) | 0.5 |
| Read `routes/accountingv2.php` — mapped all 22 AccountingV2 controllers and route structure | 0.75 |
| Read `AccountingController.php` — journal entry creation, editing, postje, is_generate | 0.75 |
| Read `PurchasingController.php` — vendor CRUD, purchase_create, purchase_post, purchase_delete | 0.5 |
| Read `AccountingV2Controller/JournalVoucherController.php` — validated input handling | 0.25 |
| Confirmed all Gen 1 state-changing routes are GET (no CSRF) | 0.25 |
| Confirmed AccountingV2 write routes are `['auth']` only — any user modifies accounting | 0.25 |
| Wrote all three Accounting portal documents | 0.0 (counted in Bookkeeper session) |

**Findings:** 6 security findings (1 CRITICAL, 3 HIGH, 2 MEDIUM) + 4 backend bugs  
**Key Issues Identified:** `isAccounting` middleware bypassed via `refid == 19 || refid == 33` — any authenticated user gains full accounting access via session manipulation. All Gen 1 COA, journal entry, and purchasing operations are GET routes (no CSRF — malicious link can post/delete journal entries). AccountingV2 COA, journal vouchers, fixed assets, and supplier records writable by any authenticated user (no accounting role check). All financial statement exports (income statement, balance sheet, general ledger, trial balance) accessible to any authenticated student. `isBookkeeperAdmin` bypassable via `currentPortal == 67`.

---

### 12. Bookkeeper Portal
**Date:** June 11, 2026  
**Hours:** 3.0 hours  
**Documents Produced:** `BOOKKEEPER_CODE_REVIEW.md`, `BOOKKEEPER_EXECUTIVE_SUMMARY.md`, `BOOKKEEPER_POC.md`

| Task | Hours |
|---|---|
| Read `AuthenticateBookkeeperAdmin.php` — identified `currentPortal == 67` bypass | 0.25 |
| Read `RouteServiceProvider::mapBookkeeperRoutes()` — confirmed zero auth middleware | 0.25 |
| Read `routes/bookkeeper.php` (200+ lines) — catalogued all unauthenticated routes | 0.75 |
| Read `BookkeeperController.php` — examined storecoa, v2_voidtransactions, COA ID assignment | 1.0 |
| Read `BookkeeperControllers/ExpensesItemController.php` — confirmed no input validation | 0.25 |
| Read `routes/accountingv2.php` isBookkeeperAdmin sub-groups — confirmed approve/close/activate operations | 0.25 |
| Wrote all three Bookkeeper portal documents | 0.25 |

**Findings:** 6 security findings (2 CRITICAL, 2 HIGH, 2 MEDIUM) + 3 backend bugs  
**Key Issues Identified:** `bookkeeper.php` is the only module in the entire system loaded with zero authentication middleware (`middleware('web')` only). Every route — 150+ endpoints — is accessible without login. Unauthenticated internet users can download complete financial statements (income statement, balance sheet, general ledger, cashflow, equity, trial balance, disbursements). Transaction void routes are accessible without authentication. `isBookkeeperAdmin` bypassable via `currentPortal == 67` session manipulation.

---

### 13. TESDA / Admission / Guidance / Document Tracking / Library (Other Modules)
**Date:** June 13, 2026  
**Hours:** 2.5 hours  
**Documents Produced:** `OTHER_MODULES_CODE_REVIEW.md`, `OTHER_MODULES_EXECUTIVE_SUMMARY.md`, `OTHER_MODULES_POC.md`

| Task | Hours |
|---|---|
| Read `routes/tesda.php` (220 lines) — confirmed all routes are unauthenticated | 0.25 |
| Read `routes/admission.php` — mapped public applicant flow + admin auth group | 0.25 |
| Read `routes/guidance.php` — confirmed `['auth']` only, no role check | 0.25 |
| Read `routes/documenttracking.php` — confirmed `['auth']` only, state-changing GETs | 0.25 |
| Read `routes/library.php` — mapped public catalogue, auth group, admin sub-group | 0.25 |
| Read `AdmissionController.php` — analyzed `student_info_update()` (IDOR), `save_answer()` (score tampering), `student_info_save()` (mass assignment), `diagnostic_view()` (null deref bug) | 0.75 |
| Wrote `OTHER_MODULES_CODE_REVIEW.md`, `OTHER_MODULES_EXECUTIVE_SUMMARY.md`, `OTHER_MODULES_POC.md` | 0.5 |

**Findings:** 7 security findings (1 CRITICAL, 3 HIGH, 2 MEDIUM, 1 LOW) + 2 backend bugs  
**Key Issues Identified:** Entire TESDA portal unauthenticated (same root cause as Bookkeeper — `mapTesdaRoutes()` uses `middleware('web')` only) — student PII, enrollment management, COR/TOR printing, grade submission, national certificates all accessible without login. Unauthenticated IDOR on admission `update-student-info` — any internet visitor can overwrite any applicant's registration data by supplying a sequential integer ID. Exam answer tampering via `GET /admission/save-answer` — attacker-controlled `studid` and `points` fields with no ownership check. Mass assignment in student registration — all POST fields inserted directly into DB row. Any authenticated user can delete guidance exam setup and referrals (no role check). Any authenticated user can forward/reject/close any document in the tracking system.

---

## Engagement Totals

| Module | Hours | Findings | Critical | High |
|---|---|---|---|---|
| SuperAdmin | 8.0 | 12 | 2 | 4 |
| Teacher | 6.0 | 15 | 1 | 5 |
| Student | 5.5 | 10 | 1 | 3 |
| Registrar | 4.25 | 9 + 4 bugs | 2 | 3 |
| College | 5.0 | 10 + 5 bugs | 1 | 5 |
| Principal | 4.5 | 6 + 7 bugs + 4 FE | 2 | 2 |
| Director | 2.5 | 6 + 4 bugs | 3 | 2 |
| Admin | 4.5 | 8 + 2 bugs | 3 | 4 |
| Parent | 4.0 | 7 + 3 bugs | 0 | 2 |
| HR Portal | 4.5 | 12 + 7 bugs | 1 | 6 |
| Accounting | 3.5 | 6 + 4 bugs | 1 | 3 |
| Bookkeeper | 3.0 | 6 + 3 bugs | 2 | 2 |
| **Other Modules** | **2.5** | **7 + 2 bugs** | **1** | **3** |
| **Total** | **57.75** | **114 + 41 bugs + 4 FE** | **20** | **44** |

**Modules Not Covered (done by others):** Finance V2, Cashier V2  
**All route files reviewed.**

---

## Notes

- All modules were reviewed by static analysis only — no dynamic testing was performed
- PoC scripts were written for all critical and high findings but not executed against the production system
- The `Analysis Docs/` folder at the project root contains all deliverables
- Findings count reflects unique issues only — related variants are grouped under parent findings
- Dates reflect active work sessions; brief interruptions and context switches are included in reported hours

---

*End of Workload Report*
