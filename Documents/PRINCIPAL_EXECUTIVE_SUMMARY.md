# Principal Portal — Executive Summary
**Date:** June 09, 2026  
**Module:** Principal Portal  
**Reviewer:** Internal Red Team  
**Risk Level:** CRITICAL

---

## Overview

The Principal portal's core security failure is architectural: the `isPrincipal` middleware was written correctly and registered in the application kernel, but was never applied to any route. As a result, the entirety of the Principal module — grade posting, approval, SF9 signatory management, deportment conduct grading, section management, and student honors — is accessible to any logged-in user regardless of their role.

Compounding this, two deportment grade-write endpoints are outside all middleware entirely, making them accessible to unauthenticated internet users.

Beyond access control, the module contains a cluster of backend bugs that cause null-pointer crashes, a stored XSS in the principal's own deportment table, a file race condition in award certificate generation, and frontend presentation issues including persistent misspellings visible to end users.

---

## Risk Summary Table

| ID | Severity | Finding | CVSS |
|---|---|---|---|
| PR-01 | **CRITICAL** | `isPrincipal` middleware exists but is never applied — any auth user has full Principal access | 8.8 |
| PR-02 | **CRITICAL** | Deportment grade-status write endpoints — no middleware, fully unauthenticated | 7.5 |
| PR-03 | **HIGH** | Grade post/approve/unpost under `isDefaultPass` only — no role check | 8.1 |
| PR-04 | **HIGH** | SF9 report card signatory CRUD under `['auth']` only — any user can overwrite | 8.1 |
| PR-05 | **MEDIUM** | IDOR in section profile — decrypt exception silently swallowed, plain integer accepted | 4.3 |
| PR-06 | **MEDIUM** | Unauthenticated deportment routes crash on `auth()->user()->id` call (500 leak) | 5.3 |
| BUG-PR-01 | **Bug** | "Aproved"/"Succesfully" typos hardcoded in API responses and UI labels | — |
| BUG-PR-02 | **Bug** | Null dereference in `loadtable()` when `deportment_hps` record does not exist | — |
| BUG-PR-03 | **Bug** | `store_error()` throws secondary exception when called from unauthenticated context | — |
| BUG-PR-04 | **Bug** | `loadAverageType()` throws on null DB result | — |
| BUG-PR-05 | **Bug** | Award certificate `.docx` race condition — concurrent requests overwrite each other | — |
| BUG-PR-06 | **Bug** | Stored XSS via unescaped student names in deportment HTML table | — |
| BUG-PR-07 | **Bug** | `$status`/`$color` uninitialized in female student loop — stale value bleed | — |
| FE-PR-01 | **Frontend** | "Aproved" label visible to principal in grade status badges | — |
| FE-PR-02 | **Frontend** | Green badge for "Submitted" grades misleads users into thinking grades are finalized | — |
| FE-PR-03 | **Frontend** | Summary page entirely blank — full implementation commented out | — |
| FE-PR-04 | **Frontend** | Award certificate `Content-Disposition` filename header not quoted | — |

**Module totals: 2 Critical, 2 High, 2 Medium, 6 Bugs, 4 Frontend Issues**

---

## Highest-Impact Attack Chains

### Chain 1: Any Student Self-Approves Their Own Grade (PR-01 + PR-03)
```
1. Student logs in via student portal
2. Student calls:
   GET /posting/grade/approve?gdid=<student_own_gradeid>&studid=<own_studid>&quarter=1&syid=<syid>&semid=<semid>
   — Middleware: auth + isDefaultPass (no role check)
   — Result: student's own grade submission moves to "Approved" status
3. Student calls:
   GET /posting/grade/post?gdid=<gradeid>&studid=<own_studid>&quarter=1&syid=<syid>
   — Result: grade is permanently posted to academic record
4. Student bypasses the teacher → principal review workflow entirely
```

### Chain 2: Any Student Rewrites Report Card Signatory (PR-04)
```
1. Logged-in student calls:
   GET /setup/signatories/update/sf9?id=1&name=Hacked+Principal&title=Attacker&acadprogid=2&syid=<active_syid>
   — Middleware: auth only
   — Result: "Hacked Principal / Attacker" is now the printed signatory on all K-12 SF9 report cards
2. All SF9 forms generated until fixed show the tampered name
```

### Chain 3: Unauthenticated Bulk Conduct Grade Manipulation (PR-02)
```
1. No credentials needed
2. Enumerate known section IDs and school year IDs from any public page or prior enumeration
3. GET /posting/grade/update-grade-status
     ?array[]=<studid1>&array[]=<studid2>
     &syid=<syid>
     &sectionid=<sectionid>
     &quarter_ID=2
     &status=5
     &hpsid=<hpsid>
   — Response: {"status":200,"statusCode":"success","message":"Succesfully Approved!"}
   — Result: selected students' deportment conduct grades moved to status 5 (Posted)
   — No authentication required
```

### Chain 4: Teacher Self-Posts Grades After Rejection (PR-03)
```
1. Teacher's grade submission is returned to "Pending" by principal
2. Teacher (authenticated, changed default password) calls:
   GET /posting/grade/approve?gdid=<gdid>&studid=<studid>&quarter=2&syid=<syid>
   — Passes isDefaultPass check, no isPrincipal check
   — Grade re-approved without principal review
3. Teacher then calls:
   GET /posting/grade/post?gdid=<gdid>&studid=<studid>&quarter=2
   — Grade posted to official record
```

---

## Business Impact

| Area | Impact |
|---|---|
| **Academic Integrity** | Any authenticated user can post, approve, or unpost any student's K-12 grades — bypassing the entire teacher→principal verification chain |
| **Report Card Integrity** | The name and title printed on all official SF9 forms can be overwritten by any logged-in user |
| **Conduct Records** | Deportment (conduct) grade statuses writable by unauthenticated external parties |
| **Student Privacy** | Full enrolled student lists, grade submission status, and honors rankings accessible to any portal user |
| **DepEd Compliance** | Unauthorized grade manipulation violates DepEd Order No. 8 s. 2015 (Policy on Grading System) and may affect school accreditation |

---

## Remediation Priority

**Immediate (this sprint):**
1. Apply `['auth', 'isPrincipal']` to all route groups currently using `['auth']` or `['auth', 'isDefaultPass']` for Principal operations
2. Move `update-grade-status` and `update-stud-gradstatus` into `['auth', 'isPrincipal']`
3. Apply `htmlspecialchars()` to student names in `loadtable()` HTML generation (BUG-PR-06)
4. Add null guard on `$deportmentID` and `$hps` in `loadtable()` (BUG-PR-02)

**Short term:**
5. Fix `loadSectionProfile` to `abort(404)` on decrypt failure instead of silently continuing
6. Fix `loadAverageType` null check
7. Save award `.docx` files to `storage/app/temp/<uuid>/` to eliminate race condition
8. Add `auth()->check()` guard to `store_error()`

**Low effort / quick wins:**
9. Find-replace all `"Aproved"` → `"Approved"`, `"Succesfully"` → `"Successfully"`
10. Quote `Content-Disposition` filename in `print_award()`
11. Initialize `$status = ''` and `$color = ''` before each loop iteration
12. Replace `count($items) != null` with `count($items) > 0`

---

*End of Principal Portal Executive Summary*
