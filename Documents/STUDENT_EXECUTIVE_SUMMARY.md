# Student Portal — Executive Security Summary
**Date:** June 3, 2026  
**Classification:** Internal / Confidential  
**Module:** Student Portal (`type=7`, `isStudent` middleware)

---

## 1. At-a-Glance

| Metric | Value |
|---|---|
| Controllers Reviewed | 8 / 8 (100%) |
| Total Findings | 10 |
| Critical | 2 |
| High | 4 |
| Medium | 2 |
| Low | 2 |
| Backend Bugs | 5 |
| Frontend Bugs | 1 |
| Unauthenticated Attack Surface | 5 routes |

---

## 2. Risk Table

| ID | Severity | CVSS | Title | Authentication Required |
|---|---|---|---|---|
| ST-01 | **CRITICAL** | 9.9 | RCE via Unrestricted File Upload (Scholarship) | Any login (type agnostic) |
| ST-02 | **CRITICAL** | 7.5 | Unauthenticated SMS Injection via tapbunker | **None** |
| ST-03 | **HIGH** | 7.5 | Unauthenticated IDOR — Full Student Financial Records | **None** |
| ST-04 | **HIGH** | 7.5 | Unauthenticated IDOR — Grades & Class Schedule | **None** |
| ST-05 | **HIGH** | 6.5 | Cleartext Password Stored in Audit Log Table | Student login |
| ST-06 | **HIGH** | 6.5 | IDOR — Unauthorized Scholarship Application Deletion | Any login |
| ST-07 | MEDIUM | 5.4 | Privilege Confusion — Student Routes Under `auth` Only | Any login |
| ST-08 | MEDIUM | 6.5 (intent) | Missing Auth on Survey Submission Routes | **None** (but 500s) |
| ST-09 | LOW | 3.1 | Profile Photo — No Content Validation | Student login |
| ST-10 | LOW | N/A | Duplicate Route Definitions | N/A |

---

## 3. Critical Findings Detail

### ST-01: RCE via Scholarship File Upload
`POST /uploadrequirement` accepts any file extension because it calls `$file->getClientOriginalExtension()` — attacker-supplied. The upload destination is `public/scholarship/`, which is directly web-accessible. An attacker with **any** login can upload `evil.php`, navigate to its URL, and execute arbitrary PHP on the server.

This is the same RCE pattern found in the SuperAdmin module (`PoC-9: PreSchoolGrading webshell`) but accessible to a much broader audience — any authenticated user, not just admins.

**One-liner test:**
```bash
curl -X POST -b "laravel_session=<ANY>" -F "file=@shell.php" http://app/uploadrequirement
# then visit: http://app/scholarship/<timestamp>.php?cmd=id
```

### ST-02: Unauthenticated SMS Injection
`POST /student/notify_individual_student` is under `['cors']` middleware only — which adds CORS response headers and does nothing else. Zero authentication. Any person on the internet can queue an SMS to any phone number, draining the school's SMS balance and potentially harassing individuals.

---

## 4. Attack Chains

### Chain A: Anonymous Internet User → Full Data Breach
```
1. Enumerate students: GET /api/mobile/api_student_ledger_v2?studid=1,2,3,...
   → Full financial records for every student (balances, payment history, billing, photo URL)

2. Enumerate grades: GET /api/mobile/api_reportcard_v2?studid=X&syid=1
   → Complete grade report card for any student

3. Enumerate schedules: GET /api/mobile/api_class_schedule_v2?studid=X&syid=1
   → Full class schedule including teacher names, room locations, times
```
**No account needed.** studid values start from 1 and increment sequentially.

---

### Chain B: Student Login → RCE → Full Server Compromise
```
1. Login as any student (type=7)

2. POST /uploadrequirement with file=webshell.php
   → File saved to public/scholarship/<timestamp>.php

3. GET http://app/scholarship/<timestamp>.php?cmd=id
   → Code executes as PHP web process

4. Escalate:
   → Read .env → grab DB_PASSWORD → dump all tables
   → Read app key → forge session cookies for any user
   → Write cron job for persistence
```
**3 HTTP requests from student login to full server control.**

---

### Chain C: Anonymous User → SMS Flood / Financial Damage
```
1. No login needed

2. Loop: POST /student/notify_individual_student  phone=<victim>
   → Inserts N rows into tapbunker with smsstatus=1

3. SMS daemon sends N messages to victim's phone
   → Harassment + SMS credit depletion for the school
```

---

### Chain D: Student Login → Delete Competitor's Scholarship
```
1. Login as Student A

2. GET /student/scholarship → note scholarshipapplicant IDs visible in JSON
   → Try adjacent IDs for other students' applications

3. POST /student/delete/scholarship  id=<victim_scholarship_id>
   → Soft-deletes scholarship application of another student
   → Finance/registrar never sees the application
```

---

## 5. Comparison to Other Portals

| Portal | Critical | High | Medium | Low | Worst Finding |
|---|---|---|---|---|---|
| SuperAdmin | 3 | 8 | 7 | 2 | eval()-based RCE (College module) |
| Teacher | 4 | 4 | 5 | 2 | Mass password reset (T-13) |
| **Student** | **2** | **4** | **2** | **2** | File upload RCE + Unauthenticated IDOR |

**Unique to Student portal:** The presence of **fully unauthenticated** data access routes (no session at all) is the most severe exposure across all reviewed portals. Other portals require at minimum a valid login. The student portal leaks grades, schedules, and financial data to the entire internet.

---

## 6. Compliance Impact

| Regulation | Violated? | Finding |
|---|---|---|
| **Data Privacy Act of 2012 (RA 10173)** | YES | ST-03/ST-04: Personal data (grades, financials) exposed without consent |
| **FERPA (if applicable)** | YES | Student education records accessible without authentication |
| **PCI-DSS (if payment data stored)** | YES | ST-05: Passwords in logs; ST-03: Financial data unauthenticated |
| **OWASP Top 10** | Multiple | A01 (IDOR), A03 (Injection/Upload), A07 (Auth failure) |

---

## 7. Remediation Roadmap

### Immediate (0–48 hours)
1. **Disable or require auth on all `/api/mobile/*` routes** — add `['auth']` minimum, scope `studid` to logged-in user
2. **Add `['auth']` to `/student/notify_individual_student`** — stop unauthenticated SMS queuing
3. **Fix scholarship file upload** — validate MIME, whitelist extensions, move outside `public/`
4. **Remove password from `updatelogs`** — delete `$request->get('password')` concatenation

### Short-term (1 week)
5. Move `['auth']`-only student routes into `['auth', 'isStudent']` group
6. Add ownership check to `delscholarship()`
7. Add `['auth', 'isStudent']` to survey form routes

### Medium-term (2–4 weeks)
8. Fix dead code in `loadGrades()` — restore college grading page
9. Remove duplicate route registrations
10. Add CSRF token verification to all POST routes
11. Audit `tapbunker` queue for orphaned malicious entries

---

## 8. Coverage

- **100%** of `StudentControllers/` reviewed (8/8 controllers)
- **100%** of student-related routes in `web.php` reviewed (lines 100–260, 5363–5367, 7181–7195)
- Routes not under `StudentControllers/` but reachable from student portal (e.g., `RegistrarControllers\StudentRequirementsController`, `ApplicationFormsController`) noted but reviewed within their respective portal analyses

---

*End of Student Portal Executive Summary*
