# Parent Portal — Executive Security Summary
**Date:** June 08, 2026  
**Classification:** Internal — Restricted  
**Module:** Parent Portal (type=9)  
**Reviewer:** Internal Red Team

---

## Executive Overview

The Parent portal gives parents visibility into their child's academic performance, billing, and attendance. It is a read-heavy module — but it also hosts the online payment submission flow, which introduces write-side risks.

The review found **7 security findings** (2 HIGH, 2 MEDIUM, 2 LOW, 1 INFO) and **3 backend bugs**. The defining issue is architectural: the most data-heavy parent endpoints (grades, billing, ledger, attendance) sit completely outside Laravel's authentication middleware, relying solely on a PHP session key that students also set at login. A secondary issue is the online payment submission endpoint — also outside middleware — which accepts user-controlled amounts including negative values.

**Overall Risk Rating: HIGH**

---

## Risk Summary Table

| ID | Severity | CVSS | Title | Auth Required |
|---|---|---|---|---|
| P-01 | **HIGH** | 6.5 | 7 Data Endpoints Outside Auth Middleware — Accessible to Students | Session only |
| P-02 | **HIGH** | 7.5 | Online Payment Submission Outside All Middleware | Session only |
| P-03 | MEDIUM | 5.3 | Negative / Zero Amount Accepted in Payment | Session |
| P-04 | MEDIUM | 4.2 | Receipt Upload — Unvalidated File Extension | Session |
| P-05 | LOW | 3.1 | Testing Route in Production Exposes Section Data | None |
| P-06 | LOW | 2.1 | Student Photo Update Outside `isParent` Middleware | Session |
| P-07 | INFO | — | `isParent` Lacks `currentPortal` Check — Inconsistent Pattern | N/A |

---

## Attack Chains

### Chain A — Student Bypasses Parent Portal Access Control (P-01)

**Threat actor:** Any logged-in student  
**Impact:** Student accesses parent portal data endpoints without `isParent` check  
**Complexity:** Low — standard login, no special tools needed

```
Step 1:  Student logs in normally via POST /login (type=7)
         → LoginController sets: Session::put('studentInfo', $studentData)

Step 2:  Student calls GET /parent/enrollment/billing
         → No 'auth' or 'isParent' middleware on this route
         → Session::get('studentInfo') returns their own student data
         → Student receives billing data through the parent endpoint

Step 3:  Student calls GET /parent/enrollment/record/grades
         → Full grade data returned through parent's grade API
         → isParent middleware completely bypassed

Step 4:  Student calls GET /parent/enrollment/ledger
         → Full payment ledger returned — same data as parent sees
```

**Why this matters beyond "same data":**
- The parent endpoint has different business logic than the student endpoint — if future code adds parent-exclusive features (e.g., approval controls, contact updates), they inherit this bypass
- Students can detect parent-only AJAX endpoints and probe for features not visible from the student portal
- The `isParent` role check provides zero protection for these routes

---

### Chain B — Fake Online Payment Record Submission (P-02 + P-03)

**Threat actor:** Any session-bearing user (student, teacher, any type with `studentInfo`)  
**Impact:** Fraudulent payment records in `onlinepayments` table — finance staff waste time processing fake submissions  
**Complexity:** Low

```
Step 1:  Any user with an active session calls POST /parentEnterAmount
         {
           "studid": "1001",
           "paymentType": "1",
           "recieptImage": <valid image file>,
           "amount": "-5000",           ← no minimum validation
           "refNum": "REF-FAKE-001",
           "transDate": "2026-06-11"
         }

Step 2:  No middleware blocks the request
         → amount="-5000" passes validation (only 'required' is checked)
         → Record inserted into onlinepayments with negative amount
         → Finance staff see it in their approval queue

Step 3:  If finance staff approve the -5000 entry
         → Negative credit applied to student ledger
         → Student's balance artificially reduced
```

---

### Chain C — Registrar Breach Enables Payment Fraud (R-01 → P-02)

Combining Registrar finding R-01 with Parent P-02:

```
Step 1:  GET /fixAccountConflict (Registrar R-01)
         → Creates parent accounts with password=123456 for all students
         → Account email format: P<sid>

Step 2:  POST /login { email: "P1001", password: "123456" }
         → Authenticated as parent of student 1001
         → Session::put('studentInfo', ...) set for student 1001

Step 3:  POST /parentEnterAmount { amount: "-99999", refNum: "XXXX", ... }
         → Fraudulent payment record submitted for student 1001
```

The Registrar chain creates accounts; the Parent chain submits payment fraud. Both are unauthenticated / easily authenticated.

---

## Affected Components

| Component | Risk | Action |
|---|---|---|
| 7 `/parent/enrollment/*` routes | HIGH | Move inside `['auth', 'isParent']` |
| `POST /parentEnterAmount` | HIGH | Move inside `['auth', 'isParent']` + add amount validation |
| `GET /getremBill` | MEDIUM | Move inside `['auth', 'isParent']` |
| `POST /parent/update/studpic` | LOW | Move inside `['auth', 'isParent']` |
| `GET /testingesayloading` | LOW | Remove from production |
| `loadGrades()` dead code | BUG | Fix unreachable grade logic block |

---

## Compliance Impact

| Standard | Impact |
|---|---|
| **Data Privacy Act (R.A. 10173)** | P-01 exposes student academic records, billing, and ledger to any authenticated user bypassing role control |
| **Financial Controls** | P-02/P-03 allow submission of fraudulent payment records with arbitrary amounts — compromise of financial integrity |
| **ISO/IEC 27001 A.9.4** | Incomplete access control — `isParent` middleware rendered ineffective for the most sensitive data routes |

---

## Finding Count by Severity

| Severity | Count |
|---|---|
| High | 2 |
| Medium | 2 |
| Low | 2 |
| Info | 1 |
| Bugs | 3 |
| **Total** | **10** |

---

*End of Parent Portal Executive Summary*
