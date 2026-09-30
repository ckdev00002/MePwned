# Director Portal — Executive Summary
**Date:** June 10, 2026  
**Module:** Director / AdminAdmin (CORS Group)  
**Reviewer:** Internal Red Team  
**Risk Level:** CRITICAL

---

## Overview

The Director module has two independent but equally severe categories of vulnerability. The first — shared with the Admin portal — is the `cors` middleware misuse: all Director finance dashboards, the `passData` data API, and six AdminAdmin management pages are grouped under a middleware that adds only CORS headers with no authentication. The second is entirely unique to this module: **production database credentials are hardcoded in plain text in the PHP source file**, repeated four times, including the fallback IP address of the production database server.

Together these create a scenario where an attacker can trivially obtain live database credentials from the source code and use them to connect directly to the hosted multi-school database platform, bypassing the application layer entirely.

---

## Risk Summary Table

| ID | Severity | Finding | CVSS |
|---|---|---|---|
| DR-01 | **CRITICAL** | Hardcoded production DB credentials (`ckgroup_dev`/`Sels2019`) + server IP in source code | 10.0 |
| DR-02 | **CRITICAL** | `GET /passData` unauthenticated — dumps all employee PII, attendance, financial receivables | 7.5 |
| DR-03 | **CRITICAL** | All Director finance dashboard pages accessible without authentication | 7.5 |
| DR-04 | **HIGH** | SSL certificate verification disabled for all inter-school HTTP communication | 7.4 |
| DR-05 | **HIGH** | Finance/academic/HR/enrollment admin dashboards all under CORS-only | 7.5 |
| DR-06 | **MEDIUM** | Dynamic DB connection controlled by session `schoolid` — no validation | 6.8 |
| BUG-DR-01 | **Bug** | Empty `else{}` blocks in all 4 methods — null response when `?action=` supplied | — |
| BUG-DR-02 | **Bug** | Null dereference when `schoolid` not in session — immediate 500 | — |
| BUG-DR-03 | **Bug** | DB credentials copy-pasted 4× — rotation risk | — |
| BUG-DR-04 | **Bug** | `date_create()` on invalid input throws uncaught `TypeError` in PHP 8+ | — |

**Module totals: 3 Critical, 2 High, 1 Medium, 4 Bugs**

---

## Highest-Impact Attack Chains

### Chain 1: Source Code to Full Database Compromise
```
1. Attacker obtains source code (GitHub leak, server misconfiguration, LFI, etc.)
2. Reads DirectorFinanceReportsController.php — extracts:
     Host:     141.164.36.7
     User:     ckgroup_dev
     Password: Sels2019
     Port:     3306
3. Connects directly to the production MySQL server:
     mysql -h 141.164.36.7 -u ckgroup_dev -p'Sels2019'
4. SHOW DATABASES; — lists all school databases on the hosted platform
5. SELECT * FROM users; on any school's DB — extracts all account credentials
6. Full compromise of all schools on the hosted platform
```

This attack requires no web application interaction whatsoever after obtaining the source code.

### Chain 2: Unauthenticated Employee PII Dump
```
1. No credentials needed
2. GET /passData?action=getemployees
   — Returns JSON with all active employees:
     firstname, lastname, middlename, gender, DOB, home address, email,
     employment status, hire date, education history, portal access list
3. Data dumped in ~1 second, all staff records in a single response
```

### Chain 3: Unauthenticated Financial Data Access
```
1. GET /passData?action=getreceivables&syid=<syid>&semid=<semid>
   — Returns full accounts receivable per student, per academic program
2. GET /director/finance/cashiertransactionsindex
   — Loads the cashier transactions dashboard (school's full payment history)
3. GET /director/finance/collectionsindex
   — Loads the collections dashboard (revenue by period)
4. No credentials required for any of the above
```

### Chain 4: MITM via Disabled SSL Verification
```
1. Attacker positions on network path between Director server and school instance
2. Intercepts GET /director/finance/cashiertransactionsindex request
3. Director server makes outbound Guzzle call to $url->eslink/passData — SSL disabled
4. Attacker serves forged response (manipulated financial data)
5. Director sees fabricated financial figures on their dashboard
```

---

## Business Impact

| Area | Impact |
|---|---|
| **Full Platform Compromise** | Hardcoded credentials expose all databases for all schools on the hosted platform to anyone with source code access |
| **Employee Privacy (RA 10173)** | All staff PII (addresses, DOB, emails, employment status) exposed via unauthenticated `/passData` endpoint |
| **Financial Confidentiality** | School revenue, cash transactions, collections, and accounts receivable accessible without credentials |
| **Data Integrity** | Disabled SSL verification enables MITM falsification of financial reports seen by the Director |
| **Regulatory Risk** | Violation of RA 10173 (Data Privacy Act) — mass PII exposure; potential violation of BSP and BIR financial data handling requirements |

---

## Remediation Priority

**Immediate (deploy today):**
1. Rotate `ckgroup_dev` password and remove it from source code immediately — move to `.env`
2. Restrict `/passData` to internal IP range OR add `['auth', 'isAdminAdmin']` — this endpoint alone exposes all employee PII
3. Move all Director finance routes out of the `['cors']` group into `['auth', 'isAdminAdmin']`
4. Re-enable SSL verification (`CURLOPT_SSL_VERIFYPEER => true`)

**Short term:**
5. Audit git history to determine whether credentials were ever committed to a remote repository — if so, treat the password as compromised regardless of rotation
6. Refactor the 4× copy-pasted DB connection block into a single private method with credentials from `.env`
7. Add null guard on `Session::get('schoolid')` in all methods
8. Implement `action` parameter handling or return 400 for unsupported actions

---

*End of Director Portal Executive Summary*
