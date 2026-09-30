# Auxiliary Modules — Executive Summary
## TESDA · Admission · Guidance · Document Tracking · Library
**Date:** June 13, 2026  
**Prepared for:** School Management — Leadership & IT Team

---

## At a Glance

| # | ID | Severity | Module | Issue |
|---|---|---|---|---|
| 1 | AUX-01 | 🔴 CRITICAL | TESDA | Entire TESDA portal is unauthenticated |
| 2 | AUX-02 | 🟠 HIGH | Admission | IDOR: any visitor can overwrite any applicant's info |
| 3 | AUX-03 | 🟠 HIGH | Admission | Any visitor can tamper with exam answers for any applicant |
| 4 | AUX-04 | 🟠 HIGH | Admission | Mass assignment: caller controls all columns on student registration |
| 5 | AUX-05 | 🟡 MEDIUM | Guidance | Any logged-in user can delete exam setup and referrals |
| 6 | AUX-06 | 🟡 MEDIUM | DocTracking | Any logged-in user can forward, reject, or close any document |
| 7 | AUX-07 | 🔵 LOW | Library | `pinbook` is a state-changing GET without login |
| 8 | BUG-AUX-01 | Bug | Admission | `diagnostic_view()` crashes on invalid pooling number |
| 9 | BUG-AUX-02 | Bug | TESDA | Any auth user can re-run database seeders in production |

**Total findings: 7 security + 2 bugs**  
**Critical: 1 | High: 3 | Medium: 2 | Low: 1 | Bugs: 2**

---

## AUX-01 — CRITICAL: The Entire TESDA Portal Requires No Login

**What it means:** Every TESDA page — student records, enrollment management, transcript printing, grade submission, course setup — is accessible from the internet with no login.

**What an attacker can do today:**
- Open `http://[SCHOOL-DOMAIN]/tesda/getStudent` to download all TESDA student records
- Open `http://[SCHOOL-DOMAIN]/tesda/printTORall` to print every student's Transcript of Records as a PDF
- Send `DELETE /tesda/delete-student/1` to begin deleting student records one by one
- Submit `POST /tesda/trainer/systemgrades/submit_grades` to insert fabricated grades into the system
- Print national certificates and honorable dismissal documents for arbitrary students

**Why it happened:** The system's route provider loads `tesda.php` with `middleware('web')` only. No `auth` group was ever added inside the route file. This is the same configuration bug already found in the Bookkeeper portal.

**The fix is one line in `RouteServiceProvider.php`:**
```php
// Change:  ->middleware('web')
// To:      ->middleware(['web', 'auth'])
```

---

## AUX-02 — HIGH: Any Internet Visitor Can Overwrite Another Applicant's Registration

**What it means:** The admission update endpoint (`POST /admission/update-student-info`) is intentionally unauthenticated (for public applicants). However, it accepts a record `id` from the caller with no ownership check. Anyone who discovers an applicant's sequential integer ID (e.g., `id=42`) can overwrite their name, contact number, date of birth, exam slot, and academic program — even without knowing anything else about them.

**Impact:** An applicant's registration can be corrupted (wrong exam slot, wrong grade level) by any internet visitor. This could be used to disqualify targeted students from the admissions process.

**The fix:** Issue a secure random token at registration time (stored in the session). Require that token — instead of the raw database ID — for the update operation.

---

## AUX-03 — HIGH: Any Internet Visitor Can Tamper With Any Applicant's Exam Answers

**What it means:** `GET /admission/save-answer` is unauthenticated and accepts a `studid` parameter from the caller. Anyone can submit or overwrite exam answers for any other applicant by providing their `studid`. The caller also supplies the `points` value directly — the server does not compute points from the answer key — making it trivial to inflate any student's score.

**Impact:** Deliberate sabotage of a target student's exam results (set all answers to wrong) or score inflation of a favored student by pre-submitting correct answers with high points values.

**The fix:** Bind `studid` to the session's registered applicant (not a caller-supplied parameter). Compute `points` server-side from the answer key.

---

## AUX-04 — HIGH: Admission Registration Inserts All POST Fields Unfiltered

**What it means:** The student registration handler uses `$request->except(['_token'])` to build the INSERT statement — meaning every field in the POST body (except `_token`) goes directly into the database row. If the `admission_student_information` table has columns like `status`, `accepted`, or `verified`, an attacker can set them at registration time and bypass verification steps.

**The fix:** Replace the catch-all insert with an explicit allowlist of permitted fields.

---

## AUX-05 — MEDIUM: Any Logged-In User Can Delete Guidance Exam Setup and Referrals

**What it means:** Every guidance endpoint — exam question management, exam date scheduling, passing rate configuration, counseling referrals — is protected by login only. There is no guidance-specific role check. A student or teacher who discovers the endpoints can delete exam questions or all upcoming exam dates for the current school year.

**The fix:** Add a role-based middleware check (guidance officer or admin) before guidance management routes. Move destructive operations from GET to POST.

---

## AUX-06 — MEDIUM: Any Logged-In User Can Interfere With Any Document's Routing Workflow

**What it means:** Document tracking operations (forward, receive, reject, close) are protected by login only. There is no check that the caller is the current document holder or designated signatory. Any employee with a system account can forward any document to an unintended recipient, reject documents they were never sent, or permanently close documents in progress.

**The fix:** Add an ownership or signatory check — verify that the user is the current holder of the document before allowing state transitions.

---

## BUG-AUX-02 — Any Authenticated User Can Re-Seed the Production Database

A development route (`GET /tesda/seedtesda`) is reachable in production. It runs `db:seed --force` — overwriting live data — for any logged-in user of any role. This route should be removed entirely.

---

## Combined Risk Rating

| Module | Risk Level | Primary Concern |
|---|---|---|
| TESDA | **CRITICAL** | Zero authentication — all data exposed to internet |
| Admission | **HIGH** | IDOR + exam tampering + mass assignment |
| Guidance | **MEDIUM** | No role check — any user can corrupt exam configuration |
| Document Tracking | **MEDIUM** | No ownership check — any user disrupts any document workflow |
| Library | **LOW** | Minor state-change GET; well-structured compared to other modules |

---

## Remediation Priority

**Fix today:**
1. Add `auth` to `mapTesdaRoutes()` in `RouteServiceProvider.php`
2. Remove the `GET /tesda/seedtesda` production database seed route
3. Bind admission `update-student-info` and `save-answer` to the session's applicant token — not raw IDs

**Fix this sprint:**
4. Add guidance-specific role middleware
5. Add document ownership check before forward/reject/close
6. Replace mass assignment in `student_info_save` with explicit field allowlist
