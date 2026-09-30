# HR Portal — Full Code Review
**Date:** June 11, 2026  
**Target:** `app/Http/Controllers/HRControllers/` (50+ files), `AuthenticateHumanResource.php`, HR route groups in `routes/web.php`  
**Methodology:** Static analysis — middleware, routes, controllers, payroll logic, file upload handling, employee data exposure  
**Scope:** Authentication, authorization, data handling, payroll integrity, file uploads, PII exposure, backend reliability

---

## Table of Contents
1. [Module Overview](#1-module-overview)
2. [Middleware Analysis](#2-middleware-analysis)
3. [Route Mapping](#3-route-mapping)
4. [Security Findings](#4-security-findings)
5. [Backend Bug Findings](#5-backend-bug-findings)
6. [Fix Recommendations](#6-fix-recommendations)

---

## 1. Module Overview

The HR Portal is the largest module in the system. It covers the full employee lifecycle and payroll pipeline:

| Subsystem | Key Controllers |
|---|---|
| Employee Management | `HREmployeesController.php`, `HREmployeesControllerV4.php`, `HREmployeeProfileController.php` |
| Payroll (V1/V2/V3/V4) | `HRPayrollController.php`, `HRPayrollV2Controller.php`, `HRPayrollV3Controller.php`, `HRPayrollV4Controller.php`, `HRPayrollDailyController.php`, `HRPayrollWeeklyController.php` |
| Attendance | `HRAttendanceController.php`, `HRAttendanceuploadController.php` |
| Leaves / Overtime | `HRLeavesController.php`, `HROvertimeController.php` |
| Deductions & Allowances | `HRDeductionSetupController.php`, `HRAllowanceSetupController.php`, `HREmployeeDeductionsController.php`, `HREmployeeAllowancesController.php` |
| Employee Credentials | `HREmployeeCredentialsController.php`, `HREmployeeProfile/HRCredentialInfoController.php` |
| Payslip / Reports | `HRPayrollHistoryController.php`, `HRSummaryController.php`, `HREmployeePrintablesController.php` |
| 13th Month Pay | `HREmployeeThirteenthMonthController.php`, `HRThirteenthMonthController.php` |
| Shifting / Holiday | `HREmployeeShiftingController.php`, `HREmployeeHolidayController.php`, `HREmployeeWorkDayController.php` |
| Part-Time / Overload / MWSP | `HREmployeeParttimeController.php`, `HREmployeeOverloadController.php`, `HREmployeeMwspController.php` |
| Notifications | `HREmployeeNotificationsController.php`, `HREmployeeNotificationsV2Controller.php` |

**Sensitive data processed:**
- Employee salaries, salary basis types (monthly/daily/hourly)
- SSS, PhilHealth, Pag-IBIG, TIN numbers (statutory IDs)
- RFID card assignments
- Leave balances and approval workflows
- Payroll release records — `hr_payrollv2history`
- Employee banking/account details — `employee_accounts`
- Employment status (active/inactive/separated)

---

## 2. Middleware Analysis

### `AuthenticateHumanResource` (`Kernel.php` alias: `isHumanResource`)

```php
public function handle($request, Closure $next)
{
    $refid = DB::table('usertype')
        ->where('id', Session::get('currentPortal'))
        ->first()->refid;                           // ← NULL DEREFERENCE BUG (see BUG-HR-01)

    if (auth()->user()->type == 10                  // HR user type
        || Session::get('currentPortal') == 10      // ← currentPortal session bypass
        || $refid == 26) {                          // ← refid bypass (see HR-01)
        return $next($request);
    }

    return back();
}
```

**Three separate access paths, two of which are unsafe:**

| Check | Condition | Risk |
|---|---|---|
| `auth()->user()->type == 10` | User's actual DB type is HR | Safe |
| `Session::get('currentPortal') == 10` | Session variable matches HR ID | Unsafe — any user who sets this via portal-switching bypasses the type check |
| `$refid == 26` | A `usertype` row whose `refid` column equals 26 | Unsafe — any user whose `currentPortal` maps to a `usertype` with `refid=26` gains full HR access; this bypasses the explicit type check entirely |

**Additional issue:** The `->first()->refid` call executes before the auth check. If `Session::get('currentPortal')` is `null` or references a deleted/non-existent `usertype`, `->first()` returns `null` and `->refid` throws a fatal `ErrorException`. This crashes the middleware before it can even redirect the user — turning every invalid access into an HTTP 500.

---

## 3. Route Mapping

### Group 1 — `['auth', 'isHumanResource', 'isDefaultPass']` (lines 2013–2516)
The primary HR group. Covers all employee management, attendance, payroll V2/V3, credentials, shifting, part-time, overload, holiday, deductions, and allowances.

**Key routes:**
```
GET  /hr/employees/index                                 → HREmployeesController@index
GET  /hr/employees/addnewemployee/save                   → HREmployeesController@addnewemployeesave
GET  /hr/employees/profile/deactivateuser                → HREmployeeProfileController@deactivateuser
GET  /hr/employees/profile/uploadphoto (POST)            → HREmployeeProfileController@uploadphoto
POST /hr/employees/profile/tabcreds/upload               → HREmployeeCredentialsController@tabcredsupload
POST /attendance/upload                                  → HRAttendanceuploadController@upload_attendance
GET  /hr/attendance/addtimelog                           → HRAttendanceController@addtimelog
GET  /hr/attendance/deletetimelog                        → HRAttendanceController@deletetimelog
GET  /hr/payrollv3/voidpayslip                           → HRPayrollV3Controller@voidpayslip
GET  /hr/payrollv3/editpayslip                           → HRPayrollV3Controller@editpayslip
GET  /hr/payrollv3/batchreleaseemployeepayroll           → HRPayrollV3Controller@batchreleaseemployeepayroll
GET  /hr/payrollv3/batchgenerateemployeepayroll          → HRPayrollV3Controller@batchgenerateemployeepayroll
```

### Group 2 — `['auth', 'isHumanResource', 'isDefaultPass']` (lines 4538–4680) — Duplicate legacy group
Largely mirrors Group 1 with an older set of routes. Contains overlapping paths for attendance, payroll, leaves, overtime, and deductions.

**Key additional routes in this group:**
```
GET  /hr/leaves/{id}                                     → HREmployeesController@leaves
GET  /hr/globalapplyleave                                → HREmployeesController@globalapplyleave
GET  /hr/overtime/{id}                                   → HREmployeesController@overtimes
POST /employeecredential                                 → HREmployeesController@employeecredential
```

### Group 3 — `['auth', 'web']` (no HR role check) — Notification routes
```
GET  /hr/settings/notification/index
GET  /hr/settings/notification/valid_employees
POST /hr/settings/notification/sendnotification
POST /hr/settings/notification/sendnotificationv2
GET  /hr/settings/notification/getMessages
GET  /hr/settings/notification/getAllMessages
POST /hr/settings/notification/sendReply
GET  /hr/settings/notification/getReply
GET  /hr/settings/notification/mark-as-read
GET  /hr/settings/notification/mark-as-displayed
POST /hr/settings/notification/uploadattachedfile
```

### Group 4 — `['auth', 'web']` (no HR role check) — Employee self-service routes
```
GET  /applyleave/{id}                                    → EmployeeLeavesController@leave
GET  /applyovertimedashboard/{id}                        → EmployeeOvertimeController@applyovertimedashboard
POST /applyovertimerequest                               → EmployeeOvertimeController@applyovertimerequest
GET  /applyovertimeupdate/{id}                           → EmployeeOvertimeController@applyovertimeupdate
GET  /employeedailytimerecord/{id}                       → EmployeeDailyTimeRecordController@employeedailytimerecord
GET  /empdtr/updateremarks                               → EmployeeDailyTimeRecordController@updateremarks
GET  /employeepayrolldetails                             → EmployeePayrollHistoryController@employeepayrolldetails
```

---

## 4. Security Findings

---

### HR-01 — CRITICAL — `isHumanResource` Middleware Bypassed via `refid == 26` (Any Auth User)
**File:** `app/Http/Middleware/AuthenticateHumanResource.php`  
**Category:** Broken Access Control (OWASP A01)

The middleware contains a third access path — `$refid == 26` — that is completely disconnected from the HR user type check:

```php
$refid = DB::table('usertype')
    ->where('id', Session::get('currentPortal'))
    ->first()->refid;

if (auth()->user()->type == 10
    || Session::get('currentPortal') == 10
    || $refid == 26) {          // ← grants access if ANY usertype with this refid is found
    return $next($request);
}
```

`Session::get('currentPortal')` is the portal-switching session variable used for multi-role users. An attacker who sets `currentPortal` to any `usertype.id` where `refid = 26` gains full HR portal access regardless of their actual user type.

Since `refid` values are internal, an attacker can enumerate them via the Director's `passData?action=getemployees` endpoint (which returns `otherportals` data including `usertype` IDs), or by trial-and-error across the small integer range of `usertype` IDs.

**Additionally:** The `Session::get('currentPortal') == 10` check means any authenticated user who manipulates their portal session (attainable via the portal-switching UI or any endpoint that sets session values) gets full HR access.

**Fix:**
```php
public function handle($request, Closure $next)
{
    $user = auth()->user();
    if (!$user) {
        return redirect('/login');
    }

    // Only allow explicit HR user type. Remove the refid and currentPortal bypasses.
    if ($user->type == 10) {
        return $next($request);
    }

    // If multi-role portal switching is needed, verify the user ALSO holds type 10:
    // $hasHRPrivilege = DB::table('faspriv')->where('userid', $user->id)
    //     ->where('usertype', 10)->where('deleted', 0)->exists();
    // if (Session::get('currentPortal') == 10 && $hasHRPrivilege) { return $next($request); }

    return redirect('/home');
}
```

---

### HR-02 — HIGH — HR Notification System Accessible to Any Authenticated User
**File:** `routes/web.php` lines 2517–2530  
**Category:** Broken Access Control (OWASP A01)

The HR notification module — which includes sending notices to employees, reading all HR messages, and uploading HR attachments — is placed in a separate `['auth', 'web']` group with no `isHumanResource` check:

```php
Route::group(['middleware' => ['auth', 'web']], function () {
    Route::get('/hr/settings/notification/index', ...);
    Route::post('/hr/settings/notification/sendnotification', ...);
    Route::get('/hr/settings/notification/getAllMessages', ...);    // all HR messages
    // ...
});
```

Any authenticated user — student, teacher, cashier, parent — can:
- Send official HR notifications to any employee
- Read all HR message threads
- Upload files to the HR notification system

**Fix:** Move these routes into the `['auth', 'isHumanResource', 'isDefaultPass']` group.

---

### HR-03 — HIGH — Employee Self-Service Routes Lack Ownership Verification
**File:** `routes/web.php`, `EmployeeLeavesController.php`, `EmployeeDailyTimeRecordController.php`, `EmployeePayrollHistoryController.php`  
**Category:** Insecure Direct Object Reference (OWASP A01)

The employee self-service routes use `['auth', 'web']` only and accept an employee ID directly as a URL parameter with no ownership check:

```php
Route::get('/applyleave/{id}', 'EmployeeLeavesController@leave');
Route::get('/employeedailytimerecord/{id}', 'EmployeeDailyTimeRecordController@employeedailytimerecord');
Route::get('/applyovertimedashboard/{id}', 'EmployeeOvertimeController@applyovertimedashboard');
```

A student or teacher who knows any employee's ID (sequential integer, discoverable from the Director's `passData?action=getemployees` endpoint or by brute-force) can:
- View that employee's full daily time record (all attendance punch-in/out times)
- Access the employee's leave application history and balance
- Access the employee's overtime dashboard (all overtime requests and approval status)
- View payroll payment history via `GET /employeepayrolldetails`

**Fix:** Derive the employee ID from the authenticated session. For genuine employee self-service, verify `teacher.userid == auth()->user()->id` before returning data.

---

### HR-04 — HIGH — Employee Credential Upload: Client-Controlled Extension, No MIME Validation
**File:** `HRControllers/HREmployeeCredentialsController.php` — `tabcredsupload()`  
**Category:** Unrestricted File Upload (OWASP A04)

```php
$file = $request->file('credential');
$extension = $file->getClientOriginalExtension();  // ← from client-supplied filename

$file->move($destinationPath,
    $employeename->email . '-' . strtoupper($employeename->lastname) . '...' . $extension);
```

The stored filename extension comes from the client-submitted filename (`getClientOriginalExtension()`). There is no server-side MIME detection (e.g., via `finfo_file()`), no extension allowlist, and no validation of file content. A `.php` file can be uploaded with a `.pdf` extension, or vice versa — and uploaded files land in `public/employeecredentials/` which is directly web-accessible.

If a file is uploaded with a `.php` extension, it can be accessed at:
```
http://TARGET/employeecredentials/<credential_type>/<email>-<NAME>.php?cmd=whoami
```

**Fix:**
```php
$allowed = ['pdf', 'jpg', 'jpeg', 'png', 'docx', 'doc'];
$ext = strtolower($file->getClientOriginalExtension());
if (!in_array($ext, $allowed)) {
    abort(422, 'File type not allowed.');
}

$finfo = finfo_open(FILEINFO_MIME_TYPE);
$realMime = finfo_file($finfo, $file->getRealPath());
finfo_close($finfo);

$safeMimes = ['application/pdf', 'image/jpeg', 'image/png',
              'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
if (!in_array($realMime, $safeMimes)) {
    abort(422, 'File content does not match allowed types.');
}

// Store outside public/
$file->storeAs('employee_credentials/' . $credentialType, $safeFilename, 'local');
```

---

### HR-05 — HIGH — `employeecredential` Route in Legacy Group Accepts Any File Extension
**File:** `routes/web.php` line 4604, `HREmployeesController.php`  
**Category:** Unrestricted File Upload (OWASP A04)

The legacy credential upload route `POST /employeecredential → HREmployeesController@employeecredential` is a separate upload handler in the duplicate HR group. The same file extension bypass applies. Two distinct upload paths exist for the same purpose, doubling the attack surface.

---

### HR-06 — HIGH — Employee Profile IDOR: Any HR User Reads/Edits Any Employee's Full Profile Including Salary
**File:** `HRControllers/HREmployeeProfileController.php`  
**Category:** Insecure Direct Object Reference (OWASP A01)

All profile data endpoints accept `employeeid` (or `empid`) as a request parameter with no department-level ownership check:

```php
public function index(Request $request)
{
    $teacherid = $request->query('employeeid');  // ← attacker-controlled
    // No check: does auth()->user() have access to this specific employee?

    $profile = Db::table('teacher')
        ->select('teacher.*', 'employee_personalinfo.*', ...)
        ->where('teacher.id', $teacherid)        // ← reads any employee's full profile
        ->first();
```

A payroll clerk from Department A can view and modify the salary, deductions, allowances, and personal information of any employee across all departments by changing the `employeeid` parameter. This is particularly sensitive because the same endpoint also exposes:
- SSS, PhilHealth, Pag-IBIG, and TIN numbers
- Bank account details (`employee_accounts`)
- Emergency contact information
- Employment status and hire date

**Fix:** After loading the employee record, verify that `employee_personalinfo.departmentid` matches the requesting HR user's authorized department(s), or restrict modification to a configured list of employee IDs.

---

### HR-07 — HIGH — Payroll Void and Edit Operations: No Secondary Authorization
**File:** `HRControllers/HRPayrollV3Controller.php` — `voidpayslip()`, `editpayslip()`  
**Category:** Missing Authorization (OWASP A07)

Both payroll destructive operations accept `payrollid` and `employeeid` from the request and execute immediately with no secondary PIN, approval, or ownership check:

```php
public function voidpayslip(Request $request)
{
    $voidremarks = $request->get('voidremarks');
    $payrollid   = $request->get('payrollid');     // attacker-controlled
    $employeeid  = $request->get('employeeid');     // attacker-controlled

    DB::table('hr_payrollv2history')
        ->where('payrollid', $payrollid)
        ->where('employeeid', $employeeid)
        ->where('deleted', 0)
        ->update([
            'remarks'  => $voidremarks,
            'released' => 0,
            'deleted'  => 1,
            'void'     => 1,
            'voidby'   => auth()->user()->id,
            'voiddatetime' => date('Y-m-d H:i:s')
        ]);
    // Also voids all hr_payrollv2historydetail and hr_payrollv2addparticular records
}
```

Any HR-authenticated user can void a released payslip for any employee in any department with no approval workflow. There is no PIN verification, no supervisor check, and no rate limiting. An insider could systematically void all payslips for a payroll period.

**Fix:** Implement the same PIN/authorization token pattern used in Finance V2 and Cashier V2 — require a separate PIN verification step before the void executes, and log all void events with the authorizing user ID.

---

### HR-08 — MEDIUM — Bulk Employee Export Includes All Statutory PII (SSS, TIN, PhilHealth, Pag-IBIG) With No Department Scoping
**File:** `HRControllers/HREmployeesController.php` — `index()` export branch  
**Category:** Sensitive Data Exposure (OWASP A02)

The employee list export (Excel and PDF) includes every active employee's full statutory identity numbers:

```php
$sheet->setCellValue('S' . $startcellno, $employee->sssid);
$sheet->setCellValue('T' . $startcellno, $employee->philhealtid);
$sheet->setCellValue('U' . $startcellno, $employee->pagibigid);
```

These numbers — along with home addresses, birth dates, hire dates, and salary amounts — are returned for **all** active employees with no department filter or pagination. A single export request exposes the complete statutory data of every employee on the system.

**Fix:** Require department-scoped export. Log all export actions with the requesting user ID, timestamp, and parameter set. Consider separating statutory IDs into a restricted export that requires an additional supervisor approval step.

---

### HR-09 — MEDIUM — Attendance Upload Matches Employees by Last Name Only (No ID Verification)
**File:** `HRControllers/HRAttendanceuploadController.php` — `upload_attendance()`  
**Category:** Improper Input Validation (OWASP A04)

```php
$employeeNames = DB::table('teacher')
    ->select('id', DB::raw('UPPER(lastname) as lastname'))
    ->where('deleted', '0')->where('isactive', '1')
    ->orderBy('lastname', 'asc')
    ->get()
    ->keyBy(function ($item) {
        return strtoupper($item->lastname);
    });

// ... parse Excel ...
$employeeId = $employeeNames[strtoupper($employeeData['name'])]->id ?? null;

// Deletes existing attendance for matched employee
DB::table('taphistory')
    ->where('tdate', $attendance['date'])
    ->where('studid', $employeeId)
    ->where('deleted', 0)
    ->delete();

// Inserts uploaded times
DB::table('taphistory')->insert($insertData);
```

The match is case-insensitive and based on last name only, with no first name or employee ID validation. This introduces two risks:

1. **Ambiguous matching:** Employees who share a last name (common in Philippine workplaces — e.g., "Santos", "Reyes") are ambiguous. The `keyBy` function keeps only the last employee per last name, silently overwriting the previous match. The wrong employee's attendance records are modified.

2. **Crafted upload manipulation:** An HR user can submit an Excel file with any last name to overwrite that employee's `taphistory` records with arbitrary times — including deleting existing legitimate entries and substituting fabricated ones — with no validation against actual time constraints or approval workflow.

**Fix:** Include employee ID or employee number in the Excel template as a required column and match on that value. Reject rows where name does not match the found employee ID as a secondary sanity check.

---

### HR-10 — MEDIUM — `profileinfoupdate()` Is a Debug Endpoint in Production
**File:** `HRControllers/HREmployeeProfileController.php`  
**Category:** Security Misconfiguration (OWASP A05)

```php
public function profileinfoupdate(Request $request)
{
    return $request->all();
}
```

This method does nothing except echo all submitted form data back as a JSON response. It is registered on a route and accessible to any HR-authenticated user. It aids an attacker in:
- Understanding form field names and structures
- Testing whether sensitive fields are accessible before crafting a targeted submission
- Confirming which parameters are accepted by other profile-update endpoints

**Fix:** Remove this method and its route entirely.

---

### HR-11 — MEDIUM — All Attendance Modification Routes Use GET Verb (No CSRF Barrier)
**File:** `routes/web.php`, `HRAttendanceController.php`  
**Category:** Cross-Site Request Forgery risk (OWASP A01)

All attendance modification endpoints (`addtimelog`, `deletetimelog`, `deletetimelogtapping`, `updateremarks`, `updatetapstate`) are registered as `Route::get()`. GET requests in Laravel are exempted from CSRF token verification. An attacker who tricks an HR user into clicking a malicious link can add, delete, or modify any employee's attendance records.

Example:
```
<img src="http://TARGET/hr/attendance/deletetimelog?id=1234">
```
Fetched silently by the browser — employee attendance entry deleted.

**Fix:** Use `Route::post()` for all state-changing operations and include CSRF tokens in the request.

---

### HR-12 — LOW — `deactivateuser` and `activateuser` Use GET Verb (CSRF Risk)
**File:** `routes/web.php` lines 2029–2030  
**Category:** Cross-Site Request Forgery risk (OWASP A01)

```php
Route::get('/hr/employees/profile/deactivateuser', '...@deactivateuser');
Route::get('/hr/employees/profile/activateuser',   '...@activateuser');
```

Employee activation/deactivation is a GET request — the system portal login for the affected employee can be disabled by a CSRF attack targeting an HR user.

---

## 5. Backend Bug Findings

---

### BUG-HR-01 — Null Dereference Crash in `AuthenticateHumanResource` (Every Invalid HR Request)
**File:** `app/Http/Middleware/AuthenticateHumanResource.php`  
**Severity:** High Bug

```php
$refid = DB::table('usertype')
    ->where('id', Session::get('currentPortal'))
    ->first()->refid;   // ← CRASH if currentPortal is null or no matching row
```

If `Session::get('currentPortal')` returns `null` (e.g., a freshly logged-in user who hasn't switched portals) or references a deleted `usertype` ID, `->first()` returns `null`. The `->refid` dereference then throws:
```
ErrorException: Trying to get property 'refid' of non-object
```

This means: on every first visit to an HR route by a user who has not selected the HR portal, the middleware throws a 500 error. The user sees an error page instead of a redirect. In a non-production configuration, the full stack trace (including file paths and DB query details) is exposed.

**Fix:**
```php
$usertypeRow = DB::table('usertype')->where('id', Session::get('currentPortal'))->first();
$refid = $usertypeRow ? $usertypeRow->refid : null;
```

---

### BUG-HR-02 — N+1 Query in Employee List Export (600+ DB Calls for 200 Employees)
**File:** `HRControllers/HREmployeesController.php` — `index()` export branch  
**Severity:** Medium Bug

Inside the employee export loop, three separate DB queries are fired per employee for SSS, PhilHealth, and Pag-IBIG accounts:

```php
foreach ($employees as $key => $employee) {
    // Query 1 per employee:
    if (DB::table('employee_accounts')->where('employeeid', $employee->id)
            ->where('accountdescription', 'like', '%sss%')->...->first()) { ... }
    // Query 2 per employee:
    if (DB::table('employee_accounts')->where('employeeid', $employee->id)
            ->where('accountdescription', 'like', '%phic%')->...->first()) { ... }
    // Query 3 per employee:
    if (DB::table('employee_accounts')->where('employeeid', $employee->id)
            ->where('accountdescription', 'like', '%ibig%')->...->first()) { ... }
}
```

For 200 employees, this generates 600+ individual DB queries. There is additionally a sub-query per employee for `$employee->educationalinfo` (mapped via `->map()`), adding another 200 queries. A school with 300 employees triggers ~1,200 DB calls for a single Excel export. Export requests will time out or exhaust the DB connection pool under realistic school sizes.

**Fix:** Eager-load all `employee_accounts` in a single query, keyed by `employeeid`, before the loop. Same for `employee_educationinfo`.

---

### BUG-HR-03 — Undefined Variable `$salarybasistype` in `tabsalaryinfo()` Insert Branch
**File:** `HRControllers/HREmployeeProfileController.php` — `tabsalaryinfo()`  
**Severity:** Medium Bug

```php
$typeid = $request->get('typeid');  // ← correct variable name is $typeid

// ...
$rowid = DB::table('employee_basicsalaryinfo')->insertGetId([
    'employeeid'     => $employeeid,
    'salarybasistype' => $salarybasistype,  // ← $salarybasistype is NEVER DECLARED
    // ...
]);
```

The insert branch uses `$salarybasistype` which is not declared anywhere in the method. The declared variable is `$typeid`. PHP 7 will silently use `null` (with a Notice), and PHP 8 will throw a Warning. Either way, the `salarybasistype` column in the newly created record is always `null` for first-time salary setups, causing broken payroll calculations until manually corrected.

---

### BUG-HR-04 — Error Suppressor `@json_encode()` Silently Drops Data
**File:** `HRControllers/HREmployeesController.php`, `HRAttendanceController.php`  
**Severity:** Low Bug

```php
return @json_encode((object) [
    'data'            => $employees,
    'recordsTotal'    => $employeescount,
    'recordsFiltered' => $employeescount
]);
```

The `@` operator suppresses all `json_encode()` errors. If any employee record contains a malformed UTF-8 string (common in older data migrated from legacy systems), `json_encode()` returns `false`. The DataTables client receives an empty response and silently shows no data. There is no error logged and no notification to the HR user that data is missing.

**Fix:** Use `json_encode($data, JSON_THROW_ON_ERROR)` (or catch and log the result) and return a proper error response.

---

### BUG-HR-05 — `changestatus()` Catches All Exceptions, Returns Ambiguous `0`
**File:** `HRControllers/HREmployeeProfileController.php` — `changestatus()`  
**Severity:** Low Bug

```php
try {
    DB::table('teacher')
        ->where('id', $request->get('id'))
        ->update(['isactive' => $request->get('status'), ...]);
    return back();
} catch (\Exception $error) {
    return 0;
}
```

Any DB error (connection failure, constraint violation) is silently swallowed and returns `0`. The calling UI interprets `0` as "success but employee is now inactive" — the same value used for a deliberate deactivation. If an HR user attempts to activate an employee and the DB call fails, the UI may display the employee as successfully activated while the DB record is unchanged.

---

### BUG-HR-06 — Attendance Upload Silently Drops Duplicate Last Names (Name Collision)
**File:** `HRControllers/HRAttendanceuploadController.php`  
**Severity:** Medium Bug

```php
$employeeNames = DB::table('teacher')...
    ->keyBy(function ($item) {
        return strtoupper($item->lastname);  // ← duplicate last names overwrite each other
    });
```

`keyBy()` on last name means if two active employees share the same last name (e.g., two "Santos" or two "Reyes"), only the last one in the result set is kept in the map. The first employee's attendance records are never updated — no error is thrown and no warning is returned. The HR user has no indication that one employee's attendance was silently skipped.

---

### BUG-HR-07 — Auto-Insert on Profile View Creates Phantom Salary Rows
**File:** `HRControllers/HREmployeeProfileController.php` — `index()`  
**Severity:** Low Bug

```php
if (count(DB::table('employee_basicsalaryinfo')->where('employeeid', $teacherid)->get()) == 0) {
    DB::table('employee_basicsalaryinfo')->insert([
        'employeeid'      => $teacherid,
        'createdby'       => auth()->user()->id,
        'createddatetime' => date('Y-m-d H:i:s')
    ]);
}
```

Merely opening any employee's profile page inserts a blank `employee_basicsalaryinfo` row if one doesn't exist. All inserted fields (salary amount, basis type, hours per day) are `null`. During payroll generation, employees with a null `salarybasistype` cause the salary calculation to fail or produce `0` payslips. Any HR user who accidentally opens a new employee's profile before the salary is configured leaves the employee in a broken payroll state.

---

## 6. Fix Recommendations

### Immediate (Before Next Payroll Run)
1. **HR-01 / BUG-HR-01:** Rewrite `AuthenticateHumanResource` to remove the `refid == 26` bypass and add null protection on the `->first()` call.
2. **HR-07:** Add a secondary PIN/authorization gate before `voidpayslip()` and `editpayslip()` execute — same pattern as Finance V2.
3. **HR-04 / HR-05:** Add server-side MIME validation and file extension allowlisting to both credential upload paths.

### Short-Term (Within Sprint)
4. **HR-02:** Move HR notification routes into `['auth', 'isHumanResource', 'isDefaultPass']`.
5. **HR-03:** Add ownership verification (verify `teacher.userid == auth()->user()->id`) in all employee self-service routes.
6. **HR-09:** Rewrite attendance upload to match by employee ID, not last name.
7. **HR-10:** Remove `profileinfoupdate()` from the codebase.
8. **BUG-HR-03:** Fix `$salarybasistype` → `$typeid` in `tabsalaryinfo()`.
9. **BUG-HR-07:** Move the `employee_basicsalaryinfo` auto-insert out of the profile view into the `addnewemployeesave` flow.

### Hardening (Backlog)
10. **HR-06:** Add department-scoped access checks on all employee profile endpoints.
11. **HR-08:** Require department filter and add export audit logging.
12. **HR-11 / HR-12:** Convert all state-changing attendance and employee activation routes from GET to POST.
13. **BUG-HR-02:** Eager-load `employee_accounts` and `employee_educationinfo` before the export loop.
14. **BUG-HR-04:** Replace `@json_encode()` with `json_encode($data, JSON_THROW_ON_ERROR)`.
