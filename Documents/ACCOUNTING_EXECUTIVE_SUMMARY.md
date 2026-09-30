# Accounting Portal — Executive Security Summary
**Date:** June 11, 2026  
**Module:** Accounting Portal — Gen 1 (`FinanceControllers/`) + Gen 2 (`AccountingV2Controller/`)  
**Review Type:** Static Analysis  
**Reviewer:** Security Code Review Team

---

## Overall Risk: CRITICAL

The Accounting Portal controls the school's financial ledger, Chart of Accounts, journal entries, financial statements, and purchasing records. The `isAccounting` middleware contains two `refid`-based bypass paths that allow any authenticated user to gain full access. The AccountingV2 module provides no role gate on write routes — any student or teacher can create and delete accounting entries and download complete financial statements.

---

## Risk Summary

| ID | Severity | Title |
|---|---|---|
| ACC-01 | **CRITICAL** | `isAccounting` middleware bypassed via `refid == 19 \|\| refid == 33` and session manipulation |
| ACC-02 | **HIGH** | All COA and journal entry operations use GET verb — no CSRF protection |
| ACC-03 | **HIGH** | AccountingV2: COA, JV, fixed assets, suppliers writable by any authenticated user |
| ACC-04 | **HIGH** | All financial statement exports accessible to any authenticated user |
| ACC-05 | **MEDIUM** | `isDefaultPass` not enforced in accounting route groups |
| ACC-06 | **MEDIUM** | `isBookkeeperAdmin` middleware session bypass (`currentPortal == 67`) |
| BUG-ACC-01 | **High Bug** | Middleware returns null on failure — no redirect, silent crash |
| BUG-ACC-02 | **Medium Bug** | Null dereference in middleware if user has no matching `usertype` |
| BUG-ACC-03 | **Low Bug** | Null dereference in `purchase_read()` on deleted supplier |
| BUG-ACC-04 | **Medium Bug** | PO list joins wrong table (`expense_company` vs `purchasing_supplier`) |

**Total:** 1 Critical, 3 High, 2 Medium security findings; 4 backend bugs

---

## Attack Chain Analysis

### Chain 1: Any Authenticated User Gains Full Accounting Access
```
Authenticated user (any role)
  → Enumerate usertype.id values with refid=19 or refid=33
      (from Director endpoint passData?action=getemployees — documented in DIRECTOR_CODE_REVIEW.md)
  → Set session currentPortal = <matching usertype.id>
      (via any portal-switching endpoint)
  → isAccounting middleware: $user->refid == 19 → TRUE
  → Full accounting access granted:
      → Create/delete Chart of Accounts entries
      → Post journal entries to the general ledger
      → Create fraudulent purchase orders and mark them as POSTED
      → Download complete financial statements
```
**Prerequisite:** Any valid login. **Complexity:** Low.

---

### Chain 2: Student Downloads Complete Financial Statements (AccountingV2)
```
Enrolled student (auth user, type = student)
  → GET /accountingv2/general-ledger-api/export-excel
      → Full general ledger downloaded (no role check)
  → GET /accountingv2/income-statement-api/export
  → GET /accountingv2/balance-sheet-api/export
  → GET /accountingv2/trial-balance-api/export
      → Full balance sheet, income statement, and trial balance downloaded
```
**Prerequisite:** Any valid login. **Complexity:** None (direct URL access).

---

### Chain 3: Insider Accounting Manipulation via CSRF (Gen 1)
```
Attacker tricks an authenticated accounting user into visiting a malicious page
  → Page embeds:
      <img src="http://TARGET/finance/accounting/postje?refid=12345">
      <img src="http://TARGET/finance/coa/deleteacctype?dataid=1">
      <img src="http://TARGET/finance/purchasing/purchase_delete?dataid=99">
  → Browser loads each "image" as a GET request with the accounting user's cookies
  → Journal entry 12345 is permanently posted (jestatus = 'Posted')
  → Account type 1 is deleted from the Chart of Accounts
  → Purchase order 99 is deleted
```
**Prerequisite:** An accounting user is active in the browser. **Complexity:** Low (basic CSRF attack).

---

### Chain 4: Student Creates Fraudulent Accounting Records (AccountingV2)
```
Student user
  → POST /accountingv2/journal-voucher-api/
      entries: debit 1,000,000 to Revenue, credit 1,000,000 to Expense
      → Journal entry created in bk_generalledg with student's user ID
  → GET /accountingv2/general-ledger-api/sync
      → Forces reconciliation using the new fraudulent entry
  → Financial statements now include inflated or manipulated figures
```
**Prerequisite:** Any valid login. **Complexity:** Low (requires basic HTTP knowledge).

---

## Business Impact Assessment

| Area | Impact |
|---|---|
| **Financial Statement Integrity** | Any authenticated user can create, modify, or delete journal vouchers, COA entries, and financial records in AccountingV2. An insider or compromised student account can manipulate the income statement, balance sheet, and general ledger. |
| **Confidential Financial Data** | Complete financial statements (income statement, balance sheet, trial balance, general ledger) are accessible to any logged-in user — including students, parents, and teachers — via AccountingV2 export endpoints. |
| **Audit Trail Corruption** | Posted journal entries can be deleted by any auth user. The `deleteddatetime` and `deletedby` are correctly logged, but the records are gone from reports. |
| **CSRF Risk on Gen 1** | All Gen 1 chart-of-accounts and journal entry operations are GET routes. Any link that tricks an accounting user to click can delete COA entries or post journal entries — with no confirmation step and no CSRF barrier. |
| **Purchasing Record Integrity** | Vendor creation/deletion, purchase order creation and posting — all on GET routes with no CSRF protection in Gen 1. |

---

## Comparison to Other Modules

| Module | Critical | High | Medium | Total |
|---|---|---|---|---|
| Admin | 3 | 4 | 1 | 8 |
| Director | 3 | 2 | 1 | 6 |
| Principal | 2 | 2 | 2 | 6 |
| HR Portal | 1 | 6 | 4 | 11 |
| **Accounting** | **1** | **3** | **2** | **6** |

Accounting has a relatively compact set of findings. The critical finding (middleware bypass) is the highest-priority because it grants full accounting access to any authenticated user — enabling both data theft and ledger manipulation.

---

## Remediation Priority

### P0 — Before Next Financial Period Close
| # | Finding | Action |
|---|---|---|
| 1 | ACC-01 / BUG-ACC-01 / BUG-ACC-02 | Rewrite `AuthenticateAccounting` — remove refid bypasses, add null check, add explicit redirect |
| 2 | ACC-03 | Add `isAccounting` or `isBookkeeperAdmin` middleware to all AccountingV2 write routes |
| 3 | ACC-04 | Restrict all financial report export routes to accounting/bookkeeper roles |

### P1 — Within Sprint
| # | Finding | Action |
|---|---|---|
| 4 | ACC-02 | Convert all Gen 1 state-changing routes from GET to POST |
| 5 | ACC-05 | Add `isDefaultPass` to both `['auth', 'isAccounting']` groups |
| 6 | ACC-06 | Remove `currentPortal == 67` from `AuthenticateBookkeeperAdmin` |

### P2 — Hardening
| # | Finding | Action |
|---|---|---|
| 7 | BUG-ACC-03 | Add null check on supplier lookup in `purchase_read()` |
| 8 | BUG-ACC-04 | Correct table reference (`expense_company` → `purchasing_supplier`) in `purchase_load()` |
