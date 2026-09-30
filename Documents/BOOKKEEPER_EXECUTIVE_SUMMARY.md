# Bookkeeper Portal — Executive Security Summary
**Date:** June 11, 2026  
**Module:** Bookkeeper Portal — `BookkeeperController.php`, `BookkeeperControllers/`, `routes/bookkeeper.php`  
**Review Type:** Static Analysis  
**Reviewer:** Security Code Review Team

---

## Overall Risk: CRITICAL

The Bookkeeper Portal's route file (`bookkeeper.php`) is loaded with zero authentication middleware — it is the only module in the system where the `RouteServiceProvider` applies only the `web` middleware group with no `auth` guard. Every route is accessible without logging in. This exposes 150+ endpoints including all financial statement exports, transaction voids, purchase order management, and COA modification to anyone on the internet.

---

## Risk Summary

| ID | Severity | Title |
|---|---|---|
| BK-01 | **CRITICAL** | Entire `bookkeeper.php` route file is unauthenticated — no `auth` middleware |
| BK-02 | **CRITICAL** | Transaction void routes accessible without login |
| BK-03 | **HIGH** | All financial export routes unauthenticated |
| BK-04 | **HIGH** | Purchase order and disbursement mutation routes unauthenticated |
| BK-05 | **MEDIUM** | `isBookkeeperAdmin` session bypass (`currentPortal == 67`) |
| BK-06 | **MEDIUM** | `POST /add-expense-item` under `['auth']` only, no bookkeeper role check |
| BUG-BK-01 | **Architectural** | `BookkeeperController.php` is a 28,000-line monolith |
| BUG-BK-02 | **Low Bug** | Export methods crash on null `auth()->user()` rather than redirecting |
| BUG-BK-03 | **Low Bug** | COA ID assignment is a sequential PHP scan — race condition under concurrent requests |

**Total:** 2 Critical, 2 High, 2 Medium security findings; 3 backend bugs

---

## Root Cause

The root cause of BK-01 and BK-02 is a single line in `RouteServiceProvider.php`:

```php
protected function mapBookkeeperRoutes()
{
    Route::prefix('bookkeeper')
        ->middleware('web')    // ← should be ['web', 'auth', 'isBookkeeperAdmin']
        ->group(base_path('routes/bookkeeper.php'));
}
```

Compare to Finance V2 (which was correctly secured):
```php
protected function mapFinanceRoutes()
{
    Route::prefix('financev2')
        ->middleware('web')    // financev2.php routes themselves apply auth internally
        ->group(base_path('routes/financev2.php'));
}
```

The `bookkeeper.php` file, unlike `financev2.php`, does not define any inner `Route::middleware(['auth', ...])` groups. Every route is bare with no protection layer at all.

---

## Attack Chain Analysis

### Chain 1: Unauthenticated Download of All Financial Statements
```
Internet attacker (no account, no credentials)
  → GET http://TARGET/bookkeeper/export-excel-ledger
      → Full general ledger downloaded as Excel file
  → GET http://TARGET/bookkeeper/excel-export-income-statement
      → Full income statement downloaded
  → GET http://TARGET/bookkeeper/balance-sheet/excel
      → Full balance sheet downloaded
  → GET http://TARGET/bookkeeper/export-cashflow
  → GET http://TARGET/bookkeeper/export-excel-trialbalance
  → GET http://TARGET/bookkeeper/excel_export_disbursements
```
**Prerequisite:** None. Not even a browser — a single `curl` command.  
**Complexity:** None.  
**Impact:** Complete financial records of the school exposed to anyone who discovers the URL.

---

### Chain 2: Unauthenticated Transaction Manipulation
```
Internet attacker
  → GET http://TARGET/bookkeeper/purchase_order/delete?id=1
      (crashes if auth()->user()->id is called before delete — but may still execute
       depending on code path)
  → POST http://TARGET/bookkeeper/disbursement/create
      (controller: auth()->user()->id — crashes for unauthenticated user)

Any authenticated user (e.g., student)
  → GET http://TARGET/bookkeeper/purchase_order/delete?id=1
      → Purchase order deleted with student's user ID as deletedby
  → GET http://TARGET/bookkeeper/expenses_monitoring/delete?id=5
      → Expense monitoring record deleted
```
**Prerequisite:** Any valid login (for mutation). No login needed (for reads and exports).

---

### Chain 3: Bookkeeper Admin Privilege Escalation via Session
```
Authenticated user (any role)
  → Set session: currentPortal = 67
      (via portal-switching endpoint or session cookie manipulation)
  → POST /accountingv2/disbursement-api/{id}/approve
      → Bookkeeper Admin check passes: Session::get('currentPortal') == 67 → TRUE
  → Approve any disbursement without being a bookkeeper admin
  → POST /accountingv2/fy/close
      → Close the active fiscal year
  → POST /accountingv2/fy/activate
      → Activate any fiscal year
```
**Prerequisite:** Any valid login. **Complexity:** Low.

---

## Business Impact Assessment

| Area | Impact |
|---|---|
| **Financial Confidentiality** | Complete financial records (income statement, balance sheet, general ledger, trial balance, cashflow, equity statement, disbursements, expenses) are downloadable by anyone without authentication. This represents a complete breach of financial confidentiality. |
| **Transaction Integrity** | Any authenticated user can delete purchase orders, disbursements, and expense monitoring records. This undermines the audit trail. |
| **Fiscal Year Integrity** | `isBookkeeperAdmin` is bypassable via session manipulation — any auth user can close or reactivate fiscal years, corrupting the financial period structure. |
| **Regulatory Compliance** | Philippine accounting regulations (Government Accounting Manual, BIR audit requirements) require that financial records be protected. Unauthenticated export is a direct violation of data access controls expected under RA 10173 and standard internal controls. |

---

## Comparison to Other Modules

| Module | Critical | High | Total |
|---|---|---|---|
| Director | 3 | 2 | 6 |
| Admin | 3 | 4 | 8 |
| HR Portal | 1 | 6 | 11 |
| Accounting | 1 | 3 | 6 |
| **Bookkeeper** | **2** | **2** | **6** |

Bookkeeper has 2 Critical findings. However, BK-01 is unique among all modules reviewed: it is the only module where the entire route file is completely unauthenticated at the `RouteServiceProvider` level. Every other module at minimum applies the `auth` middleware, even when additional role checks are missing.

---

## Remediation Priority

### P0 — Emergency (Before Next Business Day)
| # | Finding | Action |
|---|---|---|
| 1 | BK-01 | Add `'auth'` (minimum) and `'isBookkeeperAdmin'` to `mapBookkeeperRoutes()` in `RouteServiceProvider.php` — one line change with immediate full protection |
| 2 | BK-02 | Add auth guard to void routes (handled by BK-01 fix above) |

### P1 — Within Sprint
| # | Finding | Action |
|---|---|---|
| 3 | BK-05 | Remove `Session::get('currentPortal') == 67` from `AuthenticateBookkeeperAdmin` |
| 4 | BK-06 | Move `/add-expense-item` under `['auth', 'isBookkeeperAdmin']` and add input validation |

### P2 — Hardening
| # | Finding | Action |
|---|---|---|
| 5 | BUG-BK-01 | Begin decomposing `BookkeeperController.php` into smaller controller classes |
| 6 | BUG-BK-03 | Replace manual ID scan with database `AUTO_INCREMENT` |
