# Bookkeeper Portal — Full Code Review
**Date:** June 11, 2026  
**Target:** `app/Http/Controllers/BookkeeperController.php` (28,000+ lines), `BookkeeperControllers/` (10 files), `routes/bookkeeper.php`, `RouteServiceProvider::mapBookkeeperRoutes()`  
**Methodology:** Static analysis — route configuration, middleware, controller methods, authentication, data exports  
**Scope:** Authentication, authorization, financial data exposure, transaction integrity

---

## Table of Contents
1. [Module Overview](#1-module-overview)
2. [Route Configuration Analysis](#2-route-configuration-analysis)
3. [Middleware Analysis](#3-middleware-analysis)
4. [Security Findings](#4-security-findings)
5. [Backend Bug Findings](#5-backend-bug-findings)
6. [Fix Recommendations](#6-fix-recommendations)

---

## 1. Module Overview

The Bookkeeper Portal manages the school's full accounting operations: chart of accounts, journal vouchers, general ledger, subsidiary ledger, trial balance, income statement, balance sheet, cashflow and equity statements, disbursements, purchase orders, receiving, fixed assets, expense monitoring, and bank management.

It exists in two overlapping generations:
- **Legacy bookkeeper** — `routes/bookkeeper.php` → `BookkeeperController.php` (monolithic, 28,000+ lines)
- **BookkeeperControllers** — `BookkeeperControllers/` (10 controllers) — partially used; `ExpensesItemController.php` has one route exposed in `web.php`

---

## 2. Route Configuration Analysis

### `RouteServiceProvider::mapBookkeeperRoutes()`

```php
protected function mapBookkeeperRoutes()
{
    Route::prefix('bookkeeper')
        ->middleware('web')              // ← ONLY 'web' — no 'auth', no 'isBookkeeperAdmin'
        ->namespace($this->namespace)
        ->group(base_path('routes/bookkeeper.php'));
}
```

The `mapBookkeeperRoutes()` method applies only the `web` middleware group, which provides CSRF protection and session binding but **no authentication check**. Every route in `bookkeeper.php` is accessible to unauthenticated internet users.

**This is the single most critical finding in the Bookkeeper module.** There are 150+ routes registered in `bookkeeper.php` — all of them unauthenticated.

### Routes Without Authentication (Complete Category Summary)

| Category | Example Routes | HTTP Method |
|---|---|---|
| Chart of Accounts views | `/bookkeeper/chart_of_accounts`, `/bookkeeper/general_ledger`, `/bookkeeper/income_statement` | Route::view (unauthenticated) |
| COA CRUD | `POST /storecoa`, `GET /fetchcoa`, `POST /destroycoa` | POST/GET |
| Sub-COA operations | `GET /sub_storecoa`, `GET /sub_sub_storecoa/create`, `POST /subcoa/update`, `POST /destroy_subcoa` | POST/GET |
| Supplier operations | `GET /supplier/create`, `GET /supplier/fetch`, `GET /supplier/edit`, `GET /supplier/delete` | GET |
| Purchase Order operations | `GET /purchase_order/create`, `GET /purchase_order/fetch`, `GET /purchase_order/delete`, `GET /purchase_order/update_approved` | GET |
| Receiving operations | `GET /receiving/fetch`, `GET /receiving/update_received`, `GET /receiving/update_cancelled_received` | GET |
| Expenses Monitoring | `GET /expenses_monitoring/create`, `GET /expenses_monitoring/fetch`, `GET /expenses_monitoring/delete` | GET |
| Disbursement operations | `POST /disbursement/create`, `GET /disbursement/fetch`, `GET /disbursement/delete` | POST/GET |
| Fixed Assets | `GET /fixed_asset/create`, `GET /fixed_asset/fetch`, `GET /fixed_asset/delete` | GET |
| Journal Voucher | `GET /display-journal-voucher`, `POST /update-journal-voucher/update`, `GET /posted-journal-voucher`, `DELETE /delete-journal-voucher` | Mixed |
| **Financial Exports** | `GET /export-excel-ledger`, `GET /excel-export-income-statement`, `GET /balance-sheet/excel`, `GET /export-cashflow`, `GET /export-excel-equity-statement`, `GET /export-excel-trialbalance`, `GET /excel_export_disbursements`, `GET /excel_export_stock_history`, `GET /export_excel_expenses_monitoring` | GET |
| **Transaction Void** | `GET /v2/v2_voidtransactions`, `GET /v2/v2_voidtransactions/disbursement` | GET |
| Bank management | `GET /bank/create`, `GET /bank/fetch`, `POST /bank/fetch/update_bank`, `DELETE /delete-bank` | Mixed |
| Other Setup | `GET /other_setup_cashierJE/setactive`, `POST /other_setup_discountJE/update_discountje`, `GET /other_setup_debadjJE/delete_debadj` | Mixed |

---

## 3. Middleware Analysis

### No Bookkeeper-Specific Auth in `bookkeeper.php`

The `RouteServiceProvider` confirms that `bookkeeper.php` runs under `middleware('web')` only. The `AuthenticateBookkeeperAdmin` middleware is registered in `Kernel.php` but never applied to `bookkeeper.php` routes. It is only used in `accountingv2.php` sub-groups.

### `AuthenticateBookkeeperAdmin.php` (used only in `accountingv2.php`)

```php
public function handle($request, Closure $next)
{
    if (auth()->user()->type == 67 ||
        Session::get('currentPortal') == 67) {   // ← session bypass
        return $next($request);
    }
    return $request->expectsJson()
        ? response()->json(['error' => 'Unauthorized.'], 403)
        : back();
}
```

`Session::get('currentPortal') == 67` allows any authenticated user who manipulates their portal session to gain Bookkeeper Admin access (disbursement approvals, fiscal year management).

---

## 4. Security Findings

---

### BK-01 — CRITICAL — Entire `bookkeeper.php` Route File Is Completely Unauthenticated
**File:** `app/Providers/RouteServiceProvider.php` — `mapBookkeeperRoutes()`, `routes/bookkeeper.php`  
**Category:** Broken Access Control (OWASP A01)

The `RouteServiceProvider` loads `bookkeeper.php` with only `middleware('web')`:

```php
protected function mapBookkeeperRoutes()
{
    Route::prefix('bookkeeper')
        ->middleware('web')    // ← no 'auth', no 'isBookkeeperAdmin'
        ->group(base_path('routes/bookkeeper.php'));
}
```

Every route in `bookkeeper.php` is accessible without any login. An unauthenticated internet user can:
- Load the chart of accounts page at `http://TARGET/bookkeeper/chart_of_accounts`
- Fetch all COA data via `GET /bookkeeper/fetchcoa`
- Fetch all suppliers via `GET /bookkeeper/supplier/fetch`
- Fetch all purchase orders via `GET /bookkeeper/purchase_order/fetch`
- Fetch all disbursements via `GET /bookkeeper/disbursement/fetch`
- Export full financial statements (see BK-03)

For routes that call `auth()->user()->id` internally (e.g., `POST /storecoa` which records `createdby`), an unauthenticated access will crash with a `Call to member function id() on null` fatal error — but this means the access check is relying on an application crash for protection, not on an actual auth gate. Any user who IS authenticated (even as a student) can use these routes fully.

**Fix:**
```php
protected function mapBookkeeperRoutes()
{
    Route::prefix('bookkeeper')
        ->middleware(['web', 'auth', 'isBookkeeperAdmin'])
        ->group(base_path('routes/bookkeeper.php'));
}
```

---

### BK-02 — CRITICAL — Unauthenticated Transaction Void Routes
**File:** `routes/bookkeeper.php` lines ~240–242  
**Category:** Broken Access Control / Financial Data Integrity (OWASP A01)

```php
Route::get('/v2/v2_voidtransactions',             [BookkeeperController::class, 'v2_voidtransactions']);
Route::get('/v2/v2_voidtransactions/disbursement', [BookkeeperController::class, 'v2_voidtransactions_disbursement']);
```

Both void endpoints are registered with no authentication. The controllers themselves implement a secondary password verification step (`Hash::check($pword, $checkuser->password)`), which mitigates the immediate financial impact — but:
1. **Any authenticated user** (student, teacher, parent) can call these endpoints. The secondary auth only requires knowing any user's email and password — not specifically a bookkeeper's.
2. The password check authenticates the vouching user, but there is no check that the vouching user is a bookkeeper or supervisor.
3. Unauthenticated callers trigger `auth()->user()->id` inside the method — resulting in a crash, but still an exploitable DoS vector.

**Fix:** Move void routes under `['auth', 'isBookkeeperAdmin']` middleware in addition to requiring the secondary password confirmation.

---

### BK-03 — HIGH — All Financial Statement Export Routes Are Unauthenticated
**File:** `routes/bookkeeper.php`  
**Category:** Sensitive Data Exposure (OWASP A02)

All Excel/PDF export routes in `bookkeeper.php` are unauthenticated. Anyone who knows the URL can download complete financial records:

```bash
# No session cookie needed — completely unauthenticated:
curl "http://TARGET/bookkeeper/export-excel-ledger"           -o general_ledger.xlsx
curl "http://TARGET/bookkeeper/excel-export-income-statement" -o income_statement.xlsx
curl "http://TARGET/bookkeeper/balance-sheet/excel"           -o balance_sheet.xlsx
curl "http://TARGET/bookkeeper/export-cashflow"               -o cashflow.xlsx
curl "http://TARGET/bookkeeper/export-excel-equity-statement" -o equity.xlsx
curl "http://TARGET/bookkeeper/export-excel-trialbalance"     -o trial_balance.xlsx
curl "http://TARGET/bookkeeper/excel_export_disbursements"    -o disbursements.xlsx
curl "http://TARGET/bookkeeper/excel_export_stock_history"    -o stock_history.xlsx
curl "http://TARGET/bookkeeper/export_excel_expenses_monitoring" -o expenses.xlsx
```

**Note:** Some of these controllers call `auth()->user()` internally and may crash for truly unauthenticated users. However, any authenticated user of any role can use these endpoints.

These exports contain the school's complete financial history — tuition revenue, salaries, vendor payments, fixed asset values, and expenses — all accessible without any access control.

---

### BK-04 — HIGH — Unauthenticated Purchase Order and Disbursement Mutations
**File:** `routes/bookkeeper.php`  
**Category:** Financial Data Integrity (OWASP A01)

All PO and disbursement write operations are unauthenticated:

```bash
# Create a purchase order without logging in:
GET /bookkeeper/purchase_order/create?supplier=1&amount=50000

# Approve a PO without logging in:
GET /bookkeeper/purchase_order/update_approved?id=123&status=approved

# Delete a disbursement without logging in:
GET /bookkeeper/disbursement/delete?id=456

# Create a disbursement without logging in:
POST /bookkeeper/disbursement/create
```

An attacker can create fraudulent purchase orders, approve them, and trigger the receiving workflow — all without ever logging in. Controller methods that call `auth()->user()->id` will crash when used unauthenticated, but any logged-in user of any role can use them successfully.

---

### BK-05 — MEDIUM — `isBookkeeperAdmin` Middleware Session Bypass (`currentPortal == 67`)
**File:** `app/Http/Middleware/AuthenticateBookkeeperAdmin.php`  
**Category:** Broken Access Control (OWASP A01)

```php
if (auth()->user()->type == 67 || Session::get('currentPortal') == 67) {
    return $next($request);
}
```

The `currentPortal == 67` check allows any authenticated user to gain Bookkeeper Admin privileges by manipulating their session variable. This affects the `accountingv2.php` approve routes (disbursement approval, PO approval, fiscal year close/activate, and receiving).

**Fix:** Remove `Session::get('currentPortal') == 67` from the condition. Only check `auth()->user()->type == 67`.

---

### BK-06 — MEDIUM — `POST /add-expense-item` Under `['auth']` Only — Any Authenticated User Can Add Expense Items
**File:** `routes/web.php` line 4521, `BookkeeperControllers/ExpensesItemController.php`  
**Category:** Broken Access Control (OWASP A01)

```php
Route::post('/add-expense-item', [
    App\Http\Controllers\BookkeeperControllers\ExpensesItemController::class,
    'addExpenseItem'
]);
```

This route is placed inside a `Route::middleware(['auth'])` group — no `isBookkeeperAdmin` or `isAccounting` check. Any authenticated user can add new expense item master records to the `bk_expenses_items` table.

The controller also lacks type/length input validation — `itemCode`, `itemName`, `quantity`, `amount`, `itemType`, and `debitAccount` are inserted directly:

```php
DB::table('bk_expenses_items')->insert([
    'itemcode'    => $request->itemCode,      // no type or length check
    'description' => $request->itemName,      // no length limit
    'qty'         => $request->quantity,      // not validated as numeric
    'amount'      => $request->amount,        // not validated as numeric
    'itemtype'    => $request->itemType,
    'coaid'       => $request->debitAccount,  // not validated as existing COA id
]);
```

**Fix:** Move this route under `['auth', 'isBookkeeperAdmin']` or `['auth', 'isAccounting']`. Add input validation for all fields.

---

## 5. Backend Bug Findings

---

### BUG-BK-01 — `BookkeeperController.php` is 28,000+ Lines — Unmaintainable Monolith
**File:** `app/Http/Controllers/BookkeeperController.php`  
**Severity:** Architectural Concern (not a security bug directly, but creates serious maintainability risk)

The legacy `BookkeeperController` exceeds 28,000 lines of PHP in a single file. The file contains hundreds of methods, dozens of commented-out implementations (alternate versions of the same method), and no logical grouping. This makes it impossible to:
- Audit specific functionality quickly
- Apply route-level middleware selectively
- Test individual methods in isolation
- Detect duplicate or conflicting logic between commented and live implementations

**Impact:** Many methods have multiple commented-out versions, and it is not always clear which version is active. Dead code may contain older vulnerable patterns (unparameterized queries, missing auth checks) that could be accidentally re-enabled.

---

### BUG-BK-02 — Financial Export Methods Call `auth()->user()` Without a Guard
**File:** `BookkeeperController.php` — export methods  
**Severity:** Low Bug

Several export methods (`export_excelGeneralLedger`, `export_excelIncomeStatement`, etc.) call `auth()->user()->id` to log who triggered the export. Since these routes are unauthenticated (BK-03), an unauthenticated call crashes the method with:
```
Call to member function id() on null
```
This means the export routes are "protected" only by a runtime crash, not an auth check. If the export method doesn't need `auth()->user()->id` for a specific code path, the export silently succeeds — meaning some export methods work fully unauthenticated, while others crash.

---

### BUG-BK-03 — COA ID Assignment Uses Sequential Scan Instead of `AUTO_INCREMENT`
**File:** `BookkeeperController.php` — `storecoa()`  
**Severity:** Low Bug

```php
// Find the first available ID (starting from 1)
$newId = 1;
while (in_array($newId, $allExistingIds)) {
    $newId++;
}
$result = DB::table('chart_of_accounts')->insertGetId(['id' => $newId, ...]);
```

The code manually computes the next available ID by loading all existing IDs from two tables and scanning in a PHP loop. This is a race condition — two concurrent requests will both compute the same `$newId` and attempt to insert with the same primary key, causing a DB duplicate key error. For a school with hundreds of COA entries, this scan loads the entire table into memory on every insert.

---

## 6. Fix Recommendations

### Immediate
1. **BK-01:** Add `['auth', 'isBookkeeperAdmin']` to `mapBookkeeperRoutes()` in `RouteServiceProvider`.
2. **BK-02:** Add `['auth', 'isBookkeeperAdmin']` requirement to void transaction routes in addition to the existing secondary password step.
3. **BK-03:** After fixing BK-01, audit which export routes need `isBookkeeperAdmin` vs `isAccounting` access.

### Short-Term
4. **BK-05:** Remove `Session::get('currentPortal') == 67` from `AuthenticateBookkeeperAdmin`.
5. **BK-06:** Move `/add-expense-item` route under `['auth', 'isBookkeeperAdmin']` and add input validation.

### Hardening
6. **BUG-BK-01:** Begin decomposing `BookkeeperController.php` into controller groups matching the `BookkeeperControllers/` pattern — one controller per domain area.
7. **BUG-BK-03:** Replace the sequential ID scan with `DB::statement('ALTER TABLE chart_of_accounts MODIFY id INT AUTO_INCREMENT')` and remove the manual ID assignment.
