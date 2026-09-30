# CashierV2 Module — Code Review

**Date:** 2026-05-29  
**Reviewer:** GitHub Copilot (automated deep review)  
**Scope:** `app/Http/Controllers/CashierV2Controller/` · `resources/views/cashier_v2/` · `routes/cashierv2.php`  
**Module version tag:** HEAD (no version file found)

---

## Module Inventory

| Component | Files |
|---|---|
| Controllers | 8 PHP files across `Home/`, `SideControls/`, root |
| Views (Blade) | 35 templates in `pages/`, `modals/`, `printing_templates/`, `layouts/`, `inc/` |
| Routes | `routes/cashierv2.php` — 30+ named routes |
| Key external deps | DomPDF (via `barryvdh/laravel-dompdf`), Laravel Cache, Pusher/Echo broadcasting |

---

## 1. Summary of Findings

| # | Severity | Category | Title |
|---|---|---|---|
| 1.1 | 🔴 CRITICAL | OS Command Exposure | `serverPrint` spawns `mshta.exe` / `shell_exec` — no cashier-role check |
| 1.2 | 🔴 CRITICAL | DomPDF RCE (latent) | `enable_php = true` in 3 PDF-print methods |
| 1.3 | 🔴 HIGH | Broken Access Control | Zero RBAC — any authenticated user can process payments, void, delete |
| 1.4 | 🔴 HIGH | Plaintext Secrets | `chrng_pin.pin_code` stored in plaintext, used in PIN verification |
| 1.5 | 🟠 HIGH | IDOR | `serverPrint` — any authenticated user can print any transaction receipt |
| 1.6 | 🟠 HIGH | IDOR | Suspended sale `DELETE` — no ownership check |
| 1.7 | 🟡 MEDIUM | Info Disclosure | `$e->getMessage()` returned in 20+ JSON error responses |
| 1.8 | 🟡 MEDIUM | Crypto Key Exposure | `fv2-mask-key` AES key in `<meta>` tag of `app2.blade.php` |
| 1.9 | 🟡 MEDIUM | Resource Exhaustion | `students()` endpoint — uncapped `per_page` |
| 1.10 | 🟢 LOW | Design | Public queue-display routes (intentional, but queue numbers are publicly visible) |
| 1.11 | 🟢 LOW | Code Quality | `DiscountsContoller.php` (filename typo) contains dead mutation methods not routed |
| 1.12 | 🔴 HIGH | DOM XSS (Stored) | `displayNonTuitionItems()` — unsanitized DB values injected directly into HTML |
| 1.13 | 🔴 HIGH | DOM XSS (Stored) | `loadSuspendedSales()` — unsanitized `customer_name` / `student_name` injected into HTML |
| 1.14 | 🟢 LOW | Info Disclosure | 414 `console.log()` calls leak payment amounts, student IDs, and reference numbers in production console |

---

## 2. Detailed Findings

---

### 2.1 🔴 CRITICAL — `serverPrint` Spawns `mshta.exe` via `shell_exec` / `popen` with No Role Check

**File:** `app/Http/Controllers/CashierV2Controller/Home/CashierV2HomeController.php`, lines 3493–3577  
**Route:** `GET /cashier/server-print` — inside `auth` middleware only

**Description:**  
`serverPrint()` is intended to silently print receipts on the server-side printer. It does the following:

1. Takes `ornum` and `studid` from query parameters (only `required` validation — no further checks).
2. Calls `shell_exec('cmd /c wmic printer where "Default=TRUE" get Name /format:value 2>nul')` to discover the Windows default printer.
3. Writes HTML receipt content to `storage/app/tmp/receipt_<timestamp>_<rand>.html`.
4. Generates an HTA file (`.hta`) — a Windows HTML Application using the deprecated Internet Explorer engine (`mshta.exe`).
5. Runs `popen('cmd /c start "" "C:\Windows\System32\mshta.exe" "<htafile>"', 'r')` to launch the HTA.
6. The HTA file auto-calls `window.print()` using the server's default printer.
7. Schedules `unlink()` cleanup via `register_shutdown_function`.

**Access control issues:**  
- Protected only by `auth` middleware. **Any logged-in user** (teacher, registrar, parent portal user) can call this endpoint.
- No check that the caller is a cashier, or that the transaction belongs to their terminal.
- `$templatePath` for the receipt is read from `receipt_template` DB table (`receipt_template.template_path` → `view()`) — if an attacker with DB admin access sets a malicious path, they get server-side template injection.

**Impact:**
- Any authenticated user can trigger the server's physical printer to print any receipt.
- Receipt content is based on DB records, so forged/duplicate receipts are possible.
- `mshta.exe` is a deprecated, legacy scripting engine with a long exploit history. Spawning it from a web-facing process is high-risk in any production environment.
- Even without exploitation, this is a direct attack surface: every request launches a Windows process on the server.

**Recommended fix:**
```php
// 1. Add cashier-role check before executing
if (!$this->userIsCashier(auth()->id())) {
    return response()->json(['success' => false, 'message' => 'Unauthorized'], 403);
}

// 2. Verify the transaction belongs to the current user's terminal:
$trans = DB::table('chrngtrans')
    ->where('ornum', $ornum)
    ->where('studid', $studid)
    ->where('transby', auth()->id())  // <-- ownership
    ->where('cancelled', 0)
    ->first();

// 3. Long-term: remove mshta.exe / server-side print approach entirely.
// Print receipts in-browser via the printReceipt endpoint instead.
```

---

### 2.2 🔴 CRITICAL — DomPDF `enable_php = true` (Latent RCE)

**File:** `app/Http/Controllers/CashierV2Controller/SideControls/CashierTransactions.php`  
**Lines:** 1300 (`printVoidHistory`), 1566 (`printCashierTransactions`), 1880 (`printCollectionReport`)

**Description:**  
Three PDF-generating methods all set:

```php
$pdf->getDomPDF()->set_option('enable_php', true);
```

This allows PHP code embedded in PDF templates to execute with full server privileges.

**Current protection:**  
All three methods build `$signatoriesHtml` using `htmlspecialchars()` on every signatory field (`title`, `name`, `designation`) before concatenation. The `{!! $signatoriesHtml !!}` unescaped Blade output in the corresponding templates is therefore safe **today**.

**Risk:**  
The sole protection is developer discipline on a single helper. Any of the following breaks the chain:
- A developer adds a new signatory source that omits `htmlspecialchars()`.
- A stored signatory record is modified directly in the DB.
- A future template is created without the same discipline.

This is the same systemic risk documented in `FINANCEV2_CODE_REVIEW.md` but limited to 3 occurrences here (vs 25 in FinanceV2).

**Fix:** Set `enable_php` to `false` in all three methods:

```php
$pdf->getDomPDF()->set_option('enable_php', false);
```

---

### 2.3 🔴 HIGH — Zero RBAC: Any Authenticated User Can Process Payments, Void Transactions, Delete Records

**Files:** All controllers in `app/Http/Controllers/CashierV2Controller/`  
**Grep result:** Zero matches for `authorize()`, `Gate::`, `->can()` across entire module.

**Description:**  
Every route in `routes/cashierv2.php` is inside a single `Route::middleware(['auth'])->group(...)`. There are no role checks, permission table lookups, or policy evaluations anywhere in the module controllers.

This means:
- A teacher with a valid session can call `POST /process-payment` and record a payment transaction.
- A registrar can call `POST /cashier/void` and void any payment (if they can also obtain a void auth token).
- A student portal user (if they share the auth system) can access the cashier dashboard.

The `checkVoidPermission()` endpoint does check `faspriv` and `chrngpermission` tables — but this is **data-driven permission** enforced only in that one UI flow. It does not protect the `processPayment`, `deleteSuspendedSale`, `store` (OR setup), `update`, or `destroy` routes.

**Recommended fix:**  
Introduce a `cashier` middleware or policy:

```php
// Create app/Http/Middleware/EnsureCashierRole.php
public function handle($request, Closure $next) {
    $user = auth()->user();
    $isCashier = DB::table('teacheracadprog')
        ->where('userid', $user->id)
        ->where('acadprogutype', 11) // CASHIER user type
        ->exists();
    if (!$isCashier) {
        return response()->json(['message' => 'Forbidden'], 403);
    }
    return $next($request);
}

// Apply to mutation routes in routes/cashierv2.php
Route::middleware(['auth', 'cashier'])->group(function () {
    Route::post('/process-payment', ...);
    Route::post('/cashier/void', ...);
    Route::delete('/cashier/suspended-sales/{id}', ...);
    // etc.
});
```

---

### 2.4 🔴 HIGH — Plaintext PINs in `chrng_pin` Table

**File:** `app/Http/Controllers/CashierV2Controller/SideControls/CashierTransactions.php`, line 790  
**File:** `app/Http/Controllers/CashierV2Controller/SideControls/StudentLedgerController.php`, lines 338–345 (delegates to `DiscountV2Controller::verifyPin`)

**Description:**  
Void authorization via PIN uses:

```php
$pinRow = DB::table('chrng_pin')->where('id', $request->input('pin_id'))->first();
// ...
if (hash_equals((string) $pinRow->pin_code, (string) $provided)) {
```

`hash_equals` provides timing-safe comparison (good), but `chrng_pin.pin_code` is stored as plaintext in the database. A single SQL injection, DB dump, or insider with read access to the DB would expose all cashier PINs.

This is the same pattern found across the FinanceV2 module (5 locations there, confirmed 2 locations here via delegation to FinanceV2's `DiscountV2Controller::verifyPin`).

**Fix:**  
Hash PINs at rest using `bcrypt` / `Hash::make()`:

```php
// When saving a PIN:
DB::table('chrng_pin')->insert(['pin_code' => Hash::make($pin), ...]);

// When verifying:
if (Hash::check($provided, $pinRow->pin_code)) { ... }
```

---

### 2.5 🟠 HIGH — IDOR: `serverPrint` Can Print Any Transaction (See also 2.1)

**File:** `CashierV2HomeController::serverPrint()`, lines 3493–3577  
**Route:** `GET /cashier/server-print?ornum=X&studid=Y`

**Description:**  
Independent of the OS-execution risk in §2.1, the `serverPrint` endpoint has an IDOR:

```php
$request->validate(['ornum' => 'required', 'studid' => 'required']);
$ornum  = $request->query('ornum');
$studid = $request->query('studid');
// ... used in buildReceiptData() →
//     ->where('ct.ornum', $ornum)->where('ct.studid', $studid)->where('ct.cancelled', 0)
```

No check that the `ornum` or `studid` belongs to the authenticated user's terminal or session. Any authenticated user who knows (or guesses — OR numbers are sequential) both values can:
1. Read the content of another user's receipt.
2. Trigger the server to physically print it.

---

### 2.6 🟠 HIGH — IDOR: Suspended Sale Delete — No Ownership Check

**File:** `app/Http/Controllers/CashierV2Controller/Home/CashierV2HomeController.php`  
**Route:** `DELETE /cashier/suspended-sales/{id}`

**Description:**  
The `deleteSuspendedSale(Request $request, $id)` method deletes by ID from `suspended_sales` (or equivalent table) with no check that the record belongs to the requesting user's terminal or session. Any authenticated user with the suspended-sale ID can delete another cashier's parked transaction.

---

### 2.7 🟡 MEDIUM — `$e->getMessage()` Returned in 20+ JSON Responses

**Files:** All controllers in `CashierV2Controller/`  
**Grep result:** 20+ matches

**Representative examples:**

```php
// CashierTransactions.php
return response()->json(['error' => 'Failed to fetch transactions', 'details' => $e->getMessage()], 500);
return response()->json(['ok' => false, 'error' => $e->getMessage()], 500);

// StudentLedgerController.php
return response()->json(['error' => $e->getMessage()], 500);

// CashierV2HomeController.php
'message' => 'Error fetching tuition fees: ' . $e->getMessage()
```

Raw exception messages expose:
- Table names and column names from SQL errors.
- File paths from `FileNotFoundException`.
- Internal logic from assertion failures.

**Fix:**  
Log the full exception, return a generic message to the client:

```php
} catch (\Exception $e) {
    \Log::error('Cashier error', ['exception' => $e]);
    return response()->json(['error' => 'An error occurred. Please try again.'], 500);
}
```

---

### 2.8 🟡 MEDIUM — `fv2-mask-key` AES Encryption Key Exposed in HTML

**File:** `resources/views/cashier_v2/layouts/app2.blade.php`, line 20

```html
<meta name="fv2-mask-key" content="{{ $fv2ClientKey }}">
```

The AES-256-CBC encryption key used by `FinanceV2MaskResponses.php` to "mask" financial responses is embedded in the page's `<head>`. Any authenticated user can read it from the browser's page source.

This was identified in the FinanceV2 review; the CashierV2 module shares the same layout/key. The encryption provides no actual protection since both the key and ciphertext are available client-side.

**Fix:** Remove `$fv2ClientKey` from the layout, or accept that this is intentional obfuscation only (not security). Do not call it encryption in documentation.

---

### 2.9 🟡 MEDIUM — Uncapped `per_page` in Student Listing

**File:** `app/Http/Controllers/CashierV2Controller/Home/CashierV2HomeController.php`  
**Method:** `students(Request $request)`, line 60

```php
$perPage = (int) $request->query('per_page', 50);
// No max() cap
```

A request with `?per_page=999999` will attempt to fetch all students in a single DB query. With enrollment-status lookups that run per-student-level, this can cause timeouts and high memory usage.

The `getCashierTransactions()` method does correctly cap: `$perPage = max(1, min(200, (int) $request->input('per_page', 25)));`. The same pattern should be applied consistently.

**Fix:**
```php
$perPage = max(1, min(200, (int) $request->query('per_page', 50)));
```

---

### 2.10 🟢 LOW — Queue Display Routes Are Publicly Accessible (Intentional)

**File:** `routes/cashierv2.php`, lines 12–16

```php
Route::get('/queue-display', [QueueDisplayController::class, 'show'])
    ->name('cashierv2.queue_display');
Route::get('/cashier/queue/current', [QueueDisplayController::class, 'getCurrentQueue'])
    ->name('cashierv2.queue.current');
```

These two routes are **outside** the `auth` middleware group — intentional, as queue display screens are often TV displays without login sessions.

`getCurrentQueue()` only reads from `chrng_queuing_setup` (queue number + terminal description) — no PII, no financial data. This is acceptable.

**Note for audit:** Document this explicitly as an intentional design decision in internal security records.

---

### 2.11 🟢 LOW — `DiscountsContoller.php` — Filename Typo + Dead Mutation Methods

**File:** `app/Http/Controllers/CashierV2Controller/SideControls/DiscountsContoller.php`

The filename is missing an `r` (should be `DiscountsController.php`). The class contains `store()`, `update()`, and `destroy()` methods but `routes/cashierv2.php` only exposes `GET /cashier/discounts` → `index()`. The mutation routes are not registered.

While not a current vulnerability, if a developer adds a catch-all route or auto-discovers routes, these methods become unexpectedly accessible. The methods themselves do proper Validator checks but have no cashier-role enforcement.

---

### 2.12 🔴 HIGH — DOM XSS (Stored): `displayNonTuitionItems()` Injects Unsanitized DB Values into HTML

**File:** `resources/views/cashier_v2/pages/home.blade.php`, lines ~10590–10652  
**Function:** `displayNonTuitionItems(items)`

**Description:**  
The `displayNonTuitionItems()` JavaScript function builds an HTML string by directly concatenating server-returned values and then inserts it into the DOM via `$panelBody.html(html)`. None of the values are HTML-escaped:

```js
// All four of these are concatenated raw — no escaping:
html += '<h6 ...>' + classification + '</h6>';  // classification_name from DB
html += '<strong ...>' + item.description + '</strong>'; // non-tuition item description
html += '<small ...>Code: ' + item.itemcode + '</small>'; // non-tuition item code
html += '<span ...>' + formattedAmount + '</span>'; // formatted amount string from DB

$panelBody.html(html); // inserted into DOM
```

**Attack path:**  
Any user with access to manage non-tuition item records (typically an Admin or Finance staff) can store an XSS payload in an item's `description`, `itemcode`, or `classification_name`. When any cashier opens the non-tuition items panel, the payload executes in their browser.

**Impact:**  
- Session hijacking (steal `XSRF-TOKEN` cookie or `localStorage` data).  
- Keylogging — capture PINs typed into the void authorization flow.  
- Exfiltrate the `fv2-mask-key` AES key from the `<meta>` tag, enabling decryption of all masked API responses.  
- DOM manipulation to redirect payment confirmation to a different endpoint.

**Fix:** Use jQuery's `.text()` for text nodes or a sanitization utility (e.g., a `escapeHtml()` helper) before concatenating into HTML:

```js
function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Usage:
html += '<strong>' + escapeHtml(item.description) + '</strong>';
html += '<small>Code: ' + escapeHtml(item.itemcode) + '</small>';
html += '<h6>' + escapeHtml(classification) + '</h6>';
```

Alternatively, build DOM nodes via `$('<strong>').text(item.description)` instead of string concatenation.

---

### 2.13 🔴 HIGH — DOM XSS (Stored): `loadSuspendedSales()` Injects Unsanitized Customer Name into HTML

**File:** `resources/views/cashier_v2/pages/home.blade.php`, lines ~20728–20736  
**Function:** `loadSuspendedSales()` (inside the success callback for `GET /cashier/suspended-sales`)

**Description:**  
Suspended-sale rows are rendered by concatenating server data into an HTML template literal without escaping:

```js
const customerName = sale.customer_name || sale.student_name || '-';
const studentId   = sale.sid || '-';

tableHtml += `<tr class="suspended-sale-row" data-id="${sale.id}" ...>`;
tableHtml += `<td>${studentId}</td>`;      // sale.sid — unescaped
tableHtml += `<td>${customerName}</td>`;   // user-entered free text — unescaped
tableHtml += `<td>${createdAt}</td>`;
```

`$('#suspendedSalesList').html(tableHtml)` then inserts the result into the DOM.

**Attack path:**  
A cashier creates a suspended sale for a walk-in customer and sets the customer name to an XSS payload (e.g., `<img src=x onerror="fetch('/exfil?c='+document.cookie)">`).

When *any* cashier opens the Suspended Sales panel on their terminal, the payload executes in their browser with full access to the cashier application's context.

**Impact:** Same as §2.12 — session hijack, PIN keylogging, AES key theft, DOM manipulation.

**Fix:** Apply `escapeHtml()` (defined above) to all interpolated values:

```js
tableHtml += `<td>${escapeHtml(studentId)}</td>`;
tableHtml += `<td>${escapeHtml(customerName)}</td>`;
tableHtml += `<td>${escapeHtml(createdAt)}</td>`;
tableHtml += `<tr ... data-id="${escapeHtml(String(sale.id))}" ...>`;
```

Also validate that `sale.id` is a positive integer on the backend before returning it (it should be, but defense-in-depth).

---

### 2.14 🟢 LOW — 414 `console.log()` Calls Expose Payment Data in Production Console

**File:** `resources/views/cashier_v2/pages/home.blade.php`  
**Count:** 414 `console.log` / `console.error` / `console.warn` calls

**Notable examples (from payment processing):**

```js
console.log('[PROCESS-PAYMENT] Payment calculation:', {
    totalAmount, totalAmountPaid, discountAmount, amountTendered
});
console.log('[PAYMENT-DETAILS-COLLECTED]', paymentDetails);
// paymentDetails includes: type, amount, reference, bank_name, check_number, check_date

console.log('[TERMINAL-CHECK] User has assigned terminal:', response.terminal);
console.log('Current user loaded:', currentUser);
console.log('Modal opening - Student ID:', studentId, 'Level ID:', levelid, ...);
```

**Impact:**  
Any person who opens browser DevTools on a cashier workstation can see:
- Full payment breakdown (amounts, payment types, references, check/bank details)
- Student IDs, level IDs, course IDs
- Terminal assignment details
- User identity details

In a school lab or shared-terminal environment this is a real exposure vector. If browser telemetry or an extension captures console output, this data is forwarded externally.

**Fix:**  
Remove or gate all `console.*` calls behind a development flag:

```js
const DEBUG = false; // Set via build tool or env variable
if (DEBUG) console.log('[PROCESS-PAYMENT]', ...);
```

Or use a webpack/Laravel Mix build step to strip `console.*` calls in production builds.

---

## 3. Frontend & Handshake Architecture

This section covers the JavaScript layer (`home.blade.php`, modal files, `app2.blade.php`) and how it communicates with the backend API.

### 3.1 CSRF Protection — Per-Call, No Global Setup

The layout (`app2.blade.php`) sets a `<meta name="csrf-token">` tag. CSRF tokens are then included manually per call — there is no `$.ajaxSetup()` global header. All reviewed state-changing AJAX calls include the token correctly:

- `POST /process-payment` → `headers: {'X-CSRF-TOKEN': ...}` ✅
- `POST /cashier/suspended-sales` → `headers: {'X-CSRF-TOKEN': ...}` ✅
- `DELETE /cashier/suspended-sales/:id` → `headers: {'X-CSRF-TOKEN': ...}` ✅
- `POST /cashier/void/verify-pin`, `POST /cashier/void` → `_token: ...` in POST body ✅
- All early-load `GET` calls (user info, school info, school year) correctly omit CSRF (Laravel does not require it for GET) ✅

No CSRF gaps were found in the reviewed code paths.

### 3.2 AES Response Decryption via `$.ajax` / `fetch` Monkey-Patching

The tail of `app2.blade.php` overrides the global `$.ajax` and `window.fetch` functions to auto-decrypt responses whose JSON contains a `payload` key:

```js
// app2.blade.php (line ~2395)
$.ajax = function(options) {
    options.success = wrapSuccess(originalSuccess);
    // ...
    return originalAjax.call($, options);
};
```

The decryption key is read from `<meta name="fv2-mask-key">` using CryptoJS AES-256-CBC (CryptoJS v3.1.2, inlined ~360 lines).

**Consequences:**
- Every `$.ajax()` and `fetch()` call in the entire application is silently intercepted.
- Any XSS payload in the page has immediate access to the `fv2-mask-key` and can decrypt all "masked" API responses.
- CryptoJS 3.1.2 is from 2013. It is not actively maintained. For this specific use-case (direct key AES-CBC, not password-derived), the primary known weakness is the lack of authenticated encryption (no HMAC/GCM), meaning a MITM could flip bits in the ciphertext without detection.
- The `$.ajax` override introduces fragility: if a third-party script replaces `$.ajax` before or after the layout runs, the chain breaks silently.

This is the same pattern already documented in §2.8. The additional concern raised here is the **global monkey-patching creating an XSS amplification surface**.

### 3.3 Payment Data Flow: Client → Server Trust Boundary

The `processPayment()` JS function collects:
- `total_amount` from `window.latestGrandTotalForPayment` (JS variable)
- `amount_tendered` computed from `totalAmountPaid` (JS variable)
- `payment_details[].amount` parsed from DOM text content (`$row.find('td:nth-child(6)').text()`)
- `selected_items` from `selectedItemsData` (JS array populated by prior API calls)

All of these are client-side values. A user with DevTools open can modify them before clicking **PROCESS PAYMENT**. The backend `processPayment()` must be the authoritative validator (it is — it recalculates amounts from DB records). Client-side values are convenience inputs, not trusted totals.

Action: confirm that the backend `processPayment()` method ignores `total_amount` from the request and recomputes it server-side from `selected_items` IDs.

### 3.4 Iframe-Based Browser Print (Separate from `serverPrint`)

After a successful payment, the client silently loads the receipt URL into a hidden `<iframe>` to trigger the browser's built-in print dialog:

```js
printFrame.src = '{{ route("cashierv2.print_receipt") }}'
    + '?ornum=' + encodeURIComponent(response.data.or_number)
    + '&studid=' + encodeURIComponent(studentId || '')
    + (isFullPayment ? '&full_payment=1' : '');
```

`encodeURIComponent()` is used correctly — no reflected XSS in the URL. ✅  
The `print_receipt` route should also validate that the requesting user owns that OR number (same IDOR risk as `serverPrint` — see §2.5).

---

## 4. Void Authorization Flow (Security Positive)

The void transaction flow is one of the better-designed parts of this module:

1. `checkVoidPermission()` checks `faspriv` / `chrngpermission` tables for the user.
2. `verifyVoidPin()` uses `hash_equals()` (timing-safe) and generates a **cryptographically random ephemeral token** via `bin2hex(random_bytes(16))`.
3. `verifyVoidCredentials()` uses `Hash::check()` (correct) against the `users.password` field.
4. Both flows store the token in **Cache** for 2 minutes with `Cache::put('void_auth_' . $token, ...)`.
5. `voidTransaction()` calls `Cache::pull()` (consume-once) and validates that the token's `chrngtransid` matches the request.
6. Double-void is prevented by checking `chrngvoidtrans` for an existing record before inserting.

**Remaining issues in this flow:**
- The PIN itself is plaintext (see §2.4).
- `checkVoidPermission()` can be called by any authenticated user, not just cashiers — returns internal permission status.

---

## 5. What Is Done Well

| Practice | Detail |
|---|---|
| Query Builder parameterization | All DB queries use Eloquent/Query Builder binding — no raw string concatenation with user input |
| CSRF protection | All POST/DELETE routes use Laravel's CSRF middleware (default); all JS AJAX state-changing calls include CSRF token ✅ |
| `signatoriesHtml` escaping | All three PDF builders apply `htmlspecialchars()` to all signatory fields before concatenation |
| Void ephemeral tokens | `bin2hex(random_bytes(16))` — cryptographically secure, consume-once via `Cache::pull()` |
| `verifyVoidCredentials` | Correctly uses `Hash::check()` against hashed password |
| `perPage` cap in transactions | `CashierTransactions::getCashierTransactions()` caps at `min(200, ...)` |
| Academic program scoping | `getUserAcadProgs()` restricts student list to the cashier's assigned programs |
| Pagination on student list | Paginated by default (`per_page: 50`), total count returned |
| Error messages in UI dialogs | `Swal.fire({ text: errorMessage })` uses `text:` not `html:` — XSS-safe for error display |
| Print URL encoding | `processPayment()` uses `encodeURIComponent()` on OR number and student ID when building iframe `src` |

---

## 6. Quick Wins (Can Fix Today)

| # | Fix | File | Effort |
|---|---|---|---|
| A | Set `enable_php = false` in 3 PDF methods | `CashierTransactions.php` lines 1300, 1566, 1880 | 5 min |
| B | Cap `per_page` in `students()` | `CashierV2HomeController.php` line 60 | 1 min |
| C | Add ownership check to `serverPrint` | `CashierV2HomeController.php` line 3493 | 15 min |
| D | Add ownership check to `deleteSuspendedSale` | `CashierV2HomeController.php` | 5 min |
| E | Replace `$e->getMessage()` with `\Log::error` + generic message | All controllers | 30 min |
| F | Add `escapeHtml()` helper and apply to `displayNonTuitionItems()` | `home.blade.php` line ~10590 | 15 min |
| G | Apply `escapeHtml()` to `loadSuspendedSales()` table rows | `home.blade.php` line ~20728 | 10 min |
| H | Remove or gate `console.log` calls behind a DEBUG flag | `home.blade.php` (414 calls) | Build-step config |

---

## 7. Pre-Release Minimum Checklist

Before deploying to production:

- [ ] **serverPrint**: Add cashier-role check + transaction ownership validation (§2.1, §2.5)
- [ ] **DomPDF**: Disable `enable_php` in all 3 methods (§2.2)
- [ ] **RBAC**: Add `cashier` middleware to mutation routes (§2.3)
- [ ] **PINs**: Hash PINs at rest using `Hash::make()` (§2.4)
- [ ] **$e->getMessage()**: Replace all 20+ with logged error + generic HTTP 500 message (§2.7)
- [ ] **per_page cap**: Add `min(200, ...)` to `students()` (§2.9)
- [ ] **Suspended sale IDOR**: Add ownership check to `deleteSuspendedSale` (§2.6)
- [ ] **DOM XSS — non-tuition items**: Apply `escapeHtml()` in `displayNonTuitionItems()` (§2.12)
- [ ] **DOM XSS — suspended sales**: Apply `escapeHtml()` in `loadSuspendedSales()` (§2.13)
- [ ] **console.log cleanup**: Remove or gate all 414 debug console calls behind a dev-only flag (§2.14)

---

## 8. Security Audit At-a-Glance

| Issue | Severity | Status | Occurrences |
|---|---|---|---|
| `serverPrint` OS exposure | 🔴 CRITICAL | Open | 1 method |
| DomPDF `enable_php = true` | 🔴 CRITICAL (latent) | Open | 3 methods |
| Zero RBAC | 🔴 HIGH | Open | Module-wide |
| Plaintext PINs | 🔴 HIGH | Open | Shared with FinanceV2 |
| DOM XSS — non-tuition items | 🔴 HIGH | Open | 1 JS function |
| DOM XSS — suspended sales | 🔴 HIGH | Open | 1 JS function |
| `serverPrint` IDOR | 🟠 HIGH | Open | 1 method |
| Suspended sale IDOR | 🟠 HIGH | Open | 1 method |
| `$e->getMessage()` exposure | 🟡 MEDIUM | Open | 20+ locations |
| AES key in `<meta>` + `$.ajax` patching | 🟡 MEDIUM | Open | 1 layout (shared) |
| Uncapped `per_page` | 🟡 MEDIUM | Open | 1 endpoint |
| Public queue routes | 🟢 LOW | Intentional | 2 routes |
| 414 `console.log` in production | 🟢 LOW | Open | `home.blade.php` |
| Dead mutation methods | 🟢 LOW | Info | 1 file |

---

*End of CashierV2 Code Review*
