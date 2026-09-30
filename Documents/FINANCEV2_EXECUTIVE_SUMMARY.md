# FinanceV2 — Executive Summary

**Date:** May 29, 2026  
**System Reviewed:** FinanceV2

---

## What Is FinanceV2?

FinanceV2 is the software your school uses to manage student billing, tuition fees, payment records, discounts, adjustments, and financial reports. It is used daily by cashiers, finance officers, and administrators to handle real money and real student accounts.

---

## The Bottom Line

> **We recommend placing a hold on any further rollout or expansion of FinanceV2 until a focused set of security and reliability problems are fixed.**

These are not cosmetic issues. Several of the problems found could allow unauthorized people to delete or alter financial records, expose student financial data to outside parties without consent, or crash the system during peak usage periods. None of these outcomes are acceptable for a live financial system.

---

## What We Found — In Plain Terms

### 🔴 Problem 1: The Security PINs Protecting Financial Records Are Not Safe

Finance officers use a PIN code to authorize sensitive actions — like reversing a payment or voiding an adjustment. Think of this like the PIN on a debit card.

**The problem:** These PINs are stored in the system's database in plain readable text — the same way you would write a password on a sticky note. Anyone who can access the database (an IT staff member, a vendor, or someone who finds a security gap) can read every PIN in seconds.

**Why it matters:** If someone learns these PINs, they can authorize financial changes — reversals, voids, adjustments — without anyone knowing. This is a direct financial integrity risk.

**The fix:** Store PINs in a scrambled, unreadable form (the industry standard). This way, even if the database is accessed, the PINs are worthless without the correct input.

---

### 🔴 Problem 2: The PIN System Can Be Bypassed Entirely

Even if the PINs were stored safely, we found that the actual step where the system should *check* the PIN before voiding a record is missing in the code. The PIN entry screen exists, but the underlying action does not wait for PIN approval — it executes regardless.

**Why it matters:** The PIN protection on void/reversal operations gives a false sense of security. An authorized system user who knows the right web address can reverse or void financial records without ever entering a PIN.

**The fix:** The verification step must be connected to the action it is supposed to protect.

---

### 🔴 Problem 3: Student Financial Data Is Being Sent to Outside AI Services

FinanceV2 has an AI assistant feature that can "analyze" what is on the screen. When used, the system takes whatever financial information is currently visible — which can include student names, ID numbers, balances, and payment history — and sends it to a free, third-party artificial intelligence service on the internet.

**Why it matters:** This likely violates student data privacy laws (such as the Philippine Data Privacy Act and FERPA for institutions with US-affiliated accreditation). Student financial records are protected information. Sending them to an outside service without a formal data agreement is a compliance risk that could result in regulatory penalties, and the school has no control over what that service does with the data.

**The fix:** Either remove this feature until a proper legal review is done, or ensure it only sends general summaries — never names, IDs, or specific financial figures.

---

### 🔴 Problem 4: The System Can Crash Under Normal Peak Usage

One of the financial report pages (Accounts Receivable grand totals) is built in a way that, to calculate a single total, it fetches student data in small batches and adds them up one batch at a time — repeating this process potentially hundreds of times in a row.

**Why it matters:** For a school with several thousand students, this process could take so long that the system times out and crashes before it finishes — exactly when it is needed most (end-of-term, enrollment periods). It is the equivalent of counting money one coin at a time instead of using a scale.

**The fix:** Recalculate the total using a single database query, the same way a bank calculates account balances — instantly from the ledger.

---

### 🔴 Problem 5: A Technical Setting Could Allow External Attack

A specific setting in the PDF generation feature (used for printing financial reports and student account summaries) is turned on when it should be off. With this setting active, a carefully crafted piece of data could cause the server to run unauthorized commands.

**Why it matters:** This is a known category of attack. Leaving this setting on is like leaving a master key under the doormat — it may never be used, but the risk is unnecessary and easy to eliminate.

**The fix:** Turn off the setting. It is a single one-line change.

---

### 🔴 Problem 6: Item Names and Student Names Can Hijack a Finance Staff Member’s Browser

The screen that Finance staff use to view student payment history, adjustment records, and laboratory fee setups displays text from the database directly on screen. The system does not treat this text as “plain text” — it treats it as code that the browser can run.

**What this means in practice:**

- An administrator who sets up a school fee can write a fee name that, when viewed by a Finance staff member, silently runs in their browser.
- A student whose registered name contains a special sequence of characters can trigger the same effect when Finance staff load the student list.
- A laboratory fee subject item with a crafted name does the same when a Finance user expands the fee details.

**What the silent code can do:**
- Copy the Finance staff member’s session — allowing someone else to act as them in the system.
- Capture whatever that staff member types, including their authorization PIN.
- Automatically submit unauthorized financial changes (adjustments, voids, reversals) without the staff member clicking anything.

**Technical name:** This class of attack is called *stored cross-site scripting (XSS)*. It is ranked in the OWASP Top 10 — the industry standard list of the most critical web security risks.

**The fix:** The code that displays data on screen needs to be told to treat all text from the database as “plain text to be displayed,” not “code to be run.” This is a standard HTML-escaping fix that takes hours to implement across the affected screens.

---

## What Is Working Well

- The overall structure of the module is organized and follows a logical separation between different financial functions (student accounts, reports, discounts, etc.).
- Most routine operations (loading student lists, filtering by school year, generating reports) work correctly.
- The system does record who performed financial actions and when, which is the foundation of a good audit trail.
- The response masking feature shows an intention to protect data in transit, which is a good instinct even if the current implementation needs revision.

---

## Risk Summary

| Risk | Likelihood | Impact | Status |
|---|---|---|---|
| Unauthorized financial record alteration | Medium | Very High | ❌ Unresolved |
| Student financial data sent to outside parties | High (feature is live) | High | ❌ Unresolved |
| System crash during peak usage on reports | High | High | ❌ Unresolved |
| PIN/authorization bypass | Medium | Very High | ❌ Unresolved |
| PDF attack vector | Low | Very High | ❌ Unresolved |
| Browser session hijack via XSS in fee/student names | Medium | Very High | ❌ Unresolved |

---

## Recommended Actions — In Priority Order

| Priority | Action | Estimated Effort |
|---|---|---|
| 1 | Disable or restrict the AI assistant from accessing student data | Hours |
| 2 | Turn off the unsafe PDF setting | Minutes |
| 3 | Secure PIN storage and fix the missing authorization check | Days |
| 4 | Add brute-force protection to PIN entry | Hours |
| 5 | Fix the report calculation that causes system timeouts | Days |
| 6 | Apply HTML escaping to fee names, item names, and student names displayed on screen | Hours |
| 7 | Conduct a formal privacy review of all data flows | Weeks |

---

## Fix Recommendation

The FinanceV2 system should **not be expanded to additional users or campuses** until items 1 through 4 above are resolved. If the system is already live for a limited group, those five items should be treated as urgent patches — not scheduled backlog items.
