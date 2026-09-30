# CashierV2 Module — Executive Security Summary

**Date:** May 29, 2026  
**Prepared for:** School Leadership / Non-Technical Stakeholders  
**Module:** The Cashier (CashierV2) — the digital cashier window used to collect and record student payments

---

## What Is This Module?

The CashierV2 module is the software that cashiers use every day to:
- Look up students and see what they owe
- Accept and record payments (cash, check, online)
- Issue official receipts (OR numbers)
- Void incorrect transactions
- Print receipts and reports (void history, collection reports, cashier transactions)
- Display the queue number board in the cashier area

Because it handles **real money transactions and official receipt issuance**, any security weakness here has direct financial and legal consequences for the school.

---

## The Bottom Line

A review of the code found **four serious issues** that need to be fixed before this system is trusted in a live school environment. Two of them are the kind of issues that could allow someone to commit financial fraud or cause the school to lose control of its official receipt records.

---

## Issue 1 — Any Employee Can Process Payments (Not Just Cashiers)

**Risk level: HIGH**

Right now, the system checks that a person is *logged in*, but it does **not** check that they are a *cashier*. This means any school employee who has a login — a teacher, a registrar, an IT staff member — can go to the cashier page in their browser and:

- Record a payment as if they were a cashier
- Delete a suspended (parked) sale
- Look at financial reports meant only for the cashier's eyes

**Why this matters:**  
The school's official receipt records and financial transaction logs should only be writeable by people assigned to the cashier role. Without this check, unauthorized staff can post transactions that appear legitimate in the system.

**What needs to happen:**  
The software needs to check the user's assigned role before allowing any financial action. This is a straightforward fix for the development team.

---

## Issue 2 — A "Silent Print" Feature Can Be Triggered by Unauthorized Users

**Risk level: CRITICAL**

The cashier system has a feature that allows the server (the school's computer) to automatically send a receipt to the physical printer — without the cashier clicking "print" in the browser. This is meant to make printing receipts faster.

The problem: **any logged-in employee can trigger this feature**, not just cashiers. More importantly, the feature:
1. Runs a Windows program (`mshta.exe`) directly on the school's server — this is an old, risky scripting engine.
2. Can be pointed at *any* receipt in the system by providing the right receipt number.
3. Has no check that the person requesting the print actually issued that receipt.

**Why this matters:**  
In plain terms, someone with a school login could:
- Print duplicate copies of any official receipt.
- Use the server's printer to generate paper receipts that look legitimate.
- The Windows scripting engine being invoked is a known target for attackers.

**What needs to happen:**  
This feature should only be usable by cashiers, and only for receipts they issued from their own terminal. The IT/development team should also consider removing or redesigning this feature to avoid launching Windows programs from the web server.

---

## Issue 3 — PIN Codes Are Stored Unprotected in the Database

**Risk level: HIGH**

When a cashier needs to void a transaction, they (or a supervisor) enters a PIN code to authorize it. These PIN codes are stored in the database exactly as typed — no encryption, no protection.

**Why this matters:**  
If anyone ever gains access to the database — through a software vulnerability, a database backup that isn't secured, or an insider — they would immediately see every PIN code for every person authorized to approve voids. This is the same issue found in the Finance module.

**Analogy:** It is the same as writing everyone's ATM PIN on a Post-It note and leaving it on the server room wall.

**What needs to happen:**  
PIN codes need to be stored in a scrambled (hashed) form so that even if the database is viewed, the actual PIN values cannot be read.

---

## Issue 4 — Error Messages Accidentally Reveal Technical Details to Users

**Risk level: MEDIUM**

When something goes wrong in the system — a database error, a connection problem — the system currently shows the full technical error message to the person using it. This includes details like the names of database tables and internal file paths.

**Why this matters:**  
This information is a roadmap for attackers. Knowing the exact names of database tables and internal structure makes it much easier to probe for other weaknesses. These details should only appear in the school's internal server logs, not in the browser.

**What needs to happen:**  
Error messages shown to users should be simple and generic ("Something went wrong. Please try again."). The technical details should be logged internally for the IT team to review.

---

## Issue 5 — The PDF Receipt Engine Can Execute Code (Same as Finance Module)

**Risk level: CRITICAL (currently protected but risky)**

The same PDF library issue found in the Finance module is present here. Three of the report-printing features (Void History, Cashier Transactions, Collection Report) have a setting that allows the PDF engine to run PHP code.

**Current status:** Today, this is protected by a safeguard in the code that cleans the data before it reaches the PDF engine. However, that safeguard is a single line of code — if a developer ever forgets it or bypasses it, an attacker who can modify signatory records in the database could execute arbitrary code on the server.

**What needs to happen:**  
The PDF engine's "run code" setting should be permanently turned off. This is a configuration change that takes minutes and eliminates the risk entirely.
---

## Issue 6 — Malicious Item Names Can Hijack a Cashier’s Browser Session

**Risk level: HIGH**

The cashier interface displays lists of items (non-tuition fees, suspended sales) that are loaded from the database and shown directly on screen without being cleaned first. If anyone with access to set up non-tuition item records — or any cashier who creates a suspended sale with a walk-in customer name — enters a carefully crafted piece of text, that text can instruct the cashier’s browser to take unauthorized actions.

**What this looks like in practice:**

- A non-tuition item is created with a name that contains a hidden browser instruction.
- Every cashier who opens the non-tuition items panel will unknowingly trigger that instruction in their browser.
- The instruction could silently steal the cashier’s session, capture anything they type (including PINs), or quietly send financial data to an outside address.

**A second version of this issue** exists with the suspended sales list: any cashier can park a sale under a walk-in customer name. If that name contains a browser instruction, it runs in the browser of every cashier who views the suspended sales list.

**Why this matters:**  
This is a class of attack known as “stored cross-site scripting.” It is in the OWASP Top 10 list of the most critical web security risks. The impact ranges from session theft to full account takeover of cashier accounts without the cashier’s knowledge.

**What needs to happen:**  
The development team needs to ensure that any text loaded from the database and displayed on screen is treated as plain text, not as code that the browser can execute. This is a standard, well-understood fix (HTML escaping) that takes minutes per affected area.
---

## Summary Table

| Issue | Risk Level | Can Be Fixed By Dev Team In | Financial Impact If Exploited |
|---|---|---|---|
| Any employee can process payments | HIGH | 1–2 days | Unauthorized transaction recording, fraud |
| "Silent print" — unauthorized receipt printing | CRITICAL | 1 day (add role check) | Receipt duplication/forgery, audit failure |
| PINs stored unprotected | HIGH | 1–2 days | PIN theft, unauthorized voids |
| Error messages leak technical info | MEDIUM | 1 day | Enables targeted attacks |
| PDF engine can run code (protected today) | CRITICAL (latent) | 30 minutes (config change) | Full server compromise if protection fails || Malicious item names execute in cashier browsers | HIGH | 1 day (HTML escaping) | Session hijack, PIN capture, account takeover |
---

## What Is Working Well

It's important to note what the development team got right:

- **Void approvals are secure** — the process of approving a void uses short-lived one-time codes (like SMS verification codes) that expire in 2 minutes. This is a good security practice.
- **No SQL injection risk** — the database queries are written in a way that protects against the most common type of database attack.
- **Receipt numbers are validated** — the system correctly prevents duplicate receipt numbers and validates them against assigned series.
- **Queue display is intentionally public** — the queue number board (visible in the cashier waiting area) does not require a login, which is by design and not a security concern.

---

## Recommended Action Plan

| Priority | Action | Timeline |
|---|---|---|
| Immediate | Turn off PDF code-execution setting (3 places) | This week |
| Immediate | Add cashier-role check to all payment-processing routes | This week |
| Immediate | Fix HTML escaping in non-tuition items and suspended sales display | This week |
| Short-term | Add ownership check to silent-print feature | Within 2 weeks |
| Short-term | Replace plain-text PIN storage with secure hashing | Within 2 weeks |
| Short-term | Fix error messages to show generic text to users | Within 2 weeks |
| Medium-term | Consider redesigning or removing the Windows silent-print feature | Within 1 month |

---

*This document was produced as part of a security code review for school leadership. Technical details are available in the accompanying `CASHIERV2_CODE_REVIEW.md` document.*
