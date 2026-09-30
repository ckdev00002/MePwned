# MePwned — Technical Handoff

Prepared: 30 September 2026  
Source reviewed: `C:\Users\MDVLLN\Downloads\FROMUSB\cli`  
Version displayed by launcher: **MEPWNED v1.0**  
Status: source-based handoff; live behavior and target compatibility are unverified.

## 1. Purpose and scope

MePwned is a collection of interactive Python scripts with a central terminal menu. Its code targets school-management application functions, including accounts, academic records, finance, reporting, and notifications. Several scripts contain actions that modify remote data, disclose credentials, or execute commands. It is not a general-purpose administration client or a read-only scanner.

This document supports transfer of source ownership, maintenance, and isolated validation. Module descriptions describe implementation intent, not confirmed vulnerabilities in a deployed application. It intentionally omits exploit sequences, payload instructions, credentials, and captured personal data.

The reviewed folder contains 21 Python files, three PHP files, a `dumps` directory, and Python cache files. No dependency manifest, automated test suite, or release instructions were found inside this folder.

## 2. Architecture

```text
Terminal operator
    |
    v
mepwned.py
    |-- TOOLS: menu labels and script paths
    |-- check_modules(): existence and Python compilation checks
    |-- launch(): child process using the current Python interpreter
    v
Independent Python script
    |-- interactive input and module-specific configuration
    |-- requests or aiohttp HTTP calls
    |-- terminal output and, in some modules, local output files
    v
Return to launcher after child process exits
```

The launcher resolves paths with `os.path.abspath()` against the **current working directory**. Starting it from another directory can make existing modules appear missing. Child processes inherit that working directory and use `sys.executable`, so dependency installation must match the interpreter running the launcher.

The launcher does not provide shared configuration, a shared authenticated session, or a unified output schema. Each tool manages its own prompts, HTTP requests, and results. `workflow.py` implements its own multi-stage logic; it is not simply a subprocess wrapper around the other menu entries.

Startup checks only compile the scripts registered in `TOOLS`. “All modules OK” does not verify installed dependencies, connectivity, application compatibility, authorization, or correctness of results.

## 3. Source inventory

### Launcher menu

| Menu | Display name | Source | Responsibility / impact |
|---|---|---|---|
| 1 | CROWBAR | `madcrow.py` | Student credential collection; sensitive output |
| 2 | REAPER | `styx.py` | Academic header enumeration; record metadata output |
| 3 | NEXUS | `nexus.py` | Multi-stage academic-record mutation |
| 4 | TRASHFIRE | `dumpster.py` | Academic mastersheet collection |
| 5 | EXECVEIL | `execveil.py` | Formula-injection and remote-command payload logic |
| 6 | KILLCHAIN | `workflow.py` | Combined discovery and academic-record mutation |
| 7 | VENOM | `sqlpwn.py` | Database query and export operations |
| 8 | SPECTER | `ghost.py` | Personal/account data, backup, and grade-related operations |
| 9 | WRAITH | `ssrfetch.py` | Server-side request and file-access operations |
| 10 | LOCKPICK | `pincrack.py` | Cashier PIN attempts and transaction-void logic |
| 11 | SIREN | `smsbomb.py` | Notification requests, including repeated sending |
| 12 | KEYHAMMER | `passreset.py` | Account password-reset operations |
| 13 | CODEX | `help.py` | Existing terminal reference text |
| 0 | Exit | `mepwned.py` | Exit the launcher |

### Additional files outside the launcher menu

| File | Maintenance relevance |
|---|---|
| `adminpwn.py` | Account creation, password, privilege, and account-lifecycle actions |
| `cashierpwn.py` | Payment, receipt, and transaction actions |
| `collegepwn.py` | College academic records, curriculum, and signatory actions |
| `datapwn.py` | Financial, student, employee, reporting, and attendance data functions |
| `uploadpwn.py` | Upload/command-execution, enrollment, and configuration actions |
| `brute.py` | Standalone credential-attempt script with an embedded target |
| `mass_text.py` | Standalone notification script with an embedded external target |
| `ev_shell.php` | Command-execution template referenced by `execveil.py` |
| `evil.php` | Defacement presentation asset |
| `mepwned.php` | Separate PHP defacement/command-execution artifact; not the Python launcher |
| `dumps/` | Existing generated output; treat as restricted data |
| `__pycache__/` | Generated Python bytecode; not authoritative source |

`mepwned.php` also contains visitor logging and hidden-copy creation logic. Comments suggesting persistence are not proof of an installed scheduled task. Do not place the PHP artifacts in a served web directory for ordinary documentation review.

## 4. Local review environment

Dependencies inferred from source imports:

| Component | Role | Version status |
|---|---|---|
| Python 3 | Launcher and scripts | No supported version declared |
| `requests` | Synchronous HTTP calls | Unpinned |
| `aiohttp` | Asynchronous HTTP calls | Unpinned |
| `tqdm` | Progress display | Unpinned |
| PHP | Separate PHP artifacts | Not required for the Python launcher; compatibility unverified |

For an isolated maintenance environment, create a virtual environment from the project folder:

```powershell
Set-Location 'C:\Users\MDVLLN\Downloads\FROMUSB\cli'
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install requests aiohttp tqdm
```

These are inferred installation steps, not a tested or reproducible dependency lock. Record and pin approved versions after compatibility testing. Using the virtual environment executable directly avoids needing to change PowerShell execution policy.

For a menu-only smoke check in an isolated environment:

```powershell
.\.venv\Scripts\python.exe .\mepwned.py
```

Confirm the menu appears, then enter `0` to exit. Do not select assessment modules as part of this smoke check. The launcher startup compiles registered files and can create bytecode caches. This menu check was **not performed** during preparation of this document.

## 5. Configuration and execution model

- Most assessment scripts prompt for a base URL and module-specific values. Some request session cookies or identifiers. There is no central configuration file.
- Standalone helper scripts include embedded targets. Review these as configuration debt before any laboratory execution; do not assume they point to a local fixture.
- Several scripts execute prompts and program logic at module scope. Importing them for inspection or tests can trigger behavior. Prefer static parsing until entry points have been refactored.
- Concurrency limits, timeouts, result parsing, and exception handling vary by script. There is no suite-wide rate limiter or common retry policy.
- The source depends on application-specific routes, response formats, and record relationships. The corresponding server application and database are not provided in this folder.
- The existing `help.py` includes example settings and operational reference material. Treat the actual source as authoritative when it differs from the reference text.

For future integration testing, use a disposable application instance with synthetic accounts and records, disabled outbound notifications, and a restorable snapshot. Record expected state changes before each test. A successful HTTP response alone is insufficient evidence that the intended application behavior occurred.

## 6. Output and data handling

Output is decentralized: scripts may print responses, write JSON, download files, or prompt for a destination. Some use `dumps/`; others use filenames relative to the current working directory. No central retention, encryption, redaction, or output-schema policy was identified in the launcher.

The folder currently contains these dump filenames:

- `dumps/credentials_dump.json`
- `dumps/ghost_pii.json`
- `dumps/ghost_users.json`

Their contents were not opened for this handoff. Filenames suggest credential and personal-data content, but the actual contents and provenance remain unverified. Transfer source separately from captured data. The outgoing owner must decide who may receive existing output, its retention period, and whether any exposed credentials need rotation.

Some writers assume their destination directory already exists. Output writes using mode `w` may replace previous results. Inventory and preserve approved evidence before any future test run; do not rely on interrupted runs to produce complete output.

## 7. Known limitations and maintenance priorities

| Priority | Finding | Recommended maintenance work |
|---|---|---|
| High | Scripts can modify sensitive remote state; the launcher has no central scope enforcement | Define approved laboratory scope and introduce explicit separation of read and write actions |
| High | Embedded targets and per-script session handling | Centralize configuration and prevent accidental use of external targets in tests |
| High | Import-time execution in several scripts | Move execution into guarded `main()` entry points before importing modules into tests |
| High | No pinned dependencies or automated tests found in this folder | Establish a supported Python version, dependency lock, and mocked HTTP tests |
| Medium | Launcher paths depend on the working directory | Resolve resource paths from the script directory |
| Medium | Startup health check is syntax-only and covers only registered files | Distinguish syntax, dependency, configuration, and integration checks |
| Medium | Some output paths contain invalid escape sequences | Replace ad hoc path strings with `pathlib.Path` joins |
| Medium | Error handling and response validation vary | Use structured error categories and validate response shape before accessing fields |
| Medium | Some success messages are weak evidence of actual state | Verify test outcomes against independent application state and audit records |
| Medium | Additional scripts are absent from the launcher registry | Decide which files are supported, experimental, or retired; document that decision |
| Medium | Existing dumps are mixed with source | Establish restricted evidence storage and a sanitized source handoff package |

These are proposed improvements. No implementation changes were made for this documentation task.

## 8. Troubleshooting for maintainers

| Symptom | Likely cause / next check |
|---|---|
| Launcher reports missing files | Confirm the working directory is `cli`; paths are resolved at startup |
| `ModuleNotFoundError` after selecting a module | Check the dependency installation for the exact interpreter used by the launcher |
| “All modules OK” followed by runtime failure | Compilation does not import dependencies or validate remote response formats |
| Output file cannot be created | Check parent directory existence, permissions, and current working directory |
| JSON parsing failure | In a local fixture, inspect whether the response is HTML, a redirect, or an error rather than expected JSON |
| Terminal symbols or colors display incorrectly | Check UTF-8 and ANSI support; the code reconfigures standard output |
| Child script exits and menu returns | Inspect the child process message; the launcher does not provide a consolidated failure report |

Stopping a process does not undo completed remote writes. Restore the laboratory snapshot and verify application state after mutation tests.

## 9. Verification performed for this handoff

On 30 September 2026, all **21 Python source files passed `ast.parse`** using the locally installed Python 3.14 interpreter. This was a static syntax check: scripts were not imported or executed, and no HTTP requests were sent by the project.

Warnings were reported for invalid string escapes at:

- `ghost.py:139` and `ghost.py:171` — backslash-based output paths.
- `sqlpwn.py:133` — a backslash-based output path.

Passing syntax parsing does not establish Python 3.14 runtime compatibility. Dependency installation, PHP syntax/runtime behavior, menu interaction, network behavior, and end-to-end workflows were not validated. Existing dump contents were not inspected.

## 10. Ownership and acceptance record

Complete the following fields before accepting operational ownership:

| Item | Value |
|---|---|
| Outgoing owner | To be supplied |
| Receiving maintainer | To be supplied |
| Application/security contact | To be supplied |
| Authoritative repository and revision | To be supplied |
| License and distribution restrictions | To be confirmed |
| Supported Python and dependency versions | To be validated |
| Approved isolated test environment | To be supplied |
| Supported versus retired modules | To be decided |
| Existing dump custodian and retention decision | To be supplied |
| Known deployed PHP artifacts, if any | To be confirmed by the application owner |
| Handoff acceptance date | To be supplied |

Acceptance checklist:

- [ ] Recipient has the authoritative source snapshot and revision or checksum record.
- [ ] Recipient understands the launcher registry and additional standalone files.
- [ ] Source and sensitive output have been separated for transfer.
- [ ] Dependency versions and supported runtime have been validated and recorded.
- [ ] Menu-only startup and exit have been checked in isolation.
- [ ] Mocked tests cover malformed responses, timeouts, and output-write failures.
- [ ] Any application tests use synthetic data and a verified restoration process.
- [ ] Ownership, support contacts, and remaining maintenance work have been accepted.
