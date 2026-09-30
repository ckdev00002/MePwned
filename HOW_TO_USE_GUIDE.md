# FROMUSB GUI: Local Interface and Maintenance Guide

**Entry point:** `C:\Users\MDVLLN\Downloads\FROMUSB\gui.py`  
**Interface name:** MEPWNED / PHANTOMIDX  
**Source review date:** 30 September 2026

> This guide documents local startup, navigation, controls, storage, shutdown, and troubleshooting from the supplied source code. The application includes credential extraction, account takeover, academic and financial record modification, SMS flooding, and remote shell functions. Instructions for executing those attack functions, payloads, credential acquisition, and exploitation chains are excluded. Module descriptions below identify their purpose and potential effects; they are not execution procedures.

## Contents

1. [What the application is](#1-what-the-application-is)
2. [Files and folders](#2-files-and-folders)
3. [Local startup](#3-local-startup)
4. [Interface walkthrough](#4-interface-walkthrough)
5. [Global settings and persistence](#5-global-settings-and-persistence)
6. [Forms and field behavior](#6-forms-and-field-behavior)
7. [Run, output, clear, and kill behavior](#7-run-output-clear-and-kill-behavior)
8. [Module inventory](#8-module-inventory)
9. [Files, logs, and saved results](#9-files-logs-and-saved-results)
10. [Local inspection workflow](#10-local-inspection-workflow)
11. [Shutdown and cleanup](#11-shutdown-and-cleanup)
12. [Troubleshooting](#12-troubleshooting)
13. [Implementation limitations](#13-implementation-limitations)
14. [Maintenance and verification](#14-maintenance-and-verification)
15. [Quick reference](#15-quick-reference)

## 1. What the application is

`gui.py` is a Flask web application. It serves an HTML interface in a browser and can launch Python scripts from the `cli` folder. It is not a native Windows desktop window.

The local architecture is:

```text
Browser on this PC
        |
        | local HTTP connection
        v
gui.py / Flask at 127.0.0.1:5000
        |
        | launches a child Python process when RUN is invoked
        v
Script in FROMUSB\cli
        |
        +-- output streamed back to the browser
        +-- files written according to the selected script
        +-- external requests made by that script
```

The configured server settings are:

| Setting | Source value | Meaning |
|---|---|---|
| Bind address | `127.0.0.1` | The web interface listens on the local loopback address. |
| Port | `5000` | The browser must use this port. |
| Debug mode | `False` | Flask's debug mode is disabled. |
| Threaded mode | `True` | The server can handle multiple requests concurrently. |
| Templates | `templates` beside `gui.py` | HTML is loaded relative to the source file. |
| Child interpreter | `sys.executable` | Child scripts use the Python interpreter that launched the GUI. |
| Child working folder | `FROMUSB\cli` | Relative child-script file paths are resolved here. |

Starting the GUI does not itself launch one of the listed CLI tools. Selecting a sidebar item builds its form locally. Execution is a separate action.

This guide is based on static source inspection. No target-facing tools were run, no stored credential dumps were read, and runtime success against any target has not been verified.

## 2. Files and folders

```text
FROMUSB\
├── gui.py                       Local Flask entry point
├── templates\
│   ├── index.html               Main interface, styles, browser logic
│   └── docs.html                Built-in documentation page
├── cli\                        CLI programs launched by the GUI
│   ├── dumps\                  Existing output directory
│   ├── README.md                Existing CLI documentation
│   ├── HANDOFF.md               Existing project notes
│   └── ...                     Python scripts and other assets
├── Analysis Docs\              Existing analysis/report documents
├── security_tracker.xlsx       Existing workbook
├── a.py                        Separate database extraction script
└── all_schools_credentials.json Existing sensitive-data artifact
```

Keep `gui.py`, `templates`, and `cli` together. Copying only `gui.py` does not produce a complete application.

The GUI does not automatically import every Python file in the folder. Its `TOOLS` list determines which scripts appear in the sidebar. A script present on disk may have no GUI entry.

`a.py` is not the GUI entry point and is not in its tool registry. It contains a direct database connection and extraction routine. Do not use it as a startup or dependency-check command. Its embedded connection details are intentionally not reproduced here.

The existing JSON artifact and dump files are not configuration prerequisites for rendering the home page. Do not publish the entire directory as a documentation bundle: it includes potentially sensitive artifacts and source with embedded connection details.

## 3. Local startup

### 3.1 Check the existing Python environment

Open PowerShell and inspect the installed interpreter:

```powershell
python --version
python -c "import sys; print(sys.executable)"
```

If your installation uses the Windows Python launcher instead, use `py` consistently in place of `python`.

The reviewed project does not contain a dependency manifest specifying tested versions. A precise supported Python version or package-version combination cannot be established from the files reviewed.

The GUI imports two third-party packages directly: `flask` and `requests`. You can check those imports without importing the application or any CLI script:

```powershell
python -c "import flask, requests; print('GUI imports available')"
```

An import check verifies package availability only. It does not verify templates, child scripts, remote connectivity, or any module behavior.

### 3.2 Open the local interface

With an existing environment that satisfies the GUI imports:

```powershell
Set-Location -LiteralPath 'C:\Users\MDVLLN\Downloads\FROMUSB'
python .\gui.py
```

Keep that PowerShell window open. Open this address in a browser:

```text
http://127.0.0.1:5000
```

The code prints a startup message containing this address, but does not automatically open a browser.

The expected initial screen contains:

- MEPWNED and PHANTOMIDX branding.
- A `? DOCS` link.
- Global `URL`, `SESSION`, and `CF` inputs.
- A left sidebar of tool names.
- A `SELECT A TOOL` heading.
- An initially disabled `RUN` button.
- An `OUTPUT` area with the status `idle`.

Use `http`, not `https`, for this local interface. Its loopback address is the GUI server address, not a target-system setting.

### 3.3 Built-in documentation

The `? DOCS` link opens `/docs` in a separate tab. This route renders `templates\docs.html` and receives the same tool definitions used by the main page.

Existing documentation can drift from implementation. For actual browser behavior, `index.html` and `gui.py` are the relevant source files.

## 4. Interface walkthrough

| Area | Purpose | Important behavior |
|---|---|---|
| Top bar | Shared settings and documentation link | Shared values can survive browser reloads. |
| Sidebar | Select a registered module | Selection is blocked while this page considers a run active. |
| Tool header | Name, description, and category | Descriptions are capability labels, not runtime verification. |
| Form | Inputs defined for the selected module | Rebuilt when a module is selected. |
| RUN | Starts the selected backend script | Has real effects; it is not a preview. |
| KILL | Requests termination of the tracked child | Does not undo completed actions. |
| Small `✕` button | Clears the visible output | Does not stop a process. |
| OUTPUT | Displays streamed child output | Not a durable log or success report. |
| EXECVEIL-specific panel | Additional remote-shell interface | Deployment and command-execution instructions are outside this guide. |

Selecting an item changes its highlighted sidebar state, updates the header, rebuilds the form, enables RUN, and clears the output panel.

Tool-specific unsaved edits are not maintained as per-tool profiles. Selecting another item and returning rebuilds the original form using its defaults and current global settings.

## 5. Global settings and persistence

### 5.1 What the top-bar fields represent

| Label | Code meaning | Storage |
|---|---|---|
| URL | Shared base-URL value | Browser local storage |
| SESSION | Shared session-cookie value | Browser local storage |
| CF | Shared clearance-cookie value | Browser local storage |

The password input type masks characters on screen. It does not encrypt the saved value.

The browser saves these three values under the local-storage key `mp_global`. The stored object has `url`, `session`, and `cf` properties. Changes are saved by the `change` event, generally when an edited input loses focus.

The restore code runs when the page loads. Closing and reopening the browser is therefore not a reliable way to erase these fields.

### 5.2 Global values versus local edits

When a form is constructed, matching global settings populate supported fields. A manual edit marks an input as dirty. Subsequent global synchronization skips dirty inputs so that the local edit is not immediately overwritten.

Consequences:

1. The value shown inside a tool form can differ from the top-bar value.
2. Changing a global value does not guarantee every displayed field changed.
3. Reselecting a module rebuilds its form and discards those input objects and their dirty flags.
4. The RUN handler collects values from the current form; it does not submit the top bar as a separate configuration object.

### 5.3 CF synchronization limitation

The form builder initializes the CF field from the global value, but does not give the `global_cf` input the `data-global="cf"` attribute that `syncGlobal()` searches for. A global CF change may therefore fail to update an already-rendered form.

This is a source-level UI inconsistency, not evidence that a remote service rejected a value.

### 5.4 Clearing saved settings

For a complete browser-side reset, remove the `mp_global` item from local storage for `http://127.0.0.1:5000` using the browser's developer tools, then reload the page. Alternatively, clear that origin's site data through browser settings.

Browser settings and developer-tool layouts vary, but the item to identify is **Local Storage → the local GUI origin → `mp_global`**.

Clearing these values does not revoke a credential, delete output files, or clear the server's in-memory shell configuration. Restarting the GUI clears its in-memory dictionaries.

## 6. Forms and field behavior

The GUI builds inputs from metadata in the Python `TOOLS` list. Field types include text, URL, password, number, and select inputs.

### Defaults are static

Defaults are source-code values. They are not discovered from the target and are not evidence that an identifier, date, account, or record exists. In particular, a prefilled date is not automatically today's date.

### All dependent fields remain visible

The code defines `updateDependentVisibility()`, but it is currently a no-op. Changing Mode or POC does not hide irrelevant fields.

A visible field is therefore not proof that the selected branch uses it. The backend selects which values to include in its generated input.

### Validation is limited

The click handler reads input values and sends them as JSON. It does not run a comprehensive validation step. Browser input types alone do not establish required values, acceptable ranges, or semantic correctness.

Values collected through `.value` are strings, including values shown in number inputs.

### The form is not an interactive terminal

The backend prepares a complete sequence of input lines before the child runs, writes them to standard input, and closes that stream. The OUTPUT panel cannot answer a later CLI prompt.

If a CLI script gains a new prompt without a corresponding wrapper change, the GUI may feed the wrong answer to the wrong prompt or encounter end-of-file. Such mismatches require maintenance; repeatedly running the same operation is not a diagnosis.

Some wrappers also supply fixed answers to confirmation prompts. The GUI must not be assumed to pause before every consequential action.

## 7. Run, output, clear, and kill behavior

This section explains control semantics, not target-facing execution procedures.

### RUN lifecycle

When RUN is invoked, the browser marks itself busy, disables the RUN button, shows KILL, clears previous output, and submits the current form to the Flask backend.

The backend launches the registered script with unbuffered Python output, merges standard error into standard output, and streams text back. Color escape sequences are translated into HTML styles.

### Status meanings

| Status | Actual meaning |
|---|---|
| `idle` | Initial or cleared display state. |
| `● running` | The browser currently considers a run active. |
| `done` | The browser stopped treating the stream as active. |

**`done` is not a success verdict.** It can appear after normal completion, an exception, a stream failure, or an abort. The server waits for the child but does not include its exit status in the completion event.

Clearing output during a run can display `idle` even while the run remains active. The label and process state are not a single authoritative status system.

### Output timing

The server emits output when it sees a newline or carriage return. A prompt that has no line ending may not appear immediately. A quiet display alone cannot distinguish waiting for a network response, buffering, or failure.

The browser tries to replace consecutive progress lines instead of adding each update. It recognizes percentage/progress patterns heuristically; this is a display convenience, not a structured progress protocol.

### Clear versus KILL

The small `✕` button clears the main output panel and resets its label. It does not stop a child, remove files, reset a form, or clear saved global values.

KILL aborts the browser stream and sends a termination request for the tracked child. The UI prints `killed by user` without first verifying the server's response. The message alone does not prove termination.

Stopping a local child cannot roll back requests already completed or server-side work already started. There is no transaction rollback facility in the wrapper.

### Browser tabs and concurrent use

The single-run guard belongs to the current page. It is not a server-wide queue or lock. The backend tracks children by tool ID, not by a unique job ID. Multiple tabs launching the same tool can overwrite that tracking entry.

Use one GUI tab for local inspection. Do not interpret the disabled RUN button as a guarantee that the server has only one child process.

## 8. Module inventory

This table identifies all 17 registered GUI modules. Capabilities are taken from the registry and are not independently verified against a remote system.

| Display name | Script | Capability category and potential effect |
|---|---|---|
| MadCrow | `madcrow.py` | Credential collection; sensitive-data exposure. |
| REAPER | `styx.py` | Grade-header enumeration; repeated remote requests. |
| NEXUS | `nexus.py` | Multi-step academic-grade modification. |
| TRASHFIRE | `dumpster.py` | Bulk academic-data extraction. |
| EXECVEIL | `execveil.py` | Remote code execution and shell functionality. |
| KILLCHAIN | `workflow.py` | Automated enumeration and grade-modification workflow. |
| VENOM | `sqlpwn.py` | Database extraction and SQL operations; possible data changes. |
| SPECTER | `ghost.py` | Personal-data extraction, backup operations, and record changes. |
| WRAITH | `ssrfetch.py` | Server-side request and file-access functions; secret exposure. |
| LOCKPICK | `pincrack.py` | PIN guessing and transaction-void functionality. |
| SIREN | `smsbomb.py` | SMS sending and flooding; external-message effects. |
| KEYHAMMER | `passreset.py` | Password-reset operations across accounts. |
| OVERLORD | `adminpwn.py` | Account, privilege, and administrative changes. |
| HYDRA | `collegepwn.py` | Academic-record and related configuration operations. |
| ORACLE | `datapwn.py` | Personal/financial/academic data access and attendance changes. |
| FORGE | `cashierpwn.py` | Financial records, receipts, voids, and PIN-related operations. |
| PAYLOAD | `uploadpwn.py` | Shell upload/execution and enrollment/configuration changes. |

The colors and tags do not implement permissions or a safety classification. A module described as a data tool can also contain write operations. There is no universal dry-run switch in the GUI.

## 9. Files, logs, and saved results

### Working-directory rule

All GUI-launched children start with `cwd` set to `FROMUSB\cli`.

For example, a relative path `example.json` used by a child resolves to:

```text
C:\Users\MDVLLN\Downloads\FROMUSB\cli\example.json
```

A relative path `dumps\example.json` resolves to:

```text
C:\Users\MDVLLN\Downloads\FROMUSB\cli\dumps\example.json
```

These examples illustrate local path resolution only. Individual scripts determine whether they write a file and what its actual name is. Do not assume all results go into `dumps`.

### Paths are on the server's filesystem

Text fields that refer to filenames are passed to Python. They are not browser upload controls or download dialogs. Files are resolved on the PC running `gui.py`.

### No central output manager

The GUI has no shared file browser, output history, export button, or automatic run folder. Some scripts open files in write mode, which can replace an existing file of the same name.

### Terminal text is temporary

The main output is stored in page elements. Selecting another module, starting another run, clearing, or reloading can remove it. There is no generic automatic terminal-log file in the GUI backend.

When recording a local UI issue, keep a sanitized note containing the module name, visible error, time, and action taken. Exclude credentials, personal information, and extracted records from shared troubleshooting notes.

## 10. Local inspection workflow

This workflow lets you inspect the interface without invoking a tool:

1. Open PowerShell and start `gui.py` as described above.
2. Open `http://127.0.0.1:5000`.
3. Check whether saved global values have been restored. Clear browser storage if you need a clean inspection session.
4. Leave target and credential fields empty.
5. Select sidebar items to inspect their labels and layout.
6. Change a dropdown only to inspect the form's display behavior; do not click RUN.
7. Observe that mode-specific fields currently remain visible.
8. Open `? DOCS` to confirm the local documentation page renders.
9. Record any layout problem or browser-console error without including saved secrets.
10. Close the browser tabs and stop Flask with `Ctrl+C` in PowerShell.

Selecting a tool and changing form fields do not themselves launch its CLI script in the reviewed frontend. Avoid shell CONNECT and command controls during this inspection workflow.

## 11. Shutdown and cleanup

If no child is running, stop the local Flask process with `Ctrl+C` in its PowerShell window. Reloading the browser afterward should no longer load the page from that server.

If there is an active child, request KILL first and inspect the terminal/process state before stopping the server. The code has no comprehensive process-tree cleanup or job-recovery system. Terminating the Flask process alone should not be treated as proof that every child stopped.

Closing a browser tab can cause stream cleanup that kills a child, but disconnect timing is not a reliable stop procedure.

For a complete local cleanup:

- Remove the GUI origin's saved `mp_global` browser data if it is no longer needed.
- Stop and restart the server to clear its in-memory configuration.
- Review generated files separately; the GUI has no delete-results command.
- Preserve anything needed for an authorized review in appropriately restricted storage.

Closing the special shell panel only hides it and clears its visible output. It does not clear the server's shell dictionary or remove a remote artifact.

## 12. Troubleshooting

| Symptom | Likely explanation | Local diagnostic step |
|---|---|---|
| `python` is not recognized | Interpreter missing from PATH or wrong command | Check the installed interpreter or Windows `py` launcher. |
| Missing `flask` or `requests` | Wrong/incomplete Python environment | Run the GUI import check with the same interpreter used to launch it. |
| Browser says connection refused | Server stopped, startup failed, or wrong address | Read the PowerShell output and check `http://127.0.0.1:5000`. |
| HTTPS connection fails | GUI does not configure TLS | Use the local HTTP address. |
| Port/address already in use | Another process owns port 5000 | Identify its owner; do not terminate an unknown process indiscriminately. |
| `TemplateNotFound` | Missing or moved template files | Check `templates\index.html` and `templates\docs.html` beside `gui.py`. |
| Sidebar item is missing | No entry in `TOOLS` | Compare the registry with the filename; disk presence alone is insufficient. |
| Selecting another module does nothing | Current page thinks a run is active | Inspect current state before reloading or stopping it. |
| Form changes disappear | Selection rebuilt the form | Only the three global values are persisted by this frontend. |
| Global setting does not update a field | Input was edited locally, or CF sync limitation | Compare the rendered form value with the top bar. |
| Extra fields remain after a mode change | Visibility handler is unimplemented | Treat visibility as unrelated to whether the backend consumes a value. |
| `done` appears alongside a traceback | Completion label does not report success | Read the traceback; do not use the label as a result check. |
| Status says `idle` during work | Clear reset the label | Clearing text does not stop the child. |
| CLI prompt followed by EOF error | Fixed input sequence does not match prompts | Record the mismatch for maintenance; the output area cannot accept answers. |
| No output for a while | Prompt buffering or waiting | Inspect local terminal evidence; quiet output is not proof of a hang. |
| A relative file appears missing | Looking in the wrong folder | Resolve it relative to `FROMUSB\cli`. |
| Output vanished | Clear, selection, new run, or reload | There is no general persistent console history to restore. |
| Saved values reappear | Browser local storage restored them | Remove `mp_global` for the GUI origin and reload. |
| Controls fail after loading | JavaScript error; possibly malformed stored JSON | Inspect the console and clear the saved key if its JSON is invalid. |
| A brief GET/405 is visible in network logs | Frontend creates and closes an EventSource before POST streaming | Distinguish this implementation artifact from the actual POST result. |

To inspect the listener on the local port without changing anything:

```powershell
Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, OwningProcess
```

Use the returned process ID to inspect the owner in Task Manager. This check identifies a listener, not whether that listener is the intended application.

## 13. Implementation limitations

The following details materially affect how the UI should be interpreted:

1. **No GUI authentication.** The reviewed Flask routes have no application login or authorization layer. Preserve the current loopback-only binding; this is not a prepared multi-user service.
2. **No universal preview or rollback.** RUN launches the underlying program, and KILL cannot undo completed operations.
3. **Automatic prompt answers.** Backend input builders contain fixed answers, including confirmations. There may be no extra dialog before a write.
4. **No exit-code reporting in the main stream.** The completion marker does not encode the child return code.
5. **Fixed input sequences.** CLI prompt changes can invalidate the wrapper even when the page still looks correct.
6. **No true dependent-field filtering.** All fields after the mode selector are currently displayed.
7. **Uneven field wiring.** Some backend branches expect values not exposed by the form, while some visible fields are unused in particular branches. Do not assume UI/CLI parity.
8. **Browser-only single-run protection.** It does not prevent other tabs or clients from starting jobs.
9. **Process tracking is keyed by module.** Duplicate launches of the same module can interfere with tracking and cleanup.
10. **Global values are browser-persisted secrets.** Password masking is only visual.
11. **Shell state is server-global.** It is not scoped to a browser session or user.
12. **Shell connection acknowledgment is not verification.** The connect handler stores supplied settings and returns a success-shaped response without testing the remote endpoint.
13. **Closing the shell UI is not server cleanup.** It hides elements and clears visible text only.
14. **No structured job history.** A page reload cannot reconstruct a prior run from a durable job database.
15. **Incomplete error presentation.** Some stream errors only change the status; a backend failure may need diagnosis in the PowerShell terminal.

## 14. Maintenance and verification

### Source map

| Concern | Source location |
|---|---|
| Module names, descriptions, defaults | `gui.py` → `TOOLS` |
| CLI-input translation | `gui.py` → `build_stdin()` |
| Child creation and output streaming | `gui.py` → `run_tool()` |
| Child termination request | `gui.py` → `kill_tool()` |
| Local bind address and port | Bottom of `gui.py` |
| Global-field synchronization | `index.html` → `syncGlobal()` |
| Module switching | `index.html` → `selectTool()` |
| Form generation | `index.html` → `buildForm()` / `buildDependentFields()` |
| Mode-field visibility | `index.html` → `updateDependentVisibility()` |
| Output and status | `index.html` → `appendLine()` / `setRunning()` / `clearOutput()` |
| Saved settings | `index.html` → `mp_global` local-storage code |

### Priorities for safer maintenance

Useful UI and lifecycle improvements include explicit success/failure states, removal of credential persistence by default, unique job IDs, reliable process cleanup, complete field validation, and clear labeling of state-changing controls. These are observations and suggestions; no application code was changed to implement them during this documentation task.

UI rendering and process-management behavior can be validated separately from the target-facing tools using a harmless local fixture. Such a fixture can print progress, exit with a known return code, or wait until terminated. It should not import the actual CLI scripts, since some contain top-level execution.

### Verification limits of this document

The guide was written from `gui.py`, `templates\index.html`, the directory inventory, and selected supporting source inspection. Package imports in CLI files and their file-writing patterns were inspected for context. Existing credential datasets were not needed for the guide and were not opened.

No GUI server or attack module was launched as part of preparing this guide. No claim here should be read as confirmation that a particular exploit works, that a remote endpoint is reachable, or that a write operation can be safely reversed.

## 15. Quick reference

| Task | Reference |
|---|---|
| Start the local UI | Launch `gui.py` using the existing Python environment. |
| Open the home page | `http://127.0.0.1:5000` |
| Open local docs | Click `? DOCS`. |
| Inspect a module form | Select its sidebar item without clicking RUN. |
| Clear visible output | Small `✕` button; this does not stop work. |
| Request stop | KILL; then verify actual process state. |
| Stop Flask | `Ctrl+C` in its PowerShell window. |
| Understand `done` | Stream/UI completion, not confirmed success. |
| Locate relative child files | Start from `FROMUSB\cli`. |
| Clear saved globals | Remove local-storage key `mp_global` for the local GUI origin. |
| Reset server memory | Stop and restart `gui.py`. |
| Diagnose a UI failure | Check browser console plus the PowerShell terminal. |
