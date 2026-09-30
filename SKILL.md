# Cyber-Clops GUI UI/UX Master Design Specification

## Document Status

```text
Project: Cyber-Clops Cyber Kit v2
Document: GUI UI/UX Master Design Specification
Target: Native Desktop Security Workstation
UI Framework: Dear ImGui + SDL3 + OpenGL3
Primary Language: C++
UI Language: English only
Design Status: Implementation Blueprint
Priority: High
```

---

# 1. PURPOSE

This document defines the complete UI/UX system for the Cyber-Clops desktop application.

This is not a visual suggestion document.

This document is an implementation specification.

The coding agent must treat every section as a design and engineering requirement unless a repository constraint makes a requirement technically impossible.

The objective is to transform the existing Cyber-Clops GUI from a functional Dear ImGui shell into a coherent, professional, production-quality security workstation.

The final application must look and behave like software built specifically for security engineering.

It must not look like:

```text
A generic ImGui sample
A web dashboard copied into desktop
A gaming interface
A cyberpunk wallpaper with buttons
A futuristic movie hacking screen
A collection of unrelated cards
An AI-generated SaaS dashboard
```

The final interface should feel like:

```text
Professional Security Workstation
+
Network Analysis Console
+
Security Research Environment
+
Developer IDE
+
Evidence Investigation Workspace
```

The application must prioritize operational clarity over visual decoration.

---

# 2. CORE DESIGN PHILOSOPHY

Cyber-Clops is a security tool platform.

It is not a marketing application.

Therefore the interface must communicate:

```text
Precision
Control
Context
Trust
Density
Performance
Traceability
Safety
```

The design should make the user understand the system state immediately.

At any moment the user should be able to answer:

```text
What project am I working on?
What targets are currently in scope?
What tool is active?
What is currently running?
What backend is being used?
What results were found?
What result is selected?
Why was an action blocked?
Where did this result come from?
What can I do with this result next?
```

The UI must never force the user to infer important security state from color alone.

---

# 3. NON-NEGOTIABLE DESIGN RULES

## 3.1 No AI Slop

Do not implement:

```text
Purple-blue gradients
Heavy glassmorphism
Neon borders
Neon green glow everywhere
Glowing text
Animated grid backgrounds
Artificial scanline effects
Random terminal decorations
Huge rounded cards
Excessive pill-shaped controls
Oversized dashboard statistics
Fake hacker animations
ASCII art as decoration
Emoji as UI icons
Random futuristic labels
Unnecessary particle effects
Unnecessary blur
Decorative circuitry
Fake system logs
Fake performance numbers
Fake GPU information
```

Do not add visual effects merely because they look "cyber".

The interface must remain useful and credible when:

```text
50,000 rows are visible
5 jobs are running
logs are streaming
a scan is producing results
the user is filtering data
the user is investigating a finding
```

A professional security application should become calmer and more informative as activity increases.

It must never become visually chaotic.

---

# 4. REPOSITORY INTEGRATION RULE

Do not redesign the UI by inventing a new application architecture.

Preserve the existing Cyber-Clops engine architecture.

The existing repository already defines:

```text
25 security tools
6 tool groups
Rust core
Native C/C++ components
Go workers
Lua scripts
Dear ImGui GUI
SDL3
OpenGL3
Command palette
Live jobs
Scope guard
Safe Mode
Audit log
Acceleration detection
```

The redesign must operate as a UI layer over the existing engine and state system.

Do not move scanning logic into GUI rendering code.

Do not duplicate security logic in UI components.

Do not create fake local implementations when a real engine already exists.

Do not replace the current job execution architecture merely to produce a visual effect.

The GUI should consume application state.

---

# 5. PRIMARY DESIGN DIRECTION

The visual direction is:

```text
Dark industrial workstation
Minimal accent color
High information density
Sharp hierarchy
Subtle borders
Compact controls
Structured tables
Technical typography
Clear state indicators
Keyboard-first interaction
```

The application should feel visually mature without trying to appear expensive.

Avoid decorative UI.

Every visible component must justify its presence.

---

# 6. APPLICATION WINDOW

Default window:

```text
Width: 1400 px
Height: 900 px
```

Recommended minimum:

```text
Width: 1100 px
Height: 700 px
```

Fullscreen must work correctly.

The layout must be responsive inside the available desktop viewport.

Do not hardcode panel positions based exclusively on a 1400x900 canvas.

Docking should determine final positioning.

---

# 7. GLOBAL LAYOUT

Default workspace:

```text
+--------------------------------------------------------------------------------+
| TOPBAR                                                                         |
+----------------------+--------------------------------------+------------------+
|                      |                                      |                  |
|                      |                                      |                  |
|                      |                                      |                  |
|    NAVIGATOR         |            WORKSPACE                  |   INSPECTOR      |
|                      |                                      |                  |
|                      |                                      |                  |
|                      |                                      |                  |
+----------------------+--------------------------------------+------------------+
|                            JOB DRAWER                                          |
+--------------------------------------------------------------------------------+
```

Default dimensions:

```text
Topbar: 44 px
Navigator: 250-280 px
Inspector: 300-340 px
Job drawer: 200-240 px
Workspace: remaining space
```

The workspace must remain the dominant area.

Do not let the navigator or inspector visually overpower the center.

---

# 8. PANEL PRIORITY

Visual hierarchy:

```text
1. Workspace content
2. Tool controls
3. Results
4. Operational state
5. Inspector
6. Navigation
7. Logs and audit
```

Do not visually emphasize navigation more than the active work.

The user is here to perform security operations, not browse menus.

---

# 9. COLOR SYSTEM

Use a controlled dark palette.

## 9.1 Background Tokens

```text
BG_0 = #0B0E11
BG_1 = #101419
BG_2 = #151A20
BG_3 = #1B2128
BG_4 = #20272F
```

Use:

```text
BG_0
```

for the application foundation.

Use:

```text
BG_1
```

for primary panes.

Use:

```text
BG_2
```

for elevated controls and selected areas.

Use:

```text
BG_3
```

for secondary containers.

Use:

```text
BG_4
```

sparingly for active or highlighted areas.

---

# 10. BORDER SYSTEM

Borders must be subtle.

```text
LINE_0 = #242B33
LINE_1 = #303943
LINE_ACTIVE = #3D4852
```

Use thin borders.

Preferred:

```text
1 px
```

Avoid:

```text
2-4 px decorative borders
```

Do not outline every component aggressively.

Borders should establish structure, not create visual noise.

---

# 11. TEXT COLORS

```text
TEXT_PRIMARY   = #E7ECF1
TEXT_SECONDARY = #A8B1BB
TEXT_MUTED     = #6D7782
TEXT_DISABLED  = #4F5861
```

Text hierarchy must be obvious without requiring large fonts.

---

# 12. ACCENT COLORS

Primary:

```text
PRIMARY = #3BA55D
```

Information:

```text
INFO = #4EA1FF
```

Success:

```text
SUCCESS = #3FB950
```

Warning:

```text
WARNING = #D29922
```

Danger:

```text
DANGER = #E5534B
```

Critical:

```text
CRITICAL = #F85149
```

These colors are semantic.

Do not use them as decoration.

Green does not mean "make the interface cyber".

Green means:

```text
Primary action
Successful operation
Valid state
Active safe operation
```

---

# 13. COLOR USAGE RULE

Never communicate important security state through color alone.

Incorrect:

```text
green dot = safe
red dot = dangerous
```

Correct:

```text
Safe Mode: ON
Scope: lab-only
Status: Running
Severity: High
```

Use both:

```text
Text
+
Subtle color
```

---

# 14. TYPOGRAPHY

Use two font families.

## 14.1 UI Font

Preferred:

```text
Inter
```

Use for:

```text
Navigation
Buttons
Headers
Labels
Descriptions
Settings
Dialogs
```

Recommended sizes:

```text
11 px  Captions
12 px  Secondary information
13 px  Default application UI
14 px  Section headings
16 px  Tool heading
20 px  Application title only
```

Do not make every heading large.

---

# 15. TECHNICAL FONT

Preferred:

```text
JetBrains Mono
```

Use for:

```text
IP addresses
Domains
URLs
Ports
Hashes
HTTP requests
HTTP responses
Headers
JSON
YAML
File paths
Logs
Hex data
Packet information
Timing
Throughput
Job identifiers
Command output
```

Recommended:

```text
12 px
```

Technical data must be visually distinct from normal application copy.

---

# 16. SPACING SYSTEM

Use an 8 px spacing system.

```text
4 px   micro
8 px   compact
12 px  standard
16 px  section padding
24 px  major separation
32 px  large separation
```

Default panel padding:

```text
12-16 px
```

Default control gap:

```text
8 px
```

Default vertical section gap:

```text
16 px
```

Avoid arbitrary values unless required by ImGui layout behavior.

---

# 17. CORNER RADIUS

Use restrained rounding.

```text
Window:    6 px
Panel:     6 px
Popup:     6 px
Input:     4 px
Button:    4 px
Badge:     4 px
```

Do not use giant rounded containers.

Cyber-Clops should look engineered rather than soft.

---

# 18. SHADOWS

Use minimal or no shadows.

Dear ImGui does not need heavy card shadows.

Separation should primarily come from:

```text
Background levels
Borders
Spacing
Typography
```

Do not create fake depth using multiple shadows.

---

# 19. ICONOGRAPHY

Icons:

```text
16 px
Monochrome
Consistent visual weight
Simple line or filled technical icons
```

Never use emoji.

Required conceptual icons:

```text
Search
Settings
Play
Stop
Pause
Resume
Refresh
Filter
Export
Copy
Chevron
Lock
Shield
Warning
Information
Network
Terminal
Folder
Target
Clock
CPU
GPU
```

If an icon library is already present, reuse it consistently.

Do not introduce multiple icon families.

---

# 20. MAIN TOPBAR

Height:

```text
44 px
```

Structure:

```text
[Brand]
[Project]
[Scope]
[Safe Mode]
[Acceleration]
[Jobs]
[Search]
[Settings]
```

Example:

```text
CYBER-CLOPS
Project: demo.clops
Scope: lab-only
Safe Mode: ON
CPU: AVX2 + ISPC
GPU: None
Jobs: 2
Ctrl+K
Settings
```

The topbar must remain visible at all times.

---

# 21. BRAND

Brand treatment:

```text
CYBER-CLOPS
```

Use small uppercase or compact title case.

Do not use a giant logo.

Suggested:

```text
[CL] CYBER-CLOPS
```

The brand mark must remain simple.

Do not create animated branding.

---

# 22. PROJECT SELECTOR

Display:

```text
Project: demo.clops
```

Clicking the selector opens a compact menu:

```text
Recent Projects

demo.clops
internal-audit
research-lab

----------------

New Project
Open Project
Project Settings
```

The project selector must not occupy excessive topbar width.

---

# 23. SCOPE INDICATOR

Scope is a first-class security element.

Always visible.

Example:

```text
Scope: lab-only
```

Possible states:

```text
Scope: lab-only
Scope: project
Scope: restricted
Scope: review
```

Never show only:

```text
green shield
```

Instead:

```text
[shield] Scope: lab-only
```

---

# 24. SAFE MODE INDICATOR

Safe Mode must always be visible.

Display:

```text
Safe Mode: ON
```

Safe Mode is not a theme.

It is application state.

The UI must never allow the user to hide important safety state to make the interface look cleaner.

---

# 25. ACCELERATION STATUS

The topbar must display real acceleration information.

Example:

```text
CPU: AVX2 + ISPC
GPU: None
```

Possible:

```text
CPU: AVX512 + ISPC
GPU: CUDA 12.4
```

Possible fallback:

```text
GPU: None
Backend: CPU fallback
```

Do not invent hardware values.

Do not display:

```text
GPU Optimized
```

unless the backend really exists.

The current repository explicitly requires honest backend reporting.

---

# 26. JOB INDICATOR

Display:

```text
Jobs: 2
```

When clicked:

```text
Jobs Drawer
```

Optional secondary text:

```text
2 Running
```

Do not use animated CPU-style meters.

---

# 27. NAVIGATOR

Default width:

```text
260 px
```

The navigator is not a generic sidebar.

It is a security investigation tree.

Recommended hierarchy:

```text
PROJECT

Targets
Subdomains
Ports
Services
Findings
Evidence
Reports

RECON

T01 Subdomain Enumerator
T02 DNS Toolkit
T03 Port Scanner
T04 SSL/TLS Analyzer
T05 HTTP Fingerprint
T06 Cloud + Takeover

WEB

T07 Directory Bruteforcer
T08 Web Spider
T09 Endpoint + Secrets
T10 SQLi Detector
T11 XSS Scanner
T12 LFI + SSTI Tester
T13 Misconfig Checker
T14 Repeater

NETWORK

T15 Intercept Proxy
T16 Packet Sniffer
T17 CVE Mapper
T18 Payload Generator

CRACK

T19 Codec Lab
T20 Hash Cracker
T21 Wordlist Studio

INTEL

T22 OSINT Toolkit
T23 Chain Builder
T24 AI Auto Hacker

REPORT

T25 Report Center
```

These tool identities match the current repository definitions.

---

# 28. NAVIGATOR GROUP HEADERS

Group headers:

```text
RECON
WEB
NETWORK
CRACK
INTEL
REPORT
```

Use:

```text
11 px
Semi-bold
Muted text
Uppercase
```

Do not make group headers bright.

They are organizational elements.

---

# 29. TOOL ROW

Standard row:

```text
T03  Port Scanner
```

Optional compact description appears only in tooltip.

Selected:

```text
T03  Port Scanner
^^^^
subtle primary accent
```

Do not make the entire row bright green.

The active indicator should be restrained.

---

# 30. TOOL SEARCH

At the top of the navigator:

```text
[ Search tools... ]
```

Search must match:

```text
Tool ID
Tool name
Group
Description
Keywords
```

Example:

```text
port
```

returns:

```text
T03 Port Scanner
T16 Packet Sniffer
T17 CVE Mapper
```

Use fuzzy search.

Do not open a new window for tool search.

---

# 31. WORKSPACE

The workspace is the main operating area.

Every tool must use the same visual pattern.

```text
TOOL HEADER
TOOL CONTROLS
LIVE METRICS
RESULT AREA
```

The workspace must not have a different visual language for every tool.

---

# 32. TOOL HEADER

Structure:

```text
T03

Port Scanner

Fast TCP scan with banner and version detection.

[SAFE]
Docs
```

Do not exceed two lines for the description.

Suggested structure:

```text
[T03] Port Scanner
Fast TCP scan with banner and version detection.
```

Badge:

```text
SAFE
REVIEW
LAB ONLY
```

Use semantic badges only.

---

# 33. TOOL HEADER HEIGHT

Target:

```text
72-88 px
```

Do not create a large hero section.

Cyber-Clops is an operational application.

The user needs access to controls immediately.

---

# 34. CONTROL AREA

Example:

```text
Target
[ 127.0.0.1 ]

Profile
[ Lab ]

Ports
[ 80,443 ]

Concurrency
[ 500 ]

Timeout
[ 2000 ]

Rate
[ 50 rps ]

[ Run ]
[ Stop ]
```

The controls should remain compact.

Use labels.

Do not rely exclusively on placeholder text.

---

# 35. CONTROL LAYOUT

Desktop:

```text
Label + Input + Label + Input + Actions
```

Example:

```text
Target [127.0.0.1]   Profile [Lab]   Ports [80,443]   [Run] [Stop]
```

If the width is insufficient:

```text
Target [127.0.0.1]
Profile [Lab]
Ports   [80,443]
Concurrency [500]
[Run] [Stop]
```

Do not allow controls to overlap.

---

# 36. PRIMARY BUTTON

Primary execution button:

```text
[ Run ]
```

Use primary green.

When active:

```text
[ Stop ]
```

Stop should use danger semantic styling.

Do not create a giant full-width Run button.

---

# 37. BUTTON HIERARCHY

Primary:

```text
Run
Approve
Apply
Save
```

Secondary:

```text
Export
Filter
Refresh
Copy
Docs
```

Danger:

```text
Stop
Delete
Reject
```

Text-only:

```text
Details
Evidence
Reset
Open
```

---

# 38. LIVE METRICS STRIP

Do not use six giant cards.

Use one compact horizontal strip.

Example:

```text
Elapsed 00:42 | Rate 812 rps | Found 37 | Errors 4 | Queue 963 | Backend ISPC
```

For T20:

```text
Elapsed 00:42 | H/s 1.24M | Tested 14.2M | Progress 15.4% | ETA 00:47 | CUDA
```

The metric strip should consume minimal vertical space.

---

# 39. METRIC TYPOGRAPHY

Metric label:

```text
11-12 px muted
```

Metric value:

```text
12-13 px technical font
```

Example:

```text
Rate
812 rps
```

Do not use:

```text
72 px
812
requests/sec
```

inside a huge dashboard card.

---

# 40. PROGRESS DISPLAY

Use compact progress.

```text
[==================------] 76%
```

Text:

```text
76%
```

Optional:

```text
76% | ETA 00:21
```

Progress bars must not glow.

---

# 41. RESULT TABLE

Tables are the primary data visualization method.

Default density:

```text
Header: 32 px
Row: 28 px
```

Compact mode:

```text
Row: 24 px
```

Comfortable:

```text
Row: 34 px
```

The user can change table density from Appearance settings.

---

# 42. TABLE DESIGN

Header:

```text
Port | State | Service | Version | Latency
```

Use subtle background distinction.

Do not use strong header gradients.

Rows:

```text
normal
hover
selected
```

must each have visually distinct states.

---

# 43. TABLE EXAMPLE

```text
Port   Proto   State   Service   Version       Banner            Latency
-----  ------  ------  --------  ------------  ----------------  -------
22     TCP     Open    SSH       OpenSSH 9.2   SSH-2.0-...       3 ms
80     TCP     Open    HTTP      nginx 1.24    nginx/1.24        5 ms
443    TCP     Open    HTTPS     nginx 1.24    TLS               8 ms
```

Numeric values must be right-aligned.

Technical identifiers should use monospace.

---

# 44. TABLE FEATURES

Every serious result table must support:

```text
Sorting
Filtering
Column resizing
Column visibility
Row selection
Multi-selection
Copy
Export
Context menu
Inspector integration
```

Use virtualized rendering for large datasets.

Do not instantiate all UI rows simultaneously.

---

# 45. TABLE SEARCH

Place a compact search control above the table:

```text
[ Search results... ]
```

Optional filter control:

```text
[ Filter ]
```

Do not move search into a modal.

---

# 46. TABLE CONTEXT MENU

For generic result:

```text
Inspect
Copy
Copy as JSON
Export Selected

----------------

Send to Repeater
Send to CVE Mapper
Send to TLS Analyzer

----------------

Mark False Positive
```

Only display actions relevant to the selected entity.

Do not show every possible action on every row.

---

# 47. INSPECTOR

Default width:

```text
320 px
```

Title:

```text
Details
```

The inspector must be context sensitive.

Example:

```text
DETAILS

Port
443

State
Open

Protocol
TCP

Service
HTTPS

Version
nginx 1.24

Latency
8 ms
```

Then:

```text
EVIDENCE

Banner
HTTP/1.1 200 OK
Server: nginx/1.24
```

Then:

```text
ACTIONS

[ Send to TLS Analyzer ]
[ Send to HTTP Fingerprint ]
[ Send to CVE Mapper ]
```

---

# 48. INSPECTOR SECTIONS

Use collapsible sections:

```text
Overview
Metadata
Evidence
Relationships
Actions
```

Different entities expose different sections.

For vulnerabilities:

```text
Finding
Severity
Confidence
CWE
CVSS
Target
Parameter
Evidence
Request
Response
Remediation
Related Jobs
```

---

# 49. INSPECTOR EMPTY STATE

Never leave a blank panel.

Use:

```text
No selection

Select a result row to inspect
details, evidence, and related actions.
```

Center vertically only enough to make the state readable.

Do not use illustrations.

---

# 50. BOTTOM JOB DRAWER

Height:

```text
220 px
```

Tabs:

```text
Jobs
Logs
Audit
Output
```

This panel acts as the operational control center.

---

# 51. JOBS TAB

Example:

```text
ID     Tool     Target       Status     Progress   Started
#014   T03      127.0.0.1    Running    62%        19:22
#013   T04      127.0.0.1    Done       100%       19:18
#012   T07      lab.local    Paused     41%        19:11
```

Supported states:

```text
Queued
Running
Paused
Cancelled
Done
Failed
```

These states are part of the existing Cyber-Clops UI requirements.

---

# 52. JOB SELECTION

Selecting a job should:

```text
Focus the associated tool
Reveal its latest output
Update the inspector
Scroll logs to relevant events
```

Do not open another application window.

---

# 53. LOG TAB

Logs should use technical typography.

Example:

```text
19:22:10  INFO   Job #014 started
19:22:10  INFO   Scope validation passed
19:22:11  INFO   Backend selected: ISPC
19:22:12  INFO   Port 22 open
19:22:12  INFO   Port 80 open
19:22:14  WARN   Rate limited by server
19:22:15  INFO   Backoff 500 ms
```

Structure:

```text
Timestamp
Level
Job
Message
```

Do not fabricate log entries.

---

# 54. AUDIT TAB

Audit is different from logs.

Logs explain runtime behavior.

Audit records security-relevant events.

Example:

```text
Timestamp   Job    Tool   Event
19:22:10    #014   T03    Scope accepted
19:22:10    #014   T03    Scan started
19:22:11    #014   T03    Target validated
19:22:14    #014   T03    Rate limit triggered
19:22:20    #014   T03    Scan completed
```

The audit log must remain available and cannot be disabled from the UI.

Scope and audit requirements are part of the existing project architecture.

---

# 55. OUTPUT TAB

Output is raw tool output.

Use:

```text
JetBrains Mono
12 px
```

Support:

```text
Copy
Save
Clear View
Search
Wrap Lines
```

Do not modify raw output merely for aesthetics.

---

# 56. COMMAND PALETTE

Shortcut:

```text
Ctrl+K
```

The command palette must feel like an IDE command system.

Preferred size:

```text
720 x 520
```

Position:

```text
Centered horizontally
Upper-center vertically
```

Structure:

```text
+----------------------------------------------------------+
| Search commands...                                       |
+----------------------------------------------------------+
| Navigation                                               |
|   Open Port Scanner                           Ctrl+3    |
|   Open DNS Toolkit                                       |
|                                                          |
| Actions                                                  |
|   Run Active Tool                            Ctrl+Enter  |
|   Stop Running Jobs                          Ctrl+.     |
|                                                          |
| Recent                                                   |
|   T03 Port Scanner                                       |
|   T04 SSL/TLS Analyzer                                   |
+----------------------------------------------------------+
```

Do not create a standard draggable ImGui window as the final palette.

---

# 57. COMMAND PALETTE SEARCH

Input:

```text
Search commands...
```

Fuzzy matching.

Ranking:

```text
Exact name
Prefix
Tool ID
Recent usage
Keyword
Description
```

Navigation:

```text
Arrow Up
Arrow Down
Enter
Esc
```

Do not require a mouse.

---

# 58. COMMAND PALETTE COMMANDS

Minimum:

```text
Open Tool
Run Active Tool
Stop Running Jobs
Pause Job
Resume Job
Cancel Job
Search Workspace
Search Tools
Open Settings
Save Project
Open Project
Export Results
Toggle Inspector
Toggle Jobs
Reset Layout
```

---

# 59. GLOBAL SEARCH

Global search should cover the project.

Search:

```text
Targets
Subdomains
Ports
Services
Findings
Evidence
Jobs
Reports
Logs
Tools
```

Example:

```text
Search: 443

Ports
    443 HTTPS

Services
    nginx 1.24

Findings
    TLS configuration

Jobs
    #014 Port Scanner
```

---

# 60. PROJECT DATA MODEL IN UI

The UI should make relationships visible.

Conceptual relationship:

```text
Target
  |
  +-- Subdomains
  +-- IPs
  +-- Ports
  +-- Services
  +-- TLS
  +-- Findings
  +-- Evidence
  +-- Jobs
  +-- Reports
```

The user should be able to move between related entities without retyping information.

---

# 61. RECON WORKSPACE

Recon should feel like an investigation workspace.

Recommended layout:

```text
+----------------------+-------------------------------------+
| Recon                | Target Overview                     |
|                      |                                     |
| Subdomains           | Target: example.local               |
| DNS                  |                                     |
| Ports                | Subdomains                          |
| Services             | [table]                             |
| TLS                  |                                     |
| Fingerprint          | Ports                               |
| Cloud                | [table]                             |
+----------------------+-------------------------------------+
```

Do not turn recon into a graph-only interface.

Tables remain primary.

Relationships can be displayed as secondary navigation.

---

# 62. T01 SUBDOMAIN ENUMERATOR

Input:

```text
Domain
[ example.com ]
```

Controls:

```text
Source mode
Passive sources
Wildcard filtering
```

Result table:

```text
Subdomain
Source
IP
Status
First Seen
Last Seen
```

Inspector:

```text
Subdomain
DNS
Sources
Related IPs
Related Jobs
```

---

# 63. T02 DNS TOOLKIT

Controls:

```text
Host
Record Types
Resolver
DoH Fallback
AXFR Check
```

Results:

```text
Record
Type
Value
TTL
Resolver
```

Do not mix A, MX, TXT, CAA and NS records into unreadable single strings.

Use structured rows.

---

# 64. T03 PORT SCANNER

T03 is the reference design for all scanner-style tools.

Header:

```text
T03 Port Scanner

Fast TCP scan with banner and version detection.
```

Controls:

```text
Target
Profile
Ports
Concurrency
Timeout
Rate
```

Metrics:

```text
Elapsed
Rate
Open
Closed
Errors
Queue
Backend
```

Result columns:

```text
Port
Proto
State
Service
Version
Banner
Latency
```

The project specification already defines these data concepts and live row behavior.

---

# 65. T04 SSL/TLS ANALYZER

Layout:

```text
Target
Port

Certificate Summary
Protocol Support
Cipher Suites
Security Checks
Evidence
```

Certificate section:

```text
Subject
Issuer
Serial
SAN
Key Size
Signature
Expiry
Days Remaining
```

Protocol section:

```text
TLS 1.0
TLS 1.1
TLS 1.2
TLS 1.3
```

Do not display grade information without exposing why the grade exists.

Grade:

```text
Grade: B

Deductions
TLS 1.1 enabled
Weak cipher accepted
Missing HSTS
```

The existing tool specification requires transparent deductions.

---

# 66. T05 HTTP FINGERPRINT

Main result:

```text
Check
Value
Severity
Advice
```

Sections:

```text
Server
Technology
WAF
Headers
Cookies
Security Headers
Raw Headers
```

Raw response must be available in the inspector.

---

# 67. T06 CLOUD + TAKEOVER

Never present a speculative takeover as confirmed.

Use language:

```text
Possible takeover signal
```

not:

```text
Vulnerable
Takeover confirmed
```

unless actual engine evidence supports such a conclusion.

The UI must preserve the tool's semantic distinction.

---

# 68. T07 DIRECTORY BRUTEFORCER

Controls:

```text
Target
Wordlist
Concurrency
Rate
Status Filter
404 Filter
Resume
```

Results:

```text
Path
Status
Length
Words
Lines
Latency
```

Live progress:

```text
Tested
Found
Filtered
Rate
Queue
Checkpoint
```

Use compact metrics.

---

# 69. T08 WEB SPIDER

Result table:

```text
URL
Depth
Status
Content Type
Size
Parent
```

Inspector:

```text
URL
Headers
Forms
Links
Cookies
Robots
Sitemap
```

Use relationship actions:

```text
Send to Repeater
Open in Browser
Add to Target Set
```

---

# 70. T09 ENDPOINT + SECRETS

Separate findings into tabs:

```text
Endpoints
Potential Secrets
Sources
```

Do not visually merge secret findings with harmless endpoints.

Potential secret records should include:

```text
Pattern
Location
Source
Confidence
Redaction State
```

Sensitive values should be redacted by default.

---

# 71. T10 SQLi DETECTOR

Use clear execution state.

```text
Safe checks
Boolean checks
Time checks
```

If approval is required:

```text
Approval required.

Review step and press Approve to continue.
```

Do not hide approval behind generic error messages.

---

# 72. T11 XSS SCANNER

Result fields:

```text
Parameter
Payload Class
Reflection
Context
Encoding
Confidence
```

Evidence should show enough context for investigation without overwhelming the workspace.

---

# 73. T12 LFI + SSTI TESTER

Split findings by class:

```text
Traversal
Template Expression
```

Do not visually imply remote code execution.

Use exact semantics from actual engine results.

---

# 74. T13 MISCONFIG CHECKER

Table:

```text
Check
Status
Severity
Observed
Advice
```

Examples:

```text
CSP
HSTS
CORS
X-Frame-Options
Cookies
Directory Listing
Git Exposure
```

Selecting a row opens evidence.

---

# 75. T14 REPEATER

T14 should use a request/response editor.

```text
+--------------------------------+--------------------------------+
| REQUEST                        | RESPONSE                       |
|                                |                                |
| GET /api/user?id=1             | HTTP/1.1 200 OK                |
| Host: example.com              | Server: nginx                  |
| User-Agent: ...                | Content-Type: ...              |
|                                |                                |
| [Send]                         | Body                           |
+--------------------------------+--------------------------------+
| History                                                        |
+----------------------------------------------------------------+
```

Request and response editors must use monospace.

The user must be able to:

```text
Edit
Send
Resend
Compare
Copy
Save
```

---

# 76. T15 INTERCEPT PROXY

Tabs:

```text
Intercept
History
Scope
Settings
```

History table:

```text
Method
Host
Path
Status
Length
Time
```

Context actions:

```text
Forward
Drop
Edit
Send to Repeater
Copy as cURL
```

Do not make the proxy interface look like a generic HTTP client.

It should feel like part of the same investigation workspace.

---

# 77. T16 PACKET SNIFFER

Main layout:

```text
Packet List
Packet Details
Raw Bytes
```

Packet table:

```text
No.
Time
Source
Destination
Protocol
Length
Info
```

Packet details:

```text
Ethernet
IPv4 / IPv6
TCP / UDP
DNS
Payload
```

Hex view:

```text
00000000  48 54 54 50 2F 31 2E 31  HTTP/1.1
00000010  20 32 30 30 20 4F 4B     200 OK
```

Use synchronized selection.

---

# 78. T17 CVE MAPPER

Input:

```text
Service
Version
```

Result:

```text
CVE
Severity
Product
Version
Confidence
Reference
```

Do not turn CVE results into huge alert cards.

Use structured rows.

---

# 79. T18 PAYLOAD GENERATOR

Separate:

```text
LHOST
LPORT
Variant
Encoding
```

Output:

```text
Generated Payload
```

Use code editor style.

The interface should make scope and lab context visible when relevant.

---

# 80. T19 CODEC LAB

Layout:

```text
Operation
Input
Output
```

Operations:

```text
Base64 Encode
Base64 Decode
Hex Encode
Hex Decode
URL Encode
URL Decode
HTML Encode
HTML Decode
JWT Inspect
UUID Inspect
```

Bulk operations should use a structured file workflow rather than adding unnecessary visual complexity.

---

# 81. T20 HASH CRACKER

The design must prioritize throughput visibility.

Top control area:

```text
Algorithm
Hash
Mode
Wordlist
Mask
Rules
Backend
Threads
```

Metrics:

```text
H/s
Tested
Total
Progress
ETA
Backend
```

Example:

```text
H/s        1.24M
Tested     14.2M
Total      92.0M
Progress   15.4%
ETA        00:47
Backend    CUDA
```

When GPU is not available:

```text
GPU not found. Using CPU fallback.
```

Do not display misleading GPU performance.

---

# 82. T21 WORDLIST STUDIO

Structure:

```text
Input
Transform
Preview
Output
```

Transform controls:

```text
Deduplicate
Sort
Regex Filter
Length Filter
Mutate
Combine
Lua Transform
```

Statistics:

```text
Input Count
Unique Count
Generated Count
Average Length
Charset
```

Do not use large visual cards.

---

# 83. T22 OSINT TOOLKIT

Main navigation:

```text
Username
Domain
DNS
Wayback
Dorks
Local Match
```

Results must be source-oriented.

Table:

```text
Source
Query
Result
Confidence
Timestamp
```

Do not present uncertain OSINT matches as confirmed identity.

---

# 84. T23 CHAIN BUILDER

Chain Builder is an exception to the normal table-heavy layout.

Use a controlled node workspace.

```text
+------------------------------------------------------------------+
| New Node | Connect | Delete | Validate | Dry Run | Execute       |
+------------------------------------------------------------------+
|                                                                  |
|  [T01]                                                          |
|  Subdomain Enumerator                                            |
|        |                                                         |
|        v                                                         |
|  [T03]                                                          |
|  Port Scanner                                                    |
|        |                                                         |
|        v                                                         |
|  [T04]                                                          |
|  SSL/TLS Analyzer                                                |
|                                                                  |
+------------------------------------------------------------------+
| Variables | Validation | Execution Plan                          |
+------------------------------------------------------------------+
```

Node styling must be restrained.

Do not make nodes neon.

Do not make the canvas resemble a game engine.

---

# 85. CHAIN NODE DESIGN

Each node:

```text
T03
Port Scanner
Status: Ready
```

Selected node:

```text
T03
Port Scanner

Inputs
Target
Profile
Ports

Outputs
Ports
Services

[Inspect]
```

The node should communicate function first.

---

# 86. T24 AI AUTO HACKER

T24 must visually communicate planning and approval.

The interface should never suggest that the AI bypasses normal execution controls.

Structure:

```text
Goal
Plan
Execution Status
Approval Queue
Evidence
Replay
```

Example:

```text
GOAL

Recon and vulnerability mapping
for the current project scope.
```

Plan:

```text
01  T01 Subdomain Enumerator
    Approved

02  T03 Port Scanner
    Approved

03  T10 SQLi Detector
    Approval required

04  T13 Misconfig Checker
    Approved
```

Approval panel:

```text
Approval required.

Tool
T10 SQLi Detector

Target
app.local

Reason
Time-based check requested by plan.

[ Reject ]
[ Approve ]
```

The existing architecture explicitly requires T24 approval gates, redaction, replay, and the same scope controls as ordinary tools.

---

# 87. T25 REPORT CENTER

Report Center should resemble a security report editor.

Sections:

```text
Overview
Scope
Methodology
Findings
Evidence
Timeline
Appendix
Export
```

Findings table:

```text
Severity
Title
Target
Confidence
Status
```

Export:

```text
HTML
JSON
PDF
```

Preview should not look like a dashboard.

It should resemble a professional assessment document.

---

# 88. FINDINGS SYSTEM

Finding severity:

```text
Info
Low
Medium
High
Critical
```

Display:

```text
[High]
```

not:

```text
red card
```

Finding table:

```text
Severity
Finding
Target
Confidence
Status
Updated
```

---

# 89. FINDING DETAIL

Example:

```text
HIGH

Missing Content Security Policy

Target
https://app.local

Confidence
High

CWE
CWE-693

Evidence
--------------------------------
Content-Security-Policy header
was not observed.

Recommendation
Implement a restrictive CSP appropriate
for the application's resource model.
```

Supporting sections:

```text
Request
Response
Evidence
Timeline
Related Jobs
Related Target
```

---

# 90. FINDING ACTIONS

Contextual actions:

```text
Add to Report
Open Evidence
Send to Repeater
Copy
Mark False Positive
```

Do not show irrelevant actions.

---

# 91. EMPTY STATES

Every empty state must answer:

```text
What is empty?
Why is it empty?
What should the user do next?
```

Example:

```text
No results yet.

Enter a target in scope and press Run.

Try the local lab:
127.0.0.1
Profile: Lab
```

Avoid:

```text
Nothing here.
```

---

# 92. ERROR DESIGN

Error messages should contain:

```text
Condition
Cause
Action
```

Example:

```text
Target outside scope.

This job was blocked before network activity.

Add the target to Project Scope first.
```

This aligns with the project's existing scope semantics.

---

# 93. SAFETY BLOCK STATE

When execution is blocked:

```text
+------------------------------------------------------+
| Execution blocked                                    |
|                                                      |
| Target outside scope.                                |
|                                                      |
| No network activity was started.                     |
|                                                      |
| Add the target to Project Scope first.               |
+------------------------------------------------------+
```

The dialog must not look like a generic application error.

It is a security policy event.

---

# 94. APPROVAL STATE

Approval-required actions:

```text
+------------------------------------------------------+
| Approval required                                    |
|                                                      |
| Review the following operation before continuing.    |
|                                                      |
| Tool: T10 SQLi Detector                              |
| Target: app.local                                    |
| Mode: Time-based check                               |
| Scope: Project                                       |
|                                                      |
| [Reject]                              [Approve]      |
+------------------------------------------------------+
```

The action should be explicit.

---

# 95. GPU FALLBACK STATE

When hardware acceleration is unavailable:

```text
GPU not found. Using CPU fallback.
```

Do not use red.

Fallback is not necessarily an error.

Use informational or neutral styling.

---

# 96. RATE LIMIT STATE

Example:

```text
Rate limited by server (429). Backing off.
```

This should appear as:

```text
WARN
```

and inside job logs.

Do not use a blocking modal unless user action is required.

---

# 97. TOAST SYSTEM

Toasts should appear bottom-right.

Duration:

```text
2-4 seconds
```

Examples:

```text
Job started
Job completed
Project saved
Export complete
Target outside scope
Approval required
GPU fallback active
```

Do not use toasts for information the user must act on.

Use a persistent dialog or banner instead.

---

# 98. DIALOG SYSTEM

Dialogs:

```text
Maximum width: 720 px
Padding: 20-24 px
```

Structure:

```text
Header
Content
Actions
```

Buttons:

```text
[Cancel] [Apply]
```

Do not center huge modal content unless it is genuinely modal.

---

# 99. SETTINGS

Settings should use a left category list and right detail panel.

```text
+----------------------+--------------------------------------+
| General              | General                              |
| Scope                | UI Scale                             |
| Network              | Table Density                        |
| Acceleration         | Default Profile                      |
| AI Provider          | Autosave                             |
| Storage              |                                      |
| Updates              |                                      |
| Keyboard             |                                      |
| Appearance           |                                      |
+----------------------+--------------------------------------+
```

Categories:

```text
General
Scope
Network
Acceleration
AI Provider
Storage
Updates
Keyboard
Appearance
Privacy
```

---

# 100. APPEARANCE SETTINGS

Expose only meaningful controls.

```text
UI Scale
Compact
Standard
Large

Table Density
Compact
Standard
Comfortable

Animations
Minimal
Standard
```

Do not expose a giant custom theme editor.

Cyber-Clops must maintain a coherent visual identity.

---

# 101. KEYBOARD NAVIGATION

Required:

```text
Ctrl+K          Command Palette
Ctrl+Enter      Run Active Tool
Ctrl+.          Stop Running Jobs
Ctrl+L          Focus Target
Ctrl+F          Search Current Table
Ctrl+Shift+F    Global Search
Ctrl+J          Toggle Jobs
Ctrl+I          Toggle Inspector
Ctrl+1          Recon
Ctrl+2          Web
Ctrl+3          Network
Ctrl+4          Crack
Ctrl+5          Intel
Ctrl+6          Report
Esc             Close overlays
Enter           Confirm
```

Keyboard navigation must not conflict with text inputs.

Do not trigger global shortcuts when a text field is actively capturing the corresponding key combination unless the shortcut is intentionally defined.

---

# 102. FOCUS STATES

Every interactive control must show keyboard focus.

Example:

```text
Target
[127.0.0.1]
 ^ subtle focus border
```

Do not remove focus visibility merely for visual cleanliness.

Accessibility and keyboard control are part of the product quality.

---

# 103. HOVER STATES

Hover should be subtle:

```text
Normal
#11161B

Hover
#171D23

Selected
#1B2520 + primary accent
```

Avoid glow effects.

---

# 104. PRESSED STATES

Pressed state should darken slightly.

Do not animate buttons extensively.

Preferred feedback:

```text
100-150 ms
```

No bounce animation.

---

# 105. LOADING STATES

Use compact indicators.

Examples:

```text
Loading...
Connecting...
Scanning...
Parsing...
Waiting...
Stopping...
```

Do not freeze the entire interface.

While a job is running:

```text
Navigator remains usable
Inspector remains usable
Logs remain usable
Command palette remains usable
```

---

# 106. BACKGROUND EXECUTION

Running jobs must never make the GUI appear frozen.

The GUI must remain responsive.

The current architecture streams tool output and supports cancellation. Preserve that behavior while improving the presentation.

---

# 107. VIRTUALIZED DATA

Any large table must use virtualized rendering.

Target:

```text
100,000 rows
```

without creating 100,000 ImGui row widgets simultaneously.

The user should be able to:

```text
Sort
Filter
Scroll
Select
Inspect
```

without visible frame collapse.

The project plan specifically calls for high-volume data with responsive UI behavior.

---

# 108. DATA STREAMING UX

When rows arrive from an active job:

```text
New rows appear immediately
```

Do not wait until the job finishes.

For active scanning:

```text
Found result
+
Table update
+
Metric update
+
Log event
```

The user should visibly understand that the application is processing live data.

---

# 109. LIVE TABLE AUTO-SCROLL

Do not always force the table to scroll to the bottom.

Behavior:

```text
User at bottom:
    auto-follow new rows

User manually scrolled upward:
    pause automatic follow

Show:
    "37 new results"
```

Clicking:

```text
37 new results
```

returns the table to the latest result.

---

# 110. TABLE SELECTION BEHAVIOR

Single click:

```text
Select
Update Inspector
```

Double click:

```text
Open primary detail/action
```

Right click:

```text
Context menu
```

Ctrl-click:

```text
Multi-select
```

Do not make every action require double click.

---

# 111. CONTEXT-AWARE ACTIONS

Actions must depend on selection.

Port:

```text
Inspect
Send to TLS Analyzer
Send to HTTP Fingerprint
Send to CVE Mapper
Copy
```

URL:

```text
Inspect
Send to Repeater
Spider
Fingerprint
Copy
```

Finding:

```text
Inspect
Add to Report
View Evidence
Copy
Mark False Positive
```

This is one of the most important UX principles of Cyber-Clops.

Results should create workflow continuity.

---

# 112. DRAG AND DROP

Optional and useful:

```text
PCAP file -> Packet Sniffer
HAR file  -> Endpoint + Secrets
Wordlist  -> Directory Bruteforcer
Wordlist  -> Hash Cracker
Chain     -> Chain Builder
Project   -> Report Center
```

Do not create drag and drop merely to appear modern.

Only add it where it actually reduces user effort.

---

# 113. FILE PICKERS

File-related tools must use native or consistent file selection.

Displayed path:

```text
/home/user/wordlists/common.txt
```

Long paths should truncate from the middle:

```text
/home/user/.../common.txt
```

Provide:

```text
Copy Path
Open Folder
```

---

# 114. TOOL CONSISTENCY CONTRACT

Every tool must visually contain:

```text
Tool Identity
Input Controls
Execution Controls
Live Metrics
Result Area
Inspector Integration
Job Integration
Context Actions
```

Even if the actual controls differ.

Do not allow one tool to look like a different application.

---

# 115. COMPONENT ARCHITECTURE

Refactor GUI presentation into reusable components.

Suggested:

```text
apps/gui/
├── main.cpp
├── gui.h
├── ui/
│   ├── theme.h
│   ├── theme.cpp
│   ├── fonts.h
│   ├── fonts.cpp
│   ├── layout.h
│   ├── layout.cpp
│   ├── widgets.h
│   ├── widgets.cpp
│   ├── buttons.h
│   ├── buttons.cpp
│   ├── badges.h
│   ├── badges.cpp
│   ├── tables.h
│   ├── tables.cpp
│   ├── toolbar.h
│   ├── toolbar.cpp
│   ├── inspector.h
│   ├── inspector.cpp
│   ├── command_palette.h
│   ├── command_palette.cpp
│   ├── jobs_drawer.h
│   └── jobs_drawer.cpp
├── panels/
│   ├── topbar.cpp
│   ├── navigator.cpp
│   ├── workspace.cpp
│   ├── inspector.cpp
│   ├── jobs.cpp
│   └── settings.cpp
└── tools/
    ├── recon/
    ├── web/
    ├── network/
    ├── crack/
    ├── intel/
    └── report/
```

The exact file placement may be adjusted to fit the existing repository, but the separation of responsibilities should remain.

---

# 116. THEME API

Centralize all visual decisions.

Example:

```cpp
namespace clops::ui {

struct Theme {
    ImVec4 bg0;
    ImVec4 bg1;
    ImVec4 bg2;
    ImVec4 bg3;
    ImVec4 bg4;

    ImVec4 line0;
    ImVec4 line1;
    ImVec4 lineActive;

    ImVec4 textPrimary;
    ImVec4 textSecondary;
    ImVec4 textMuted;
    ImVec4 textDisabled;

    ImVec4 primary;
    ImVec4 info;
    ImVec4 success;
    ImVec4 warning;
    ImVec4 danger;
    ImVec4 critical;
};

void ApplyTheme();
void ConfigureMetrics();
void ConfigureFonts();

}
```

Do not scatter magic colors throughout panel code.

---

# 117. IMGUI STYLE CONFIGURATION

Replace the generic default style with the Cyber-Clops theme.

Conceptually:

```cpp
ImGuiStyle& style = ImGui::GetStyle();

style.WindowPadding = ImVec2(12.0f, 12.0f);
style.FramePadding = ImVec2(8.0f, 5.0f);
style.CellPadding = ImVec2(8.0f, 4.0f);

style.ItemSpacing = ImVec2(8.0f, 8.0f);
style.ItemInnerSpacing = ImVec2(6.0f, 6.0f);

style.ScrollbarSize = 12.0f;
style.GrabMinSize = 10.0f;

style.WindowRounding = 6.0f;
style.ChildRounding = 6.0f;
style.FrameRounding = 4.0f;
style.PopupRounding = 6.0f;
style.ScrollbarRounding = 4.0f;
style.GrabRounding = 4.0f;
style.TabRounding = 4.0f;
```

Do not blindly use these values everywhere if DPI scaling requires adjustment.

---

# 118. PANEL RENDERING MODEL

Recommended order:

```cpp
BeginFrame();

drawTopbar();
beginMainDockspace();

drawNavigator();
drawWorkspace();
drawInspector();

endMainDockspace();

drawJobsDrawer();
drawCommandPalette();
drawNotifications();
drawDialogs();

EndFrame();
```

The UI layer should not execute jobs directly during rendering.

---

# 119. STATE SEPARATION

Create clear UI state.

Example:

```cpp
struct NavigationState {
    int activeGroup = 0;
    int activeTool = 0;

    bool navigatorVisible = true;
    bool inspectorVisible = true;
    bool jobsVisible = true;
};

struct CommandPaletteState {
    bool open = false;
    char query[256] = {};
    int selectedIndex = 0;
};

struct TableState {
    int selectedRow = -1;
    bool followLiveResults = true;
};

struct InspectorState {
    bool visible = true;
    int selectedEntity = -1;
};
```

Avoid random global booleans distributed across files.

---

# 120. DATA VS PRESENTATION

Separate:

```text
Application data
Job execution
Security state
UI state
Rendering
```

Do not let:

```text
ImGui button
```

directly implement:

```text
security decision
```

The UI requests an operation.

The engine validates it.

The UI displays the result.

---

# 121. SCOPE UI CONTRACT

The UI must never decide that a target is safe by itself.

Flow:

```text
User Input
    |
    v
Application Request
    |
    v
Scope Validation
    |
    +---- Rejected
    |
    +---- Accepted
             |
             v
         Job Start
```

The UI displays:

```text
Scope validation passed
```

or:

```text
Target outside scope.
```

Do not duplicate scope parsing logic in multiple UI controls.

---

# 122. SAFE MODE UI CONTRACT

The UI must reflect engine safety state.

Do not create a fake toggle that visually changes state without changing real behavior.

If Safe Mode is locked:

```text
Safe Mode: ON
```

with supporting information:

```text
Scope enforcement active
Audit logging active
Destructive actions restricted
```

---

# 123. AUDIT UI CONTRACT

Audit entries should always originate from actual application events.

Never create fake UI-only audit logs such as:

```text
User clicked button
```

unless the application architecture actually defines click events as audit events.

Prefer security-relevant events:

```text
Scope accepted
Scope rejected
Job started
Job stopped
Approval granted
Approval denied
Policy violation blocked
Export generated
```

---

# 124. ACCELERATION UI CONTRACT

The UI must not inspect hardware independently of the official acceleration subsystem unless required.

Display the value supplied by the actual runtime detection system.

Possible:

```text
CPU: AVX2 + ISPC
GPU: CUDA
```

Possible:

```text
CPU: SSE4
GPU: None
Backend: CPU fallback
```

Never:

```text
GPU: CUDA
```

without real CUDA availability.

---

# 125. RESPONSIVE DOCKING

At large widths:

```text
Navigator 260
Workspace flexible
Inspector 320
```

At reduced width:

```text
Navigator collapsible
Inspector collapsible
Jobs drawer collapsible
```

Workspace always gets the first priority.

---

# 126. LAYOUT PERSISTENCE

Persist:

```text
Panel sizes
Dock arrangement
Selected tool
Table density
Column visibility
Inspector visibility
Jobs drawer visibility
```

Provide:

```text
View -> Reset Layout
```

Reset should restore the canonical Cyber-Clops workspace.

---

# 127. FIRST RUN

First launch:

```text
CYBER-CLOPS

Create or open a project.

[New Project]
[Open Project]
```

Then:

```text
Project Scope

Add domains, IPs, or CIDR ranges
allowed for this project.

[Add Target]

127.0.0.1

[Continue]
```

Then:

```text
Safety Profile

Safe Mode is enabled by default.

[Lab]
[Project]
[Review Settings]

[Finish]
```

Avoid an onboarding carousel.

---

# 128. PROJECT HOME

Optional project overview:

```text
demo.clops

Targets       12
Jobs           8
Findings       4
Evidence      39
Reports        1

Last Activity
19:22:10
```

This is a compact overview.

Do not build a giant "analytics dashboard".

---

# 129. NOTIFICATION PRIORITY

Severity:

```text
Critical
High
Warning
Info
Success
Debug
```

Notification behavior:

```text
Critical -> persistent until acknowledged
High     -> persistent or long duration
Warning  -> 4-6 seconds
Info     -> 2-4 seconds
Success  -> 2-4 seconds
Debug    -> logs only
```

---

# 130. TERMINAL VIEW

Terminal is a functional output surface, not the identity of the entire application.

Use:

```text
JetBrains Mono
12 px
Dark background
Subtle prompt
Structured log levels
```

Example:

```text
$ clops-job scan --host 127.0.0.1

[INFO] target validated
[INFO] scope accepted
[INFO] backend: ISPC
[OPEN] 22 ssh
[OPEN] 80 http
[OPEN] 443 https
```

Do not make the whole GUI imitate a terminal.

---

# 131. VISUAL HIERARCHY OF DATA

Priority:

```text
Primary:
Result value

Secondary:
Metadata

Tertiary:
Technical details

Supporting:
Logs

Optional:
Decorative context
```

There should be almost no decorative content.

---

# 132. INFORMATION DENSITY

Cyber-Clops is expected to display significant amounts of security data.

Therefore:

```text
Compact spacing
Dense tables
Short labels
Structured inspector
Limited card usage
Persistent context
```

Do not remove useful information merely to make the interface look minimal.

Minimalism is not the goal.

Operational clarity is.

---

# 133. "NO CARD SPAM" RULE

Do not implement:

```text
+----------+ +----------+ +----------+
| 12       | | 24       | | 81       |
| Targets  | | Findings | | Ports    |
+----------+ +----------+ +----------+
```

for every page.

Prefer:

```text
Targets 12 | Findings 24 | Ports 81
```

or a compact table.

Cards are allowed only when a card is functionally meaningful.

---

# 134. "NO GIANT HERO" RULE

Never use:

```text
CYBER-CLOPS
Security Operations Platform
The Future of Ethical Hacking
[Huge Button]
```

The user launches a desktop security tool to work.

Start working immediately.

---

# 135. "NO DECORATIVE CYBERPUNK" RULE

Do not add:

```text
Moving grid
Glitch effect
Scanline
Radar animation
Rotating globe
Holographic card
Neon border
Digital rain
```

unless later requested as an optional visual mode.

The default production theme must remain professional.

---

# 136. MICRO-INTERACTION SYSTEM

Allowed animations:

```text
Tooltip fade
Menu fade
Toast transition
Selection highlight
Progress movement
Panel appearance
```

Animation duration:

```text
100-180 ms
```

Do not animate continuously.

---

# 137. TOOLTIP RULES

Tooltips appear only when they add information.

Example:

```text
Rate limit

Maximum requests per second sent
to the selected host.
```

Do not repeat the label verbatim.

---

# 138. LABELING

Use precise English.

Preferred:

```text
Target
Scope
Profile
Rate Limit
Concurrency
Timeout
Backend
Status
Severity
Confidence
Evidence
```

Avoid:

```text
Magic
Ultra Mode
Cyber Boost
Hunter Engine
AI Power
Stealth Mode
```

unless they have actual technical semantics.

---

# 139. UI COPY BANK

Use consistent copy.

```text
Run
Stop
Pause
Resume
Cancel
Retry
Approve
Reject
Export
Save
Save to Workspace
Clear
Copy
Filter
Search
Details
Evidence
Settings
Docs
Open
Close
Refresh
Reset Layout
```

Job states:

```text
Queued
Running
Paused
Cancelled
Done
Failed
```

Severity:

```text
Info
Low
Medium
High
Critical
```

Existing project requirements define the same terminology and should remain consistent.

---

# 140. COPY STYLE

Write:

```text
Target outside scope.

This job was blocked before network activity.

Add the target to Project Scope first.
```

Not:

```text
Oops!
Something went wrong.
Try again.
```

The application should sound technical and trustworthy.

---

# 141. ACCESSIBILITY

Minimum requirements:

```text
Visible keyboard focus
Readable contrast
No color-only state
Readable text at default scale
Scalable UI
Keyboard navigation
```

Do not hide critical state in hover-only interactions.

---

# 142. DPI SCALING

The UI must support desktop scaling.

Do not hardcode assumptions that 1 logical pixel equals one physical pixel.

Fonts and layout metrics should be scaled consistently.

---

# 143. PERFORMANCE BUDGET

UI rendering should remain lightweight.

Avoid:

```text
Per-frame string construction for large tables
Per-row allocations
Repeated font switching
Repeated style mutation inside tight loops
```

Prefer:

```text
Cached strings
Reusable widgets
Virtualized tables
Precomputed metadata
Stable IDs
```

---

# 144. RENDERING PERFORMANCE

The design should not require:

```text
Blur
Post-processing
Full-screen effects
Particle systems
Continuous shader effects
```

The visual quality must come from correct layout and typography.

---

# 145. LARGE DATASET TEST

Test the table system with:

```text
1,000 rows
10,000 rows
50,000 rows
100,000 rows
```

Verify:

```text
Scrolling
Selection
Sorting
Filtering
Inspector updates
Context menu
Live insertion
```

The interface must remain usable.

---

# 146. LONG CONTENT TEST

Test:

```text
Very long URLs
Long file paths
Large HTTP headers
Long certificate SAN lists
Long banners
Large JSON
Long log lines
Large hashes
```

Rules:

```text
Truncate visually
Never destroy source data
Provide tooltip or inspector
Provide copy action
```

---

# 147. WINDOW RESIZE TEST

Test:

```text
1920x1080
1600x900
1400x900
1280x800
1100x700
```

Verify:

```text
No overlapping panels
No clipped controls
Workspace remains usable
Inspector can collapse
Navigator can collapse
Job drawer can collapse
```

---

# 148. JOB STATE TEST

Verify UI for:

```text
Queued
Running
Paused
Stopping
Cancelled
Done
Failed
```

Every state must be visually obvious.

---

# 149. MULTI-JOB TEST

Run multiple jobs.

The UI must show:

```text
Job #014 Running
Job #015 Running
Job #016 Queued
```

The active tool must not obscure other jobs.

---

# 150. FAILURE TEST

Simulate:

```text
Engine unavailable
Invalid target
Target outside scope
Timeout
Rate limiting
Malformed output
Permission failure
Backend unavailable
```

Every error must remain understandable without exposing internal stack traces in the primary user-facing message.

Stack traces belong in:

```text
Logs
Diagnostics
```

---

# 151. INSPECTOR RELATIONSHIP TEST

Select:

```text
Port
URL
Finding
Job
Packet
CVE
Subdomain
```

The inspector must change accordingly.

Do not reuse a generic inspector containing irrelevant fields.

---

# 152. COMMAND PALETTE TEST

Verify:

```text
Ctrl+K
Search
Arrow navigation
Enter
Esc
Recent commands
Tool launch
Actions
```

No focus bugs.

No input deadlocks.

---

# 153. RESET LAYOUT TEST

After random docking:

```text
View
Reset Layout
```

must return to:

```text
Topbar
Navigator
Workspace
Inspector
Jobs
```

with sensible proportions.

---

# 154. TOOL NAVIGATION TEST

Switch rapidly:

```text
T01
T03
T04
T14
T20
T23
T24
T25
```

Verify:

```text
No stale inspector data
No stale selection
No duplicated jobs
No stale metrics
No UI corruption
```

---

# 155. DATA SAFETY RULE

Do not expose sensitive values accidentally in:

```text
Toasts
Tooltips
List views
Notifications
Command palette
```

Sensitive content belongs in appropriate evidence/detail views with redaction when required.

---

# 156. AI-SPECIFIC UX RULE

AI features must not visually dominate the application.

T24 is one tool among the tool ecosystem.

Do not make an oversized AI chat panel the default home screen.

The default workflow remains:

```text
Project
Scope
Tools
Results
Evidence
Jobs
Reports
```

AI is an optional orchestration capability.

---

# 157. AI APPROVAL VISUAL LANGUAGE

AI-generated action:

```text
Proposed
```

Execution:

```text
Approved
```

Blocked:

```text
Blocked
```

Completed:

```text
Completed
```

Do not imply the AI is autonomous when an approval gate is required.

---

# 158. CHAIN BUILDER VISUAL LANGUAGE

Every node must make these visible:

```text
Tool ID
Tool Name
Input
Output
Status
```

Connection means:

```text
Data relationship
```

not merely visual decoration.

---

# 159. REPORT VISUAL LANGUAGE

Reports must use conventional security language.

Do not use:

```text
Threat score 9000
Hack level
Cyber level
AI confidence aura
```

Use:

```text
Severity
Confidence
Impact
Evidence
Recommendation
Status
```

---

# 160. SECURITY TERMINOLOGY

Prefer exact technical terms.

Examples:

```text
Scope
Target
Finding
Evidence
Service
Port
Protocol
Header
Certificate
Payload
Request
Response
Confidence
Severity
```

Avoid marketing terminology.

---

# 161. DESIGN TOKEN CENTRALIZATION

Create a central token file.

Conceptual:

```cpp
namespace clops::ui::tokens {

constexpr float PanelPadding = 14.0f;
constexpr float SectionGap = 16.0f;
constexpr float ControlGap = 8.0f;

constexpr float RadiusPanel = 6.0f;
constexpr float RadiusControl = 4.0f;

}
```

This allows the whole application to evolve consistently.

---

# 162. COMPONENT NAMING

Use descriptive components.

Good:

```text
ClopsPanel
ClopsToolbar
ClopsBadge
ClopsTable
ClopsInspector
ClopsMetricStrip
ClopsCommandPalette
ClopsJobsDrawer
ClopsStatusIndicator
```

Avoid:

```text
Box1
Panel2
WidgetX
MagicCard
CyberPanel
```

---

# 163. PANEL CONTRACT

Each panel should answer:

```text
What is this?
What information does it contain?
What interactions does it support?
What state can it display?
```

A panel must not become a dumping ground for unrelated UI.

---

# 164. DESIGN REVIEW CHECKLIST

Before considering a screen finished, verify:

```text
Does every element serve a purpose?
Can the user find the active tool immediately?
Can the user see scope?
Can the user see Safe Mode?
Can the user see job state?
Can the user understand result state?
Can the user inspect selected data?
Can the user access relevant next actions?
Can the user operate it with keyboard?
Does the screen remain usable with large datasets?
Does the screen still look professional without icons?
```

If the answer is no, improve the structure instead of adding decoration.

---

# 165. IMPLEMENTATION PRIORITY

Implement in this order.

```text
Phase 1
Theme
Fonts
Metrics
Colors
Buttons
Inputs
Badges
Panels

Phase 2
Docking
Topbar
Navigator
Workspace
Inspector
Jobs Drawer

Phase 3
Command Palette
Search
Filtering
Context menus
Toasts
Dialogs

Phase 4
Tool-specific views
Tables
Evidence
Relationships
Reports

Phase 5
Performance
Virtualization
Keyboard navigation
Accessibility
DPI scaling
State persistence
```

Do not begin with decorative elements.

---

# 166. CURRENT GUI REFACTOR TARGET

The current entry point initializes Dear ImGui with the default dark theme and renders:

```text
Topbar
Left Tree
Center
Inspector
Bottom
Palette
```

The redesign should retain that conceptual structure while replacing the visual implementation with the Cyber-Clops design system.

Do not throw away the current application entry point unless a concrete architectural reason exists.

---

# 167. REFACTOR STRATEGY

Recommended first changes:

```text
1. Add UI theme module.
2. Add font loader.
3. Replace StyleColorsDark().
4. Configure docking defaults.
5. Rebuild topbar.
6. Rebuild navigator.
7. Rebuild workspace shell.
8. Rebuild inspector.
9. Rebuild jobs drawer.
10. Rebuild command palette.
11. Introduce reusable table components.
12. Introduce reusable status badges.
13. Integrate existing tool state.
14. Add layout persistence.
15. Add keyboard navigation.
16. Optimize large result rendering.
```

Do not rewrite every tool before the common shell is stable.

---

# 168. DO NOT DUPLICATE TOOL METADATA

The repository already contains:

```text
Tool ID
Name
Group
Description
Verb
Extra Label
```

Use that existing metadata as the canonical tool registry.

The UI should not maintain a second list of the 25 tools unless required for presentation indexing.

---

# 169. TOOL REGISTRY PRESENTATION

Render tool metadata into:

```text
Tool ID
Name
Group
Description
Required input
Execution state
```

Tool metadata should drive the navigator and command palette where possible.

---

# 170. STATE COLORS

Operational status:

```text
Queued     neutral
Running    information / active
Paused     warning
Cancelled  muted
Done       success
Failed     danger
```

Severity:

```text
Info       information
Low        muted
Medium     warning
High       danger
Critical   critical
```

Do not confuse:

```text
Job status
```

with:

```text
Finding severity
```

These are different semantic systems.

---

# 171. STATUS BADGES

Use:

```text
Running
Done
Failed
High
Safe
Review
Lab Only
```

inside compact badges.

Avoid giant labels.

---

# 172. TOOL BADGES

Tool-level badge:

```text
SAFE
```

means execution behavior is considered safe under its defined profile.

```text
REVIEW
```

means explicit review may be required.

```text
LAB ONLY
```

means the tool should visibly communicate laboratory-only usage.

Do not use badges without actual policy meaning.

---

# 173. PROJECT SCOPE UI

Project scope should be inspectable.

Example:

```text
PROJECT SCOPE

Domains
example.com
*.example.com

IPs
127.0.0.1
192.168.1.10

CIDR
192.168.1.0/24
```

Actions:

```text
Add
Edit
Remove
Import
Export
```

Do not hide scope rules in a distant settings page.

---

# 174. SCOPE CONFIRMATION

When a target is accepted:

```text
Scope validation passed.
```

When rejected:

```text
Target outside scope.
```

When ambiguous:

```text
Scope requires review.
```

The UI must communicate what happened before job execution.

---

# 175. SECURITY UX PRIORITY

When there is a conflict between:

```text
Visual elegance
```

and:

```text
Security clarity
```

choose security clarity.

When there is a conflict between:

```text
Compactness
```

and:

```text
Critical information visibility
```

choose critical information visibility.

When there is a conflict between:

```text
Animation
```

and:

```text
Performance
```

choose performance.

---

# 176. TABLE COLUMN RULE

Do not show every possible field by default.

Default columns should be:

```text
Most useful
Most actionable
Most readable
```

Additional fields belong behind:

```text
Column Settings
Inspector
```

---

# 177. COLUMN ORDER

Place columns according to operational importance.

Example:

```text
Port
State
Service
Version
Latency
Banner
```

not:

```text
Banner
UUID
Timestamp
Internal ID
Port
```

---

# 178. SORT DEFAULTS

Choose meaningful defaults.

Port scanner:

```text
Port ascending
```

Findings:

```text
Severity descending
```

Jobs:

```text
Newest first
```

Logs:

```text
Newest first in default drawer
```

---

# 179. FILTER STATE VISIBILITY

When filters are active, show:

```text
Filter: 3 active
```

or:

```text
State: Open
Severity: High+
```

Do not silently hide data.

---

# 180. USER TRUST RULE

Never create UI that suggests an operation happened when it did not happen.

Examples:

Do not display:

```text
Scan complete
```

when the job merely stopped.

Do not display:

```text
GPU active
```

when the runtime selected CPU fallback.

Do not display:

```text
Takeover confirmed
```

when the detector only found a possible signal.

Do not display:

```text
Exploit successful
```

when a probe merely returned an error.

The UI must reflect actual engine state.

---

# 181. PERFORMANCE STATUS

Do not put a generic FPS counter into the default interface.

Performance diagnostics belong in developer/debug settings.

The production topbar should show only operationally relevant runtime backend information.

---

# 182. DEBUG MODE

Optional developer diagnostics:

```text
FPS
Frame time
Draw calls
Visible rows
Memory
Job queue depth
```

Put them inside:

```text
Settings -> Developer
```

or a debug overlay.

Do not clutter the normal workspace.

---

# 183. DARK THEME ONLY FOR INITIAL RELEASE

The primary theme is:

```text
Cyber-Clops Dark
```

Do not spend implementation time on light mode before the dark production theme is complete.

A second theme can be considered after the primary design system is stable.

---

# 184. VISUAL QA

Compare every screen against these questions:

```text
Is hierarchy immediately obvious?
Are inputs compact?
Are results dominant?
Is scope visible?
Is Safe Mode visible?
Is status readable?
Are logs secondary?
Are cards minimized?
Are borders subtle?
Are colors semantic?
Are icons consistent?
Is the interface calm?
```

---

# 185. SCREEN-BY-SCREEN QA

Validate:

```text
T01 Subdomain Enumerator
T02 DNS Toolkit
T03 Port Scanner
T04 SSL/TLS Analyzer
T05 HTTP Fingerprint
T06 Cloud + Takeover
T07 Directory Bruteforcer
T08 Web Spider
T09 Endpoint + Secrets
T10 SQLi Detector
T11 XSS Scanner
T12 LFI + SSTI Tester
T13 Misconfig Checker
T14 Repeater
T15 Intercept Proxy
T16 Packet Sniffer
T17 CVE Mapper
T18 Payload Generator
T19 Codec Lab
T20 Hash Cracker
T21 Wordlist Studio
T22 OSINT Toolkit
T23 Chain Builder
T24 AI Auto Hacker
T25 Report Center
```

All 25 tools should feel like members of the same product.

---

# 186. ACCEPTANCE CRITERIA

The redesign is not complete until all requirements below pass.

```text
[ ] Default ImGui visual style replaced
[ ] Cyber-Clops color tokens implemented
[ ] Typography system implemented
[ ] Inter loaded for UI
[ ] JetBrains Mono loaded for technical data
[ ] Topbar redesigned
[ ] Navigator redesigned
[ ] Workspace shell redesigned
[ ] Inspector redesigned
[ ] Jobs drawer redesigned
[ ] Command palette redesigned
[ ] Search implemented
[ ] Context menus implemented
[ ] Status badges implemented
[ ] Compact metric strip implemented
[ ] Table system standardized
[ ] Large-data rendering optimized
[ ] Tool navigation standardized
[ ] Layout persistence implemented
[ ] Reset Layout implemented
[ ] Keyboard navigation implemented
[ ] Focus state implemented
[ ] Empty states implemented
[ ] Error states implemented
[ ] Safety states implemented
[ ] Scope states implemented
[ ] Approval UI implemented
[ ] GPU fallback UI implemented
[ ] Logs standardized
[ ] Audit standardized
[ ] Inspector contextual data implemented
[ ] T03 matches reference layout quality
[ ] T14 request/response workspace implemented
[ ] T16 packet workspace implemented
[ ] T20 throughput workspace implemented
[ ] T23 chain workspace implemented
[ ] T24 approval workflow implemented
[ ] T25 report workspace implemented
[ ] 1100x700 layout validated
[ ] 1400x900 layout validated
[ ] 1920x1080 layout validated
[ ] 100k-row table test validated
[ ] Multi-job test validated
[ ] Long-content test validated
[ ] Resize test validated
[ ] No fake backend state
[ ] No fake job state
[ ] No fake security findings
[ ] No decorative cyberpunk effects
[ ] No emoji icons
[ ] No giant cards
[ ] No excessive gradients
[ ] No visual clutter
```

---

# 187. DEFINITION OF PROFESSIONAL QUALITY

Cyber-Clops should feel professional because of:

```text
Correct hierarchy
Consistent spacing
Reliable behavior
Clear execution state
Useful density
Predictable interaction
Good typography
Stable docking
Fast navigation
Accurate status
Strong data relationships
```

Not because of:

```text
More colors
More animation
More gradients
More icons
More glow
More cards
```

---

# 188. DEFINITION OF "MODERN"

Modern Cyber-Clops means:

```text
Keyboard-first
Searchable
Context-aware
Responsive
Dense but readable
Persistent state
Virtualized tables
Consistent components
Inline actions
Clear evidence flow
Low visual noise
```

Modern does not mean:

```text
Glassmorphism
Huge cards
Rounded everything
Gradient everything
```

---

# 189. DEFINITION OF "CYBER"

Cyber-Clops should look like cybersecurity software through its information architecture.

The cyber identity comes from:

```text
Targets
Scope
Services
Ports
Requests
Responses
Packets
Findings
Evidence
Jobs
Audit
Security severity
Backend information
Execution controls
```

not from neon decoration.

---

# 190. GOLDEN UI RULE

When deciding between two possible UI implementations:

```text
Choose the version that lets the security operator understand
more information with fewer interactions and less visual noise.
```

---

# 191. GOLDEN INTERACTION RULE

Every meaningful result should provide a next action.

Example:

```text
Port 443
    |
    +--> TLS Analyzer
    +--> HTTP Fingerprint
    +--> CVE Mapper
```

Example:

```text
URL
    |
    +--> Repeater
    +--> Spider
    +--> Fingerprint
```

Example:

```text
Finding
    |
    +--> Evidence
    +--> Repeater
    +--> Report
```

This is the key interaction model that differentiates Cyber-Clops from a collection of isolated tools.

---

# 192. GOLDEN SECURITY RULE

Security state must never be hidden for aesthetic reasons.

Always visible:

```text
Scope
Safe Mode
Job State
Execution State
Backend
Severity
Approval State
```

---

# 193. GOLDEN DATA RULE

Do not make important technical information visually attractive at the expense of readability.

A table containing:

```text
10000
```

correctly aligned is more valuable than a card displaying:

```text
10K
```

inside a giant animated widget.

---

# 194. GOLDEN PERFORMANCE RULE

Avoid UI effects that compete with security workloads.

The application should look better as a result of:

```text
Typography
Spacing
Alignment
Hierarchy
Consistency
```

not through rendering complexity.

---

# 195. FINAL TARGET

The finished Cyber-Clops GUI should visually communicate the following within approximately five seconds of launch:

```text
This is a serious security engineering application.

This is my current project.

This is my active scope.

Safe Mode is active.

These are my available security tools.

This is the current job state.

These are my results.

This selected result has evidence.

I can continue the workflow from here.
```

That is the final design target.

---

# 196. IMPLEMENTATION INSTRUCTION TO THE CODING AGENT

Implement this UI as a real production interface.

Do not produce a mockup.

Do not create placeholder panels that only look complete.

Do not insert fake rows merely to make the screen look populated.

Do not generate fake GPU values.

Do not create fake job progress.

Do not invent security findings.

Do not invent backend capabilities.

Use the real application state wherever available.

When a backend feature does not exist, represent the state honestly.

When a feature is not implemented yet, use a restrained empty state or disabled control with an explanation.

Do not hide incomplete functionality behind polished fake UI.

---

# 197. IMPLEMENTATION ORDER FOR AI CODING AGENT

Start with:

```text
1. Inspect existing GUI state and rendering.
2. Preserve existing engine interfaces.
3. Create centralized UI tokens.
4. Create theme application.
5. Load application fonts.
6. Implement reusable panel primitives.
7. Implement reusable button/input/badge primitives.
8. Implement table infrastructure.
9. Implement topbar.
10. Implement navigator.
11. Implement workspace shell.
12. Implement inspector.
13. Implement jobs drawer.
14. Implement command palette.
15. Connect real state.
16. Standardize tool screens.
17. Add keyboard interactions.
18. Add layout persistence.
19. Optimize large tables.
20. Run complete UI validation.
```

Do not jump directly to decorative polish.

---

# 198. CODE QUALITY REQUIREMENTS

The GUI implementation must:

```text
Use clear names
Avoid duplicated styling
Avoid excessive globals
Avoid magic numbers
Avoid repeated allocations
Avoid unnecessary per-frame work
Keep rendering code readable
Keep data logic separate
Keep security logic out of presentation code
Use stable ImGui IDs
Use consistent RAII/resource handling
```

Do not make one massive `main.cpp`.

---

# 199. FILE ORGANIZATION REQUIREMENT

Prefer:

```text
ui/theme.*
ui/fonts.*
ui/widgets.*
ui/tables.*
ui/inspector.*
ui/command_palette.*
ui/jobs_drawer.*
panels/topbar.*
panels/navigator.*
panels/workspace.*
panels/settings.*
```

over:

```text
main.cpp
    5000 lines
```

The exact organization can adapt to the repository, but the responsibilities should remain separated.

---

# 200. FINAL DESIGN STATEMENT

Cyber-Clops should not attempt to be the loudest security tool on the screen.

It should be the clearest.

It should feel like an application created by engineers who understand:

```text
network traffic
web security
security testing
large datasets
job orchestration
hardware acceleration
evidence collection
scope control
auditability
desktop software
```

The visual language must remain restrained.

The interface must remain dense.

The interactions must remain predictable.

The state must remain honest.

The data must remain inspectable.

The security controls must remain explicit.

The result should be a native desktop security workstation that feels deliberate, mature, and technically credible.

That is the Cyber-Clops GUI standard.

# END OF SPECIFICATION