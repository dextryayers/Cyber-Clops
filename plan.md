# Cyber-Clops Cyber Kit - Master Plan
Version: 2.0.0
Date: 2026-09-30
Status: Approved for build
Owner: Cyber-Clops Team
Primary stack: Rust + Dear ImGui + Lua + C/C++ + Go + CUDA/OpenCL/ISPC/eBPF
UI language: Full English only
Doc rule: No emdash character anywhere. Use hyphen - or comma. No purple gradient. No emoji icons.

## 0. Executive Summary

Cyber-Clops is a native desktop security toolkit with 25 tools in one workspace. It is offline first, audit logged, scope guarded, and performance oriented.

Target users: penetration testers, bug bounty hunters, sysadmins, SOC analysts.

Core promises:
1. One workspace file. All tools read and write to the same project.
2. Explicit network behavior. Every job shows target, rate, progress, logs, and a working Stop button.
3. No mandatory API key. Default recon sources work without keys.
4. Deterministic engines first, AI second. AI chains tools, it never replaces them.
5. Native speed. 60 fps UI with 100k rows. Real time streaming for scan results.
6. Hardware acceleration where it matters, with CPU fallback that always works.

GUI decision: Dear ImGui with SDL3 + OpenGL3, docking branch.
Reason: best for dense tables, multi panel docking, hex view, terminal view, live graphs, and low overhead rendering. It also bridges cleanly to C ABI for Rust, C, C++, Go, Lua, CUDA, and ISPC modules.

## 1. Scope: 25 Tools

All tools follow the same contract: input bar, profile selector, Run and Stop, live stats, virtualized result table, right inspector, export to JSON and CSV, save to workspace SQLite, audit log entry.

| ID | Name | Core function | Main engine | Priority |
|----|------|---------------|-------------|----------|
| T01 | Subdomain Enumerator | Aggregate 22+ cert and DNS sources without key plus local brute | Rust + Lua | P0 |
| T02 | DNS Toolkit | A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, AXFR check, PTR batch | Rust + C | P0 |
| T03 | Port Scanner + Banner | Fast TCP scan plus banner grab plus service version in real time | Rust + C + io_uring + ISPC | P0 |
| T04 | SSL/TLS Analyzer | Chain, expiry, SAN, protocol, cipher, HSTS, OCSP, vuln heuristics, grade | Rust | P0 |
| T05 | HTTP Fingerprint | Headers, tech stack, WAF detect, cookie audit | Rust + Lua | P1 |
| T06 | Cloud + Takeover Scanner | S3, Azure blob, GCS, Github Pages, Heroku, 30+ takeover fingerprints | Rust + Lua | P1 |
| T07 | Directory Bruteforcer | Fuzz paths with smart 404 filter, checkpoint resume | Rust + Go sidecar + ISPC | P0 |
| T08 | Web Spider + Crawler | Crawl site, sitemap, JS links, form map | Rust + ISPC regex | P1 |
| T09 | Endpoint + Secret Extractor | Parse JS and responses for endpoints and high precision secrets | Rust + Lua | P1 |
| T10 | SQLi Detector | Safe error, boolean, and gated time based checks | Rust + Lua payloads | P1 |
| T11 | XSS Scanner | Reflected context aware check with double send validation | Rust | P1 |
| T12 | LFI + Traversal + SSTI Tester | Path traversal plus template injection safe probe | Rust + Lua | P2 |
| T13 | Misconfig Checker | CORS, clickjacking, cookies, CSP, HSTS, info leak, CWE mapped | Rust | P1 |
| T14 | Request Repeater + Intruder | Raw editor, resend, diff, parameterized fuzz | Rust | P1 |
| T15 | Intercept Proxy | Local proxy, history, scope filter, send to Repeater | Rust | P1 |
| T16 | Packet Sniffer + PCAP Analyzer | Live capture with eBPF filter plus offline PCAP parse | C + eBPF + Rust + ISPC | P1 |
| T17 | CVE Mapper | Map service version to offline CVE DB, suggest next check | Rust + SQLite | P1 |
| T18 | Payload Generator | Reverse shell and bind shell builder with listener helper | Rust + Lua + C | P2 |
| T19 | Codec Lab | Hash ID, Base64, Hex, URL, JWT parse, timestamp, UUID | Rust + ISPC | P0 |
| T20 | Hash Cracker | Dict + mask + hybrid, CPU SIMD plus GPU CUDA/OpenCL, 30+ types | C++/CUDA/OpenCL/ISPC + Rust | P0 |
| T21 | Wordlist Studio | Generate, mutate, combine, filter, stream 1 GB plus | Go + Lua + ISPC | P1 |
| T22 | OSINT Toolkit | Username, email, breach local check, metadata, Wayback host | Rust + Lua | P2 |
| T23 | Chain Builder | No code DAG to chain T01 to T22 with vars and conditions | Rust | P1 |
| T24 | AI Auto Hacker | Planner plus gated executor with full audit | Rust + LLM adapter | P2 |
| T25 | Report Center | Findings, severity, evidence, HTML/PDF/JSON export, timeline | Rust + SQLite | P0 |

Total is 25. Do not reduce for v1.

## 2. Architecture

### 2.1 Layer diagram

```
+------------------------------------------------------------+
| GUI: Dear ImGui + SDL3 + OpenGL3                           |
| Topbar, Nav Tree, Center Tabs, Inspector, Jobs Drawer       |
+----------------------------+-------------------------------+
| App Core Rust              | Lua 5.4 Sandbox               |
| jobs, scope, rate limit,   | payloads, probes, transform,  |
| store, chain runtime,      | takeover fingerprints,        |
| proxy + intercept control  | custom tool panels            |
+----------------------------+-------------------------------+
| Scan Engines Rust          | Native C/C++                  |
| http, dns, tls, crawl,     | sockets, io_uring, pcap,      |
| detectors, cve match,      | simd parse, hash scalar core  |
+----------------------------+-------------------------------+
| Acceleration Layer                                         |
| CUDA C++, HIP, OpenCL C, ISPC, eBPF C                      |
+----------------------------+-------------------------------+
| Go Workers via gRPC on 127.0.0.1                           |
| dir brute stream, wordlist stream, template scan fanout    |
+------------------------------------------------------------+
| Storage: SQLite + JSONL logs + PCAP + export files         |
+------------------------------------------------------------+
```

### 2.2 Language boundaries, strict

Rust:
- Orchestrator, job scheduler, scope guard, rate limiter, HTTP, DNS async, TLS parse, crawler, detectors T10 to T13, proxy T15, CVE match T17, OSINT fetch, chain runtime T23, AI runtime T24, report T25, SQLite store.
- Exposes stable C ABI in `clops_core.h`. GUI never links scan logic directly except through this ABI.

C:
- `native/net/`: socket tuning, TCP connect batch, timeout control, banner read, PCAP open, io_uring helpers.
- Reason: precise control of flags, timeouts, and zero copy paths.

C++:
- `apps/gui/`: ImGui shell, docking, virtual tables, hex view, terminal, plots.
- `native/cpp/`: scalar hash core, SIMD AVX2 and AVX512 kernels, dispatcher, OpenCL host bridge, CUDA host bridge.
- Reason: ImGui is native C++ and hash kernels need intrinsics.

Go:
- `workers/go/`: high concurrency fanout for T07 dir brute, T21 wordlist stream, T08 crawl queue.
- Runs as local sidecar with random token per session over gRPC. Defined in `proto/clops.proto`.
- Never used for GUI. Only for IO fanout with backpressure.

Lua 5.4:
- `scripts/lua/`: payload packs, service probes, takeover fingerprints, WAF signatures, wordlist transforms, chain step templates.
- Sandbox: 5 sec timeout, memory cap, no file access outside workspace unless allowed, no raw socket except via `clops.*` API.
- API surface: `clops.http`, `clops.dns`, `clops.hash`, `clops.ui_panel`, `clops.store`, `clops.vars`.

Hardware languages, first class:
- CUDA C++ `.cu` for NVIDIA GPUs.
- HIP C++ `.hip` for AMD GPUs, same kernel source style.
- OpenCL C `.cl` for vendor neutral GPUs and iGPUs.
- ISPC `.ispc` for CPU SIMD across x86_64 and ARM.
- eBPF C `.bpf.c` for kernel packet filter for T16.
- These are not optional scripts. They build with the project and have CPU fallback.

### 2.3 Concurrency and real time rules

- Every tool is a Job: queued, running, paused, cancelled, done, failed.
- Tokio for async IO. Rayon for CPU bound. Go workers for mass fanout.
- UI never blocks. Results stream in batches of 100 to 500 rows per frame via channel.
- Virtualized tables only render visible rows. Target 100k rows at 60 fps.
- Stop must cancel in under 500 ms via cancellation token propagated to Rust, Go, and native layers.
- Global plus per host rate limit. Defaults: 50 rps per host for internet, 2000 rps allowed in lab with explicit Lab profile warning.

### 2.4 Scope guard and safety, non negotiable

- Project defines Allowed Scope: domains, IPs, CIDR ranges.
- Job is rejected before first packet if target is outside scope.
- Safe Mode ON by default: detect only, no dump, no destructive payload, time based SQLi needs explicit approve, takeover check is DNS plus HTTP GET only, no takeover claim action.
- Audit log JSONL records timestamp, tool ID, target, profile, payload hash, job ID. UI cannot disable audit log.
- T24 AI cannot bypass scope guard. Any bypass attempt is blocked and logged as high severity event.

## 3. Hardware Acceleration Stack

Goal: full acceleration where it pays, honest fallback where it does not.

### 3.1 Components

1. CUDA C++ backend
- Path: `native/accel/cuda/`
- Files: `md5.cu`, `sha1.cu`, `sha256.cu`, `ntlm.cu`, `maskgen.cu`, `dispatch.cu`
- Used by: T20 for fast hashes, T21 for mask expansion.
- Requires: CUDA Toolkit 12+. Compute capability 6.0 plus. Runtime detection, no hard require.
- Fallback: OpenCL, then ISPC CPU, then scalar Rust.

2. HIP backend for AMD
- Path: `native/accel/hip/`
- Files mirror CUDA: `md5.hip`, `sha256.hip`, `ntlm.hip`
- Used by: T20 on AMD GPUs.
- Build flag `CL_OPS_ENABLE_HIP=ON`. If off, OpenCL path is used.

3. OpenCL C backend, vendor neutral
- Path: `native/accel/opencl/`
- Files: `md5.cl`, `sha1.cl`, `sha256.cl`, `ntlm.cl`, `common.cl`
- Used by: T20 on Intel iGPU, AMD without HIP, Apple via POCL fallback, CI runners without NVIDIA.
- Runtime kernel compile with cache in `~/.cache/clops/kernels`.

4. ISPC CPU SIMD backend
- Path: `native/accel/ispc/`
- Files: `banner_parse.ispc`, `http_parse.ispc`, `base64.ispc`, `regex_util.ispc`, `word_mutate.ispc`, `packet_decode.ispc`, `hash_cpu.ispc`
- Used by:
  - T03 banner version parse
  - T07 404 similarity and filter
  - T08 link extract
  - T09 endpoint regex
  - T16 packet decode
  - T19 base64 and hex bulk codec
  - T20 CPU fast path for MD5, SHA1, SHA256, NTLM
  - T21 high speed mutate
- Speedup target: 6x to 14x vs scalar on AVX2. ARM NEON path via ISPC aarch64 target.
- Always available. This is the default CPU accel. Scalar is only for correctness tests.

5. C++ SIMD intrinsics
- Path: `native/cpp/simd/`
- Files: `sha_avx2.cpp`, `md5_sse.cpp`, `blake2_avx.cpp`
- Used when ISPC cannot express carry heavy loops with best throughput. Dispatcher picks ISPC or intrinsics based on micro benchmark at startup.

6. eBPF packet filter
- Path: `native/net/bpf/`
- Files: `sniff_filter.bpf.c`, `sniff_user.c`
- Used by: T16 to drop noise in kernel by port, host, and TCP flags before userspace sees packets.
- Requires Linux 5.8 plus and CAP_NET_RAW or root for live capture. Offline PCAP parse works without root via pure Rust plus ISPC path.

7. io_uring fast IO
- Path: `native/net/uring/`
- Used by: T03 port scan and T07 dir brute on Linux for batched connect and send recv.
- Fallback: Tokio TCP on Windows and macOS. Same UI, different throughput.

### 3.2 Dispatcher design, real wiring

`native/cpp/dispatch/dispatch.cpp` plus `core/rust/src/accel.rs` implement one dispatcher.

Startup flow:
1. Detect CPU features: SSE4, AVX2, AVX512, NEON.
2. Detect GPU: CUDA driver version, OpenCL platforms, HIP runtime.
3. Micro bench 200 ms per available backend for MD5 and SHA256 and banner parse.
4. Pick fastest per task and store choice in `accel_choice.json` per session.
5. UI shows badge in Topbar: `CPU: AVX2 + ISPC` and `GPU: CUDA 12.4 RTX` or `GPU: None, CPU only`. No fake GPU label.

Per job flow for T20:
```
UI Run -> Rust job -> dispatch.pick(hash_type)
 -> if fast hash and CUDA ready: load .cubin, stream batches, report H/s
 -> else if OpenCL ready: load cached kernel, same interface
 -> else: ISPC batch across Rayon threads
 -> stream founds immediately, checkpoint every 5 sec
```

Per packet flow for T16:
```
eBPF filter in kernel -> ring buffer -> Rust reader
 -> ISPC packet_decode for Ethernet, IPv4, IPv6, TCP, UDP, DNS
 -> UI table stream, PCAP writer in parallel thread
```

Per scan flow for T03:
```
Rust targets -> C batch connect via io_uring if Linux
 -> banner read with 3 sec timeout
 -> ISPC banner_parse for Server and version regex
 -> service probe Lua for edge cases
 -> UI row appears in under 300 ms after open found
```

### 3.3 Build integration

CMake targets:
- `clops_accel_cuda` if `CL_OPS_ENABLE_CUDA=ON` and toolkit found
- `clops_accel_opencl` if OpenCL SDK found
- `clops_accel_ispc` always if `ispc` binary found, else scalar define
- `clops_bpf` on Linux only
- `clops_core` static lib links all accel objects and exports C ABI
- Rust links via `build.rs` with `ffi` feature. `cargo build` without GPU still works, dispatcher reports CPU only.

CI must test three configs: CPU only, CPU plus OpenCL mock, CUDA compile check without GPU via `nvcc --ptx`.

## 4. Tool to Acceleration Map

| Tool | Hot path | Acceleration used | Source files | Fallback |
|------|----------|-----------------|--------------|----------|
| T03 Port Scan | connect batch, banner parse | io_uring + ISPC banner_parse | `native/net/scan.c`, `banner_parse.ispc` | Tokio TCP + scalar parse |
| T07 Dir Brute | HTTP fanout, 404 compare | Go fanout + ISPC similarity | `workers/go/dir.go`, `regex_util.ispc` | Rust only, 200 rps |
| T08 Crawl | link extract | ISPC regex_util | `regex_util.ispc` | Rust regex crate |
| T09 Secrets | pattern scan | ISPC + C++ vectorscan style | `regex_util.ispc` | Rust regex, slower |
| T14 Intruder | payload fanout | Go fanout + Rust async | `workers/go/fuzz.go` | Rust only |
| T16 Sniffer | capture + decode | eBPF + ISPC packet_decode | `sniff_filter.bpf.c`, `packet_decode.ispc` | libpcap pure + scalar |
| T19 Codec | bulk encode | ISPC base64 | `base64.ispc` | scalar |
| T20 Cracker | hash loop | CUDA + HIP + OpenCL + ISPC + AVX2 | `cuda/*.cu`, `opencl/*.cl`, `ispc/hash_cpu.ispc`, `simd/*` | scalar Rust, slow but correct |
| T21 Wordlist | mutate | ISPC word_mutate + Go stream | `word_mutate.ispc`, `workers/go/wordlist.go` | Rust iterator |
| T08/T17 CVE match | string match | ISPC + SQLite FTS | `regex_util.ispc` | SQL LIKE |

If GPU is missing, T20 must still run and must say so in UI: `GPU not found. Using CPU ISPC at X H/s`. Never show zero or fake speed.

## 5. UI/UX System, Full English

All visible copy is English. No other language in UI. No emdash in UI strings. Use hyphen - if needed.

### 5.1 Anti slop rules, enforced in review

Forbidden:
1. Purple blue gradients, heavy glass blur, decorative glow.
2. Large empty cards with generic illustration.
3. Hype copy such as revolutionary or next level. Use plain verbs.
4. Emoji as icons. Icons are 16 px line icons, consistent stroke.
5. Random radius and spacing. Radius is 6 px for panels, 4 px for inputs and buttons. Grid is 8 px.

Required:
1. Neutral ops palette. Tokens:
- bg0 #0B0E11, bg1 #11151A, bg2 #171C22, line #242C34
- text0 #E6EBF0, text1 #A7B1BC, text2 #6B7683
- primary single color: #3BA55D green ops. Secondary steel blue #2F81F7 only for links and info. Never gradient between them.
- danger #E5534B, warn #D29922, ok #3FB950, info #58A6FF
2. Two fonts only: Inter 13 px for UI, JetBrains Mono 12.5 px for data. Tabular numerals. Right align numbers.
3. Dense tables. Row height 28 px. Sticky header. Sortable columns. Row click opens Inspector.
4. Status uses dot plus text label, not color alone. Example: green dot plus text Open.
5. Focus ring visible for keyboard use. Contrast 4.5:1 minimum.

### 5.2 Global layout, English labels

```
+------------------------------------------------------------------+
| Topbar: Logo | Project: demo.clops | Scope: lab-only | Accel:   |
| CPU AVX2+ISPC GPU CUDA | Jobs: 2 | Rate: 50 rps | Cmd+K | Settings |
+--------+-------------------------------------------------+---------+
| Left   | Center tabs: Recon | Web | Network | Crack | Intel | Right |
| Trees  | Tool panel + live stats + result table          | Insp-   |
| Targets|                                                 | ector   |
| Results|                                                 | Details |
+--------+-------------------------------------------------+---------+
| Bottom: Jobs queue | Terminal log | Audit trail | Filter: [____]    |
+------------------------------------------------------------------+
```

Left tree labels: Targets, Subdomains, Ports, Services, Paths, Findings, Hashes, Wordlists, Chains, Reports.
Center tab groups: Recon, Web, Network, Crack, Intel, Report.
Right inspector title: Details.
Bottom tabs: Jobs, Logs, Audit.

Topbar badges use plain English: `Scope: lab-only`, `Safe Mode: ON`, `GPU: CUDA`, `CPU: ISPC AVX2`.

### 5.3 Standard tool panel pattern

Header row:
- Title, one line description, badge Safe or Full, Docs link.
- Example T03 header: `Port Scanner. Fast TCP scan with banner and version detection.`

Input row:
- Labels: `Target`, `Profile [Fast|Balanced|Deep|Lab]`, `Concurrency`, `Timeout`, `Rate limit`, buttons `Run` and `Stop`.

Live stats strip, English:
- `Elapsed 00:42 | Rate 812 rps | Found 37 | Errors 4 | Queue 963 | H/s 1.2M` for cracker.

Table actions:
- Right click: `Copy as cURL`, `Copy as JSON`, `Send to Repeater`, `Send to CVE Mapper`, `Mark false positive`.

Empty state copy, example:
- `No results yet. Enter a target in scope and press Run. Try the local lab: target 127.0.0.1 profile Lab.`

Settings dialog sections: General, Scope, Network, Acceleration, AI Provider, Storage, Updates. All English.

### 5.4 English copy bank, reuse exactly

- Run, Stop, Pause, Resume, Cancel, Retry, Export, Save to workspace, Clear, Copy, Filter, Search, Details, Evidence, Settings, Docs.
- Job states: Queued, Running, Paused, Cancelled, Done, Failed.
- Severity: Info, Low, Medium, High, Critical.
- Scope error: `Target outside scope. Add it to Project Scope first.`
- GPU notice: `GPU not found. Using CPU fallback.`
- Rate notice: `Rate limited by server (429). Backing off.`
- AI gate: `Approval required. Review step and press Approve to continue.`

## 6. Functional Spec per Tool, Detailed

### T01 Subdomain Enumerator

Goal: aggregate without key, then validate by resolve.

22 sources without key:
1. crt.sh JSON
2. Hackertarget hostsearch
3. Anubis DB mirror
4. RapidDNS scrape
5. URLScan public search
6. CertSpotter public API
7. DigiCert CT log
8. Google Transparency CT
9. CT mirror crackwatch style
10. ThreatCrowd mirror
11. AlienVault OTX web low rate
12. Netcraft light scrape
13. DNSDumpster scrape
14. Local DNS brute with built in list
15. Permutation: dev, staging, test, qa, uat, api, admin, beta, internal, prod
16. SAN feedback from T04
17. PTR sweep for small in scope ranges
18. CNAME fingerprint list
19. Wayback CDX hosts
20. Common Crawl index hosts
21. OTX plus URLScan relation graph
22. Anubis brute public endpoint

Pipeline: parallel fetch 12 sec timeout, 1 retry, lowercase normalize, wildcard probe with random token, resolve A, AAAA, CNAME with system plus DoH fallback, dedupe, tag source per entry.
Output columns: Subdomain, IP, CNAME, Source, Resolved, First seen.
Send to: T02, T03.

### T02 DNS Toolkit

Queries: A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, SRV optional.
AXFR check only if explicit lab scope, marked as sensitive action.
PTR batch for IP list.
DoH fallback to Cloudflare and Google if UDP 53 blocked.
Columns: Name, Type, Value, TTL, Latency ms, Server.
Export zone view per target.

### T03 Port Scanner + Banner, Real Time

Modes: Fast top 100, Standard top 1000, Full 1-65535 for lab only, Custom range, CIDR small.
Technique v1: full TCP connect. SYN raw optional in v1.1 with root and C module.
Concurrency 50 to 5000, default 500. Lab profile allows 5000.
Banner: read up to 4 KB, 3 sec timeout.
Probes in Lua `service_probes.lua`: HTTP, SSH, FTP, SMTP, POP3, IMAP, TLS SNI, DNS version.bind if allowed, Redis greeting without auth, MySQL greeting without auth, Mongo hello without auth, SMB banner light.
ISPC parse for common Server strings to keep UI under 300 ms per found row.
UI: rows appear live, sparkline Open vs Closed vs Filtered, per port timing.
Columns: Port, Proto, State, Service, Version, Banner snippet, Latency.
Send to: T04, T05, T17.

### T04 SSL/TLS Analyzer

Input host plus port, default 443.
Chain: leaf plus intermediates, hostname verify, expiry days left with color.
SAN list, issuer, subject, serial, sig algo, key size.
Protocols probed: TLS 1.0, 1.1, 1.2, 1.3.
Cipher offer list per active protocol.
HSTS check, HTTP to HTTPS redirect check, OCSP stapling, CRL reachable.
Heuristics: expired, self signed, hostname mismatch, SHA1 sig, RSA under 2048, TLS 1.0 on, weak DH under 2048, Heartbleed safe probe, POODLE note.
Grade A to F with transparent deduction list.
Send to: T01 for SAN feedback.

### T05 HTTP Fingerprint

Headers, Server, Powered By, WAF sigs: Cloudflare, Akamai, Imperva, Sucuri, ModSecurity, F5.
Tech via header plus meta plus JS libs: jQuery, React, Next, WordPress, Laravel, Django.
Audit: missing HSTS, CSP, X-Frame-Options, cookie missing Secure, HttpOnly, SameSite.
Store raw headers for T14.
Columns: Check, Value, Severity, Advice.

### T06 Cloud + Takeover Scanner, New

Buckets: S3 URL guess plus public access probe via HEAD, Azure blob, GCS, DigitalOcean Spaces. Read only probe, no upload.
Takeover: CNAME match against 30+ fingerprints in `takeover.lua`: Github Pages, Heroku, Azure, AWS S3 website, Netlify, Vercel, Shopify, Tumblr, Bitbucket, Fastly, Pantheon, Zendesk, Uservoice, Ghost, Helpjuice, etc.
Confidence: High if NXDOMAIN plus known dead CNAME, Medium if 404 with fingerprint string, Low if timeout.
Output never claims takeover, only `Possible takeover signal`.
Safe GET only.

### T07 Directory Bruteforcer

Input base URL, wordlist, extensions, status match list, auto 404 calibrate.
Calibrate: 3 random tokens, store length, hash, similarity threshold via ISPC.
Filters: status, length range, words, lines, regex.
429 backoff with jitter. Pause and resume with checkpoint offset.
Go sidecar for 1000 to 5000 rps in lab. Internet default cap 100 rps.
Columns: Path, Status, Length, Words, Time ms, Redirect.
Send to: T08, T09, T14.

### T08 Web Spider + Crawler, New

Seed URL plus depth max 3 default, max pages 2000 default.
Parse links, forms, JS src, sitemap.xml, robots.txt.
Respect scope domain only. No cross domain crawl unless added to scope.
ISPC fast link extract for large HTML.
Output: URL tree, Forms table with method and params, Assets list.
Send to: T09, T10, T11, T13.

### T09 Endpoint + Secret Extractor

Input: URL, HAR file, or T08 results.
Regex paths: slash API, query keys, S3 URLs, webhooks.
Secret patterns high precision only: AWS AKIA, Google API key, Slack xox, GitHub ghp, Stripe sk live, private key header, JWT.
Confidence High, Medium, Low. No vendor validation call in v1.
One click Send to Repeater.

### T10 SQLi Detector, Safe Only

No dump, no stacked destructive query.
Tests per param: quote, double quote, boolean true vs false, time sleep 2 sec max once per param with explicit approve for internet.
Sigs: MySQL, Postgres, MSSQL, Oracle, SQLite error strings in `sqli_errors.lua`.
Evidence: snippet plus response hash diff plus timing.
Columns: Param, Type, Payload ref, Evidence, Confidence.
Requires Safe Mode ON for internet targets.

### T11 XSS Scanner

Reflected only in v1. Stored is v2 backlog.
Contexts: HTML text, double attr, single attr, JS string, URL reflected.
Neutral markers `clopsXYZ` plus safe tag probe that does not execute without interaction.
Double send with different marker to cut false positives.
Columns: Param, Context, Reflected As, Encoded, Verdict.

### T12 LFI + Traversal + SSTI Tester

Traversal encoded variants plus `php://filter` meta check only in lab.
Markers: `root:x`, `[extensions]`, `win.ini` for Windows lab.
SSTI safe probe: `{{7*7}}` plus `#{7*7}` math check without code exec, look for `49` in safe context only.
No RCE, no upload, lab scope warning.

### T13 Misconfig Checker

CORS: wildcard ACAO, Origin reflection, credentials true combo flagged High.
Clickjacking: X-Frame-Options plus CSP frame-ancestors.
Cookies: Secure, HttpOnly, SameSite.
HSTS, CSP basic, server verbose leak, stacktrace, directory listing, `.git/HEAD` light check.
CWE mapped per finding with fix advice.

### T14 Request Repeater + Intruder

Raw editor with highlight for method, path, headers, body.
Resend with timing ms, hex view, rendered view, side by side diff.
Intruder: mark positions with `$1$`, load payload list, sniper mode in v1, pitchfork in v1.1.
History per target, filter by status and length.
Send to detectors T10 to T13.

### T15 Intercept Proxy, New

Local proxy default `127.0.0.1:8080`, CA install helper for lab only.
Scope filter: only in scope hosts are shown, rest bypassed.
History table with search, intercept ON and OFF toggle, forward, drop, edit and forward.
One click Send to Repeater.
No silent MITM outside scope. UI banner shows `Proxy active` clearly.

### T16 Packet Sniffer + PCAP Analyzer, New, Accelerated

Live capture on Linux with eBPF prefilter, plus libpcap fallback on Win and macOS.
Filters: host, port, proto, BPF string validated before apply.
ISPC decode for Ethernet, IPv4, IPv6, TCP, UDP, DNS basic, HTTP host sniff.
Parallel PCAP writer plus UI stream. Pause capture without losing file handle.
Offline mode: open `.pcap` and `.pcapng`, table plus flow summary plus DNS timeline.
Root needed for live capture. Offline parse works as normal user.

### T17 CVE Mapper, New

Offline DB `assets/cve/cve.sqlite` updated via script, no key.
Input: service plus version from T03 or manual.
Match: CPE style prefix match plus version range compare.
Output: CVE ID, CVSS, severity, summary, references, suggested next check in Cyber-Clops.
Never auto exploit. Button `Open in Chain Builder` for manual review.

### T18 Payload Generator, New

Reverse and bind shells for lab use: bash, python3, powershell, nc, php, java, plus msfvenom command hint if installed.
Inputs: LHOST, LPORT, type, encoding Base64 or URL.
Listener helper shows exact `nc -lvnp` command, does not auto listen without press.
Warning banner: `For authorized lab use only. Respect scope.`
Lua templates in `payloads/` so new shells added without rebuild.

### T19 Codec Lab, Accelerated

Hash ID for 30 types via length plus charset plus regex.
Codecs: Base64, Base64URL, Hex, URL, HTML entity, JWT decode without verify, Unix time, UUID v4.
Bulk mode for files up to 200 MB using ISPC base64 path.
Chain pipeline saved as preset: example Base64 then URL encode.

### T20 Hash Cracker, Fully Accelerated

30 plus types v1:
1. MD5 2. MD4 3. SHA1 4. SHA224 5. SHA256 6. SHA384 7. SHA512 8. SHA3-256 9. SHA3-512 10. RIPEMD160 11. BLAKE2b 12. BLAKE2s 13. NTLM 14. LM 15. MySQL41 16. Postgres MD5 17. MSSQL 2012 plus 18. SHA512crypt 19. apr1 MD5 20. bcrypt 21. scrypt 22. Argon2id 23. PBKDF2-HMAC-SHA256 24. Django PBKDF2 25. WordPress phpass 26. Joomla salted 27. HMAC-SHA256 28. NTHASH variant 29. Oracle 11g 30. Cisco Type 7 plus raw CRC32 helper.

Modes: Dictionary with rules, Mask with `?l ?u ?d ?s ?a` plus custom, Hybrid dict plus mask suffix, Benchmark mode.
Rules: lower, upper, capitalize, leet basic, append year 1970 to 2030.
GPU: CUDA and OpenCL for fast hashes MD5, SHA1, SHA256, NTLM first. Slow hashes bcrypt, scrypt, Argon2 stay CPU with clear cost note and honest ETA.
Benchmark at startup per type. ETA from measured H/s, not guess.
Checkpoint every 5 sec. Pause and resume. Found streams instantly.
UI stats: `H/s, Tested, Total, Progress %, ETA, Temp if available, Backend: CUDA or OpenCL or ISPC CPU`.
Acceptance: MD5 rockyou 10k sample on lab GPU under 5 sec. Same sample on CPU ISPC under 30 sec. bcrypt cost 10 runs slow with correct ETA and no UI freeze.

### T21 Wordlist Studio, Accelerated

Sources: built in small, user file, seeds from T01 and T07.
Ops: dedupe, sort, length filter, regex filter, combine two lists, mutate via Lua plus ISPC fast path.
Stats: count, unique, avg length, charset coverage, est. crack time per hash at current H/s.
Stream 1 GB plus without full RAM load via Go worker.
Export chunked files.

### T22 OSINT Toolkit, New

Username check against 15+ public profile URLs with 404 vs 200 plus content check, slow rate to avoid ban.
Email: format, MX check, Gravatar hash hint, breach local file match only, no paid API.
Breach: match against user provided local list, never upload.
Metadata: EXIF for user provided images, PDF author.
Wayback: CDX host and URL list for in scope domain.
All sources logged. No scraping behind login.

### T23 Chain Builder, New

No code DAG: nodes are tools T01 to T22, edges pass vars like `{{subdomains}}`, `{{open_ports}}`, `{{paths}}`.
Conditions: if found greater than N, branch. Loops over target list.
Vars panel plus dry run that shows planned steps without packets.
Save chains as YAML in workspace. Share via export.
Example chain `Recon to report`: T01, T02, T03, T04, T05, T07, T13, T25.

### T24 AI Auto Hacker, Gated

Input: in scope target plus goal: Recon only, Vuln mapping, Full suggestion chain.
Planner builds DAG from T01 to T23 nodes with risk per node.
Executor calls same deterministic engines. AI never opens sockets directly.
Gates: Low auto within rate, Medium and High need Approve click, Destructive blocked always.
Providers: Ollama local default, OpenAI compatible optional. Keys in OS keychain only.
Redact secrets from prompts and logs. Full replay per step.
Block log for out of scope or destructive request.

### T25 Report Center

Templates: Executive summary, Scope, Method, Findings by severity, Evidence with auto redact for cookies and tokens, Fix advice.
CVSS base plus CWE per finding.
Export HTML print ready, PDF via print CSS, JSON for machines.
Timeline: who ran what when, with job IDs.
Sign off field: Tester, Date, Scope hash.

## 7. Data Model

SQLite file `.clops.sqlite` per project. Raw large data as JSONL plus PCAP in project folder.

Tables: projects, targets, subdomains, dns_records, ports, services, tls_certs, paths, endpoints, vulns, hashes, wordlists, chains, ai_runs, proxy_history, pcap_flows, reports, jobs, audit_log.

Migrations versioned in `core/rust/migrations/`. Never break open of older project without migrate path.

## 8. Phased Build Plan

### Phase 0: Repo and Contracts, Week 1

0.1 Init monorepo and toolchain pin:
- Layout with `apps`, `core`, `native`, `workers`, `scripts`, `assets`, `tests`, `proto`.
- Pin Rust stable, CMake, Ninja, Go 1.22 plus, Lua 5.4, SDL3, OpenGL3, ISPC, CUDA Toolkit optional, OpenCL headers.
- Pre commit: fmt, clippy, gofmt, stylua, plus grep hook that rejects emdash and emoji in UI strings.

0.2 C ABI plus gRPC plus DB schema:
- `clops_core.h` for scan, dns, tls, http, hash, accel query.
- `clops.proto`: StartJob, StreamResult, Pause, Checkpoint, Cancel.
- SQLite v1 schema plus migrate 001.

0.3 Local lab:
- Docker lab: http dummy, dns fake, tls self signed, sqli dummy, xss dummy, proxy target, pcap sample, hash sample.
- Fixtures: banner samples, cert samples, wordlist tiny.

0.4 Accel skeleton:
- `dispatch.cpp` stub that reports CPU only, ISPC hello test, OpenCL query test, `nvcc --version` check script.
- Exit: `cargo test`, `go test`, `ctest` green. Empty GUI opens. Accel badge shows CPU only correctly.

### Phase 1: Platform GUI + Core, Week 2 to 3

1.1 GUI shell:
- SDL3 window, ImGui docking and viewports, Inter plus JetBrains Mono load, theme tokens.
- Topbar, left tree, center tabs, inspector, bottom Jobs Logs Audit drawer.
- Command palette Ctrl+K, full English copy, focus ring.
- Virtual table with 100k dummy rows at 60 fps.

1.2 Job system:
- Queue, cancel token under 500 ms, progress channel, global and per host limiter.
- Scope guard, audit JSONL, autosave 30 sec.

1.3 Lua sandbox:
- Safe loader, `clops.*` v1, example header inject and word mutate.
- Panel template `custom_tool.lua` renders simple form in GUI.

1.4 Accel badge wiring:
- Real CPU detect plus GPU query plumbed to Topbar. No mock text.
- Exit: dummy job run and stop, table smooth, badge honest.

### Phase 2: Recon T01 to T06, Week 4 to 6

2.1 T01 with 22 sources, cache 24h, wildcard filter, resolve validate.
2.2 T02 with DoH fallback and AXFR gate.
2.3 T03 with io_uring on Linux plus ISPC parse plus Lua probes plus live UI.
2.4 T04 with grade plus cipher enum.
2.5 T05 plus T06 takeover fingerprints plus bucket probes.
2.6 Click through: subdomain to ports to TLS to fingerprint to takeover.
- Exit: public in scope domain recon without key, no crash.

### Phase 3: Web T07 to T09 plus T14 and T08, Week 7 to 8

3.1 T07 with Go sidecar, 404 calibrate, checkpoint.
3.2 T08 crawl with sitemap and forms.
3.3 T09 secrets high precision plus send to Repeater.
3.4 T14 repeater plus diff plus history.
- Exit: hidden path plus dummy secret found in lab with low false positives.

### Phase 4: Detectors T10 to T13 plus Proxy T15, Week 9 to 10

4.1 Lua payload packs safe only with docs per payload.
4.2 T10 SQLi plus T11 XSS double send.
4.3 T12 traversal plus SSTI plus T13 misconfig with CWE.
4.4 T15 proxy with scope filter and send to Repeater.
4.5 Negative lab must stay clean. Zero High false positives.
- Exit: detectors pass positive and negative lab.

### Phase 5: Network T16 plus CVE T17 plus Payload T18, Week 11

5.1 T16 eBPF filter plus ISPC decode plus PCAP open.
5.2 T17 offline CVE import plus version match.
5.3 T18 templates plus listener helper.
- Exit: capture 10k packets in lab without drop in userspace, CVE map works offline.

### Phase 6: Crack Lab T19 to T21, Fully Wired, Week 12 to 13

6.1 T19 codec plus bulk ISPC path.
6.2 T20 dispatcher CUDA plus OpenCL plus HIP flag plus ISPC CPU plus checkpoint plus honest H/s.
- Build matrix: CPU only laptop, OpenCL iGPU, CUDA lab GPU.
6.3 T21 Go stream plus ISPC mutate plus ETA math from real H/s.
- Exit: MD5 and NTLM bench correct, bcrypt ETA honest, resume works after kill.

### Phase 7: Intel plus Automation plus AI T22 to T24, Week 14

7.1 T22 OSINT slow rate plus local breach match.
7.2 T23 DAG runtime plus dry run plus YAML save.
7.3 T24 planner plus gates plus Ollama default plus redact plus replay.
- Exit: AI builds Recon to report chain in lab with approvals logged.

### Phase 8: Report T25 plus Hardening plus Release, Week 15 to 16

8.1 T25 HTML PDF JSON plus redact plus timeline.
8.2 Hardening: fuzz HTTP, DNS, TLS, PCAP parsers with corpus. Caps on memory and time in all workers.
8.3 Packaging: Linux AppImage, Windows exe, SBOM, checksums. First run scope onboarding in English.
8.4 Perf QA: 100k rows 60 fps, T03 1000 ports lab under 20 sec balanced, T07 10k paths lab LAN under 60 sec, cancel under 500 ms.
- Exit: clean install passes 30 min smoke test. v2.0.0 tagged.

## 9. Repo Layout with Acceleration

```
Cyber-Clops/
  plan.md
  README.md
  CMakeLists.txt
  apps/gui/                 # C++ ImGui shell
  core/rust/                # orchestrator, engines, store, accel.rs
    src/accel.rs            # dispatcher client, bench, pick
    migrations/
  native/cpp/               # scalar + simd + dispatch host
    simd/
    dispatch/dispatch.cpp
  native/accel/
    cuda/md5.cu, sha1.cu, sha256.cu, ntlm.cu, maskgen.cu
    hip/md5.hip, sha256.hip
    opencl/md5.cl, sha1.cl, sha256.cl, ntlm.cl
    ispc/banner_parse.ispc, packet_decode.ispc, base64.ispc, word_mutate.ispc, hash_cpu.ispc, regex_util.ispc
  native/net/               # scan.c, pcap, uring helpers
    bpf/sniff_filter.bpf.c
  workers/go/               # dir.go, fuzz.go, wordlist.go, crawl queue
  scripts/lua/              # probes, payloads, takeover, waf, transforms
  proto/clops.proto
  assets/wordlist/
  assets/cve/
  assets/fonts/
  tests/lab/docker/
  tests/fixtures/
```

Rules: Rust never imports GUI. GUI only calls Core ABI. Go only via gRPC. Lua only via sandbox. Accel only via dispatcher. No direct CUDA call from UI.

## 10. Testing Strategy

- Unit: parsers, version regex, hash ID, 404 filter, ISPC vs scalar equivalence, CUDA vs CPU equivalence on small vectors.
- Integration: Docker lab per tool T01 to T18. PCAP fixtures for T16. Hash fixtures for T20.
- Perf: numbers in Phase 8 are release gates, not wishes.
- Safety: scope reject 100 percent, cancel under 500 ms, AI destructive block 100 percent, proxy outside scope bypass 100 percent.
- Security: no secret in logs, API keys only in keychain, report auto redact, PCAP path stays in project folder.

## 11. Build and Run

Linux dev:
- Install: Rust stable, CMake, Ninja, SDL3 dev, OpenGL, Go 1.22, Lua 5.4 dev, ISPC, OpenCL headers, CUDA Toolkit optional.
- Configure: `cmake -S . -B build -DCL_OPS_ENABLE_CUDA=ON -DCL_OPS_ENABLE_HIP=OFF`
- Build: `cmake --build build -j`
- Run: `./build/clops_gui`
- CPU only: `-DCL_OPS_ENABLE_CUDA=OFF` still builds and runs.

Windows dev:
- Same via winget plus Visual Studio 2022 plus CUDA optional. Proxy and PCAP need Npcap.

Env flags:
- `CLOPS_ACCEL=cuda|opencl|cpu` force backend for test.
- `CLOPS_LAB=1` enables Lab profile with high rates. Never default ON.

## 12. Risks and Mitigations

1. Public source HTML changes: each source is a Lua module with cache and fallback. Update without rebuild.
2. GPU driver variance: runtime detect plus OpenCL cache plus CPU fallback. UI never claims missing GPU.
3. Target rate block: polite defaults, 429 backoff, Lab profile isolated to lab scope.
4. False positives: dual send, confidence labels, negative lab gate.
5. Misuse: scope guard mandatory, Safe Mode default, audit always on, legal notice on first run in English.
6. eBPF permission: clear error `Live capture needs root or CAP_NET_RAW. Use offline PCAP mode.` plus one click switch.
7. CUDA build fragility: CI compile check plus CPU only release artifact always available.

## 13. Definition of Done for v2

- 25 tools open from GUI without CLI.
- Recon works without key for in scope public domain.
- Port rows stream live with version in under 300 ms per found row.
- T16 captures live on Linux and parses PCAP offline on all OS.
- 30 hash types identified. T20 runs on CUDA if present, else OpenCL, else ISPC CPU, with true H/s shown.
- Topbar accel badge always matches real backend.
- Report HTML plus JSON export from one workspace.
- No emdash in UI and docs. Pass grep hook.
- All UI copy English. Pass copy lint.
- No purple gradient and no emoji icons. Pass design review.

## 14. Next Steps

1. Approve v2 tool list and accel stack.
2. Scaffold repo with accel dirs and lab.
3. Start Phase 0.1 to 0.4.
4. Build T01 and T03 first as demo backbone, then T20 dispatcher stub with CPU path so GPU work can land in parallel.

---
Style note: this doc uses hyphen - and commas only. It avoids emdash by rule. Foreign terms use plain Latin for searchability.
