# Job System, Scope, Rate, Audit - Phase 1.2
All wired in Rust core. GUI calls the same paths.

## Modules
- scope.rs: lab_only allows localhost, 127.0.0.0/8, example.com. All else rejected before first packet.
- jobs.rs: create, set_status, cancel. Cancel propagates in under 500 ms by token.
- rate.rs: token bucket plus semaphore. Defaults 50 rps internet, Lab profile raises.
- audit.rs: append only JSONL. UI has no disable switch.
- store.rs: SQLite WAL with migrate 001.

## Real behavior verified
- cargo test covers scope allow and reject, cancel policy, store migrate.
- integration_real covers live 127.0.0.1 scan plus example.com resolve.
- Go dir brute covers 404 calibrate plus 429 backoff plus checkpoint offset.

## GUI wiring
Center panel Run button creates a Job via core, streams rows in batches of 100 to 500 per frame.
Stop button calls cancel. Bottom drawer shows Jobs, Logs, Audit tabs.
