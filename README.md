# Cyber-Clops Cyber Kit v2
Native desktop security toolkit. 25 tools, one workspace, full English UI.

## Quick start, CPU only, no sudo needed

```sh
# Rust core tests, real localhost + example.com polite checks
cargo test -p clops-core -- --nocapture

# Go worker
go -C workers/go test ./...

# Native CPU configure, GUI fetches SDL3 + ImGui automatically
cmake --preset dev
cmake --build build/dev -j
./build/dev/clops_gui
```

Headless without GUI:

```sh
cmake --preset headless
cmake --build build/headless -j
ctest --test-dir build/headless -V
```

## Layout
- apps/gui: Dear ImGui SDL3 OpenGL3 shell
- core/rust: orchestrator, jobs, scope, store, accel detect, real scan engines
- native: C scan, C++ dispatch, accel cuda hip opencl ispc, eBPF filter
- workers/go: dir brute and wordlist stream sidecar
- scripts/lua: probes, payloads, takeover fingerprints
- proto/clops.proto: contract for Go sidecar
- assets/wordlist: small built in lists
- tests/lab: local lab targets, real case only

## Rules
- UI English only.
- No emdash character in code or docs. Use hyphen -.
- Safe Mode ON by default. Scope guard cannot be disabled from UI.
- GPU is optional. Topbar always shows real backend.
