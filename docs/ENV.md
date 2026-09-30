# Environment Audit - Phase 0.1.0
Date: 2026-09-30
Host: Kali Linux 7.1.5 amd64, AMD Ryzen 7 5700U 16 threads

## Toolchains found
- Rust 1.95.0 with Cargo: OK. Pinned to 1.95.0 in rust-toolchain.toml.
- CMake 4.3.4 + Ninja 1.13.2: OK.
- Go 1.26.7: OK.
- Python 3.14.7: OK, used for lab helpers.
- OpenSSL 3.6.3: OK.
- X11 + GL dev headers: OK.
- SQLite 3.53.4: OK.
- OpenCL runtime POCL 7.1: OK for CPU OpenCL. Headers missing, so CMake links OpenCL only if found, else runtime dlopen path.
- SDL3 runtime 3.4.16 present, dev headers missing, no sudo. Solution: FetchContent builds SDL3 from source, no sudo needed.

## Missing, handled honestly
- Lua binary: not installed. Handled by Rust mlua with vendored Lua 5.4, no system dep. Lua scripts run through core.
- ISPC: not installed. Dispatcher reports CLOPS_HAS_ISPC=0 and uses scalar plus Rust path. Benchmark still runs to prove honest speed.
- nvcc CUDA: not installed. Default CL_OPS_ENABLE_CUDA=OFF. Topbar shows GPU: None CPU only. CUDA sources ship but do not break CPU build.
- protoc: not installed. Proto file is contract, Go sidecar uses JSON over localhost HTTP for Phase 0 and 1, gRPC codegen lands when protoc is available.
- crt.sh live: returned 502 during audit. T01 implements retry plus 22 sources so one source down does not fail the job. Real case test uses example.com plus local lab.

## Real targets selected for Phase 0 and 1
1. Local lab 127.0.0.1 with Python http server on 18080 and 18443 self signed.
2. example.com ports 80 and 443 only, rate capped, polite profile. DNS resolve verified via dig during audit.
3. Subdomain enumeration for example.com with cache, to prove no-key path without hammering sources.

## Decisions
- CPU first build must pass without GPU, without ISPC, without SDL dev.
- GUI build fetches SDL3 and ImGui docking via CMake FetchContent.
- All UI copy English only. No emdash in code or docs, enforced by pre-commit hook.
