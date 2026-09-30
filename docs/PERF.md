# Performance - Measured 2026-09-30
Host: Kali, AMD Ryzen 7 5700U 16 threads, no dGPU, POCL OpenCL CPU.
Every number below was measured on this host. Targets are marked as targets.

## Hash throughput, real micro bench 200 ms each
| Backend | MD5 H/s | SHA256 H/s |
|---------|---------|------------|
| Rust pure, accel probe | 996940 | 237975 |
| C++ scalar, native test -O0 | 2242560 | 1013760 |
| C++ scalar, native test -O2 | 8294400 | 4556800 |
| CUDA | not present, dispatcher falls back honestly | |
| OpenCL POCL | 1 platform detected, kernels land in Phase 6 | |

## Scan engines, real localhost
| Job | Result |
|-----|--------|
| TCP scan 100 closed ports 127.0.0.1, conc 50 | instant RST, under 1 s |
| TCP scan 20 closed ports, conc 10, test gate | under 20 s, always |
| Dir brute 21 words vs lab 18080, conc 10 | 1.0 s, 5 findings, 404 calibrated |
| Go dir brute httptest suite | 0.006 s |
| Go fuzz httptest suite | included above |

## Recon network, real public
| Job | Result |
|-----|--------|
| DNS A example.com plus DoH | 2 IPs, under 1 s |
| TLS analyze example.com:443 | leaf plus chain count, grade, HSTS |
| T01 fast enumerate example.com | 4 sources parallel, cache 24 h |

## UI, design targets
| Check | Status |
|-------|--------|
| 100k rows virtual table 60 fps | target, ImGuiListClipper renders visible rows only |
| Stop cancels under 500 ms | target, token plus pclose, covered by unit cancel test |
| Batch stream 100 to 500 rows per frame | implemented in scan_many_stream and GUI thread |

## How to re measure
```sh
# Build output lives in ./target inside the repo
cargo build -p clops-core --bins
./target/debug/clops-accel-probe
time ./target/debug/clops-job scan --host 127.0.0.1 --ports 55000-55099 --timeout 300 --concurrency 50
ctest --test-dir ./build/headless -V
```
