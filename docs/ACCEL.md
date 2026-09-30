# Acceleration Badge - Phase 1.4
Real probe output from this laptop, 2026-09-30.

```json
{
  "cpu": "x86_64 AVX2",
  "avx2": true,
  "avx512": false,
  "ispc": false,
  "opencl_platforms": 1,
  "cuda": false,
  "backend": "OpenCL",
  "md5_hs": 1005380,
  "sha256_hs": 234000
}
```

## Wiring
- Rust accel::detect runs at startup: CPUID via std::arch, OpenCL via clinfo parse, CUDA via nvidia-smi plus driver path, bench 200 ms per hash.
- C ABI clops_accel_json returns the same JSON for the C++ Topbar.
- Topbar shows: CPU: x86_64 AVX2, GPU: None CPU only, Backend: OpenCL.
- Honest rule: if GPU missing, UI says so. No fake speed.
- Full CUDA and OpenCL kernels land in Phase 6. Dispatcher interface is frozen now.
