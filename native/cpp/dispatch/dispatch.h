#pragma once
// Stable C ABI for Rust and GUI. No C++ types here.
// All strings UTF-8. Caller frees result JSON with clops_free.

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  int port;
  int open;           // 1 open, 0 closed
  char service[64];
  char version[128];
  char banner[512];
  int latency_ms;
} ClopsPortResult;

// TCP connect scan with timeout. Returns number of open ports written.
int clops_scan_ports(const char* host, const int* ports, int n_ports,
                     int timeout_ms, ClopsPortResult* out, int out_cap);

// Banner grab for one host port. Returns bytes written or negative on error.
int clops_banner_grab(const char* host, int port, int timeout_ms,
                      char* out, int out_cap);

// CPU feature query. Returns 1 if present.
int clops_cpu_has_avx2(void);
int clops_cpu_has_avx512(void);
int clops_has_ispc_runtime(void);
int clops_has_opencl_runtime(void);
int clops_has_cuda_runtime(void);

// OpenCL runtime query without link time headers.
// Returns platform count, or 0 if none, or negative if loader missing.
int clops_opencl_platform_count(void);

// Throughput bench of the scalar core. Returns hashes per second.
unsigned long clops_bench_md5_hs(int ms_budget);
unsigned long clops_bench_sha256_hs(int ms_budget);

// One shot digests for short messages under 64 bytes. Returns 0 on success.
int clops_md5_once(const unsigned char* msg, int len, unsigned char out16[16]);
int clops_sha256_once(const unsigned char* msg, int len, unsigned char out32[32]);

// CPU brand string. Returns 0 on success.
int clops_cpu_brand(char* out, int out_cap);

// Free for JSON strings allocated by Rust FFI.
void clops_free(char* p);

#ifdef __cplusplus
}
#endif
