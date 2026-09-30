#pragma once
#ifdef __cplusplus
extern "C" {
#endif
int clops_scan_ports(const char* host, const int* ports, int n_ports, int timeout_ms, void* out, int out_cap);
int clops_banner_grab(const char* host, int port, int timeout_ms, char* out, int out_cap);
#ifdef __cplusplus
}
#endif
