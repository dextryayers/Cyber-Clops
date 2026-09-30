#pragma once
// Fast service probe in C. No sockets here, pure banner and port logic.
// Mirrors Rust scan::guess_service so C and Rust agree byte for byte.
#ifdef __cplusplus
extern "C" {
#endif
// service_out gets ssh, ftp-or-smtp, http, https or unknown.
// version_out gets the first banner line for ssh and ftp-or-smtp, else empty.
// Returns 0 on success, -1 on bad args.
int clops_identify_service(const char* banner, int port,
                           char* service_out, int service_cap,
                           char* version_out, int version_cap);
#ifdef __cplusplus
}
#endif
