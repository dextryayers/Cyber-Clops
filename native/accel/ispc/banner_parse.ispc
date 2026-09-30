// ISPC banner parser. Compiled with ispc when available.
// Scalar fallback in Rust must produce identical output.
export void banner_service(uniform const char *banner, uniform char *service_out, uniform char *version_out) {
  // Phase 0: prefix match for SSH, FTP, SMTP, HTTP. Full regex set lands in Phase 2.
  service_out[0] = 0;
  version_out[0] = 0;
}
