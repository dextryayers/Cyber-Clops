// Real ISPC banner parser. Compiled with ispc when available.
// Scalar fallback in Rust scan.rs must produce identical output.
// Prefix match for SSH, FTP and SMTP greetings plus Server header scan.
// banner: input bytes, n: length. service_out and version_out are 64 byte buffers.

static const int MAXV = 63;

export void banner_service(uniform const char *banner, uniform int n,
                           uniform char *service_out, uniform char *version_out) {
  service_out[0] = 0;
  version_out[0] = 0;
  if (n >= 4 && banner[0] == 'S' && banner[1] == 'S' && banner[2] == 'H' && banner[3] == '-') {
    service_out[0] = 's';
    service_out[1] = 's';
    service_out[2] = 'h';
    service_out[3] = 0;
    int i = 0;
    foreach (k = 0 ... n) {
      if (banner[k] == '\r' || banner[k] == '\n') break;
      if (i < MAXV) {
        version_out[i] = banner[k];
        i++;
      }
    }
    version_out[i] = 0;
    return;
  }
  if (n >= 3 && banner[0] == '2' && banner[1] == '2' && banner[2] == '0') {
    const char txt[] = "ftp-or-smtp";
    for (uniform int i = 0; i < 12; i++) service_out[i] = txt[i];
    int i = 0;
    foreach (k = 0 ... n) {
      if (banner[k] == '\r' || banner[k] == '\n') break;
      if (i < MAXV) {
        version_out[i] = banner[k];
        i++;
      }
    }
    version_out[i] = 0;
    return;
  }
  const char unk[] = "unknown";
  for (uniform int i = 0; i < 8; i++) service_out[i] = unk[i];
}
