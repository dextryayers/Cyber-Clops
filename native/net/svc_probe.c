#include "svc_probe.h"
#include <string.h>
#include <stdio.h>

static void first_line(const char* banner, char* out, int cap) {
  if (cap <= 0) return;
  int i = 0;
  while (banner[i] && banner[i] != '\r' && banner[i] != '\n' && i < cap - 1) {
    out[i] = banner[i];
    i++;
  }
  out[i] = 0;
}

static int is_http_port(int port) {
  return port == 80 || port == 8000 || port == 8080 || port == 18080 ||
         port == 443 || port == 8443 || port == 18443 ||
         port == 3000 || port == 5000 || port == 9000;
}

static int is_tls_port(int port) {
  return port == 443 || port == 8443 || port == 18443;
}

int clops_identify_service(const char* banner, int port,
                           char* service_out, int service_cap,
                           char* version_out, int version_cap) {
  if (!service_out || service_cap <= 0 || !version_out || version_cap <= 0) return -1;
  if (!banner) banner = "";
  service_out[0] = 0;
  version_out[0] = 0;
  if (strncmp(banner, "SSH-", 4) == 0) {
    snprintf(service_out, (size_t)service_cap, "ssh");
    first_line(banner, version_out, version_cap);
    return 0;
  }
  if (strncmp(banner, "220", 3) == 0) {
    snprintf(service_out, (size_t)service_cap, "ftp-or-smtp");
    first_line(banner, version_out, version_cap);
    return 0;
  }
  if (is_http_port(port)) {
    snprintf(service_out, (size_t)service_cap, is_tls_port(port) ? "https" : "http");
    // Banner driven version only when the banner itself carries a Server token.
    const char* s = strstr(banner, "Server:");
    if (s) {
      s += 7;
      while (*s == ' ') s++;
      int i = 0;
      while (s[i] && s[i] != '\r' && s[i] != '\n' && i < version_cap - 1) {
        version_out[i] = s[i];
        i++;
      }
      version_out[i] = 0;
    }
    return 0;
  }
  snprintf(service_out, (size_t)service_cap, "unknown");
  return 0;
}
