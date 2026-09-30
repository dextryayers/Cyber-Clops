#include <cassert>
#include <cstdio>
#include <cstring>
#include "native_test.h"
#include "../native/cpp/dispatch/dispatch.h"
#include "../native/net/scan.h"
#include "../native/net/svc_probe.h"

static void hex_of(const unsigned char* b, int n, char* out) {
  for (int i = 0; i < n; i++) sprintf(out + i * 2, "%02x", b[i]);
  out[n * 2] = 0;
}

int clops_cpu_query_runs(void) {
  int a = clops_cpu_has_avx2();
  int b = clops_opencl_platform_count();
  (void)a;
  (void)b;
  return 1;
}

int main() {
  assert(clops_cpu_query_runs() == 1);
  printf("native_test: CPU query OK, OpenCL platforms=%d\n", clops_opencl_platform_count());

  // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
  unsigned char md5[16];
  assert(clops_md5_once((const unsigned char*)"abc", 3, md5) == 0);
  char hex[33];
  hex_of(md5, 16, hex);
  assert(strcmp(hex, "900150983cd24fb0d6963f7d28e17f72") == 0);
  printf("native_test: MD5 vector OK\n");

  // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  unsigned char sha[32];
  assert(clops_sha256_once((const unsigned char*)"abc", 3, sha) == 0);
  char hex64[65];
  hex_of(sha, 32, hex64);
  assert(strcmp(hex64, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
  printf("native_test: SHA256 vector OK\n");

  unsigned long mhs = clops_bench_md5_hs(100);
  unsigned long shs = clops_bench_sha256_hs(100);
  assert(mhs > 1000 && shs > 1000);
  printf("native_test: bench MD5=%lu H/s SHA256=%lu H/s\n", mhs, shs);

  char brand[64];
  assert(clops_cpu_brand(brand, sizeof(brand)) == 0 && brand[0] != 0);
  printf("native_test: CPU brand=%s\n", brand);

  char svc[32], ver[128];
  assert(clops_identify_service("SSH-2.0-OpenSSH_9.2 lab\r\n", 22, svc, sizeof(svc), ver, sizeof(ver)) == 0);
  assert(strcmp(svc, "ssh") == 0);
  assert(clops_identify_service("220 lab ftp ready\r\n", 21, svc, sizeof(svc), ver, sizeof(ver)) == 0);
  assert(strcmp(svc, "ftp-or-smtp") == 0);
  assert(clops_identify_service("", 80, svc, sizeof(svc), ver, sizeof(ver)) == 0);
  assert(strcmp(svc, "http") == 0);
  assert(clops_identify_service("", 9999, svc, sizeof(svc), ver, sizeof(ver)) == 0);
  assert(strcmp(svc, "unknown") == 0);
  printf("native_test: svc_probe OK\n");

  // scan.h links: banner grab against closed port must not crash
  char b[64];
  int r = clops_banner_grab("127.0.0.1", 1, 300, b, sizeof(b));
  assert(r <= 0 || b[0] != 0);
  printf("native_test: scan link OK\n");
  return 0;
}
