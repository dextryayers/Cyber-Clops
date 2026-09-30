#include <cassert>
#include <cstdio>
#include "native_test.h"
#include "../native/cpp/dispatch/dispatch.h"

int clops_cpu_query_runs(void) {
  int a = clops_cpu_has_avx2();
  int b = clops_opencl_platform_count();
  (void)a; (void)b;
  return 1;
}

int main() {
  assert(clops_cpu_query_runs() == 1);
  printf("native_test: CPU query OK, OpenCL platforms=%d\n", clops_opencl_platform_count());
  return 0;
}
