#include "dispatch.h"
#include <cstring>
#if defined(__x86_64__) || defined(_M_X64)
#if defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif
#endif
#ifdef __linux__
#include <dlfcn.h>
#endif

int clops_cpu_has_avx2(void) {
#if defined(__GNUC__) || defined(__clang__)
#if defined(__x86_64__)
  return __builtin_cpu_supports("avx2") ? 1 : 0;
#else
  return 0;
#endif
#else
  return 0;
#endif
}

int clops_cpu_has_avx512(void) {
#if defined(__GNUC__) || defined(__clang__)
#if defined(__x86_64__)
  return __builtin_cpu_supports("avx512f") ? 1 : 0;
#else
  return 0;
#endif
#else
  return 0;
#endif
}

int clops_has_ispc_runtime(void) {
#ifdef CLOPS_HAS_ISPC
  return CLOPS_HAS_ISPC;
#else
  return 0;
#endif
}

int clops_has_opencl_runtime(void) {
  return clops_opencl_platform_count() > 0 ? 1 : 0;
}

int clops_has_cuda_runtime(void) {
#ifdef CLOPS_HAS_CUDA
  return 1;
#else
#ifdef __linux__
  void* h = dlopen("libcuda.so.1", RTLD_LAZY);
  if (h) { dlclose(h); return 1; }
#endif
  return 0;
#endif
}

int clops_opencl_platform_count(void) {
#ifdef __linux__
  void* h = dlopen("libOpenCL.so.1", RTLD_LAZY);
  if (!h) return -1;
  typedef int (*Q)(unsigned int, void*, unsigned int*);
  // clGetPlatformIDs is looked up at runtime so no link headers are needed.
  Q fn = (Q)dlsym(h, "clGetPlatformIDs");
  if (!fn) { dlclose(h); return -1; }
  unsigned int n = 0;
  if (fn(0, 0, &n) != 0) { dlclose(h); return -1; }
  dlclose(h);
  return (int)n;
#else
  return 0;
#endif
}

void clops_free(char* p) { delete[] p; }
