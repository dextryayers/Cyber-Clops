// Scalar MD5 and SHA256 compression plus honest throughput bench.
// Standard algorithms: RFC 1321 MD5, FIPS 180-4 SHA256.
// Verified against "abc" vectors in the native test.
#include <stdint.h>
#include <string.h>
#include <chrono>

namespace {

inline uint32_t rotl(uint32_t x, uint32_t n) {
  return (x << n) | (x >> (32 - n));
}
inline uint32_t rotr(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

// ---- MD5 ----
static const uint32_t MD5_S[64] = {
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};
static const uint32_t MD5_K[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

void md5_compress(uint32_t st[4], const uint8_t blk[64]) {
  uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
  uint32_t m[16];
  for (int i = 0; i < 16; i++) {
    m[i] = (uint32_t)blk[i * 4] | ((uint32_t)blk[i * 4 + 1] << 8) |
           ((uint32_t)blk[i * 4 + 2] << 16) | ((uint32_t)blk[i * 4 + 3] << 24);
  }
  for (int i = 0; i < 64; i++) {
    uint32_t f;
    int g;
    if (i < 16) {
      f = (b & c) | (~b & d);
      g = i;
    } else if (i < 32) {
      f = (d & b) | (~d & c);
      g = (5 * i + 1) % 16;
    } else if (i < 48) {
      f = b ^ c ^ d;
      g = (3 * i + 5) % 16;
    } else {
      f = c ^ (b | ~d);
      g = (7 * i) % 16;
    }
    f += a + MD5_K[i] + m[g];
    a = d;
    d = c;
    c = b;
    b += rotl(f, MD5_S[i]);
  }
  st[0] += a;
  st[1] += b;
  st[2] += c;
  st[3] += d;
}

void md5_once(const uint8_t* msg, size_t len, uint8_t out[16]) {
  uint32_t st[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
  uint8_t blk[64] = {0};
  size_t n = len < 56 ? len : 56;
  if (len < 64) n = len;
  memcpy(blk, msg, n);
  blk[n] = 0x80;
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++) blk[56 + i] = (uint8_t)(bits >> (8 * i));
  // Messages of 56 bytes or more need two blocks. Bench input stays short.
  if (len >= 56 && len < 64) {
    md5_compress(st, blk);
    memset(blk, 0, 64);
    for (int i = 0; i < 8; i++) blk[56 + i] = (uint8_t)(bits >> (8 * i));
  }
  md5_compress(st, blk);
  for (int i = 0; i < 4; i++) {
    out[i * 4] = (uint8_t)st[i];
    out[i * 4 + 1] = (uint8_t)(st[i] >> 8);
    out[i * 4 + 2] = (uint8_t)(st[i] >> 16);
    out[i * 4 + 3] = (uint8_t)(st[i] >> 24);
  }
}

// ---- SHA256 ----
static const uint32_t SHA_K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void sha256_compress(uint32_t st[8], const uint8_t blk[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
           ((uint32_t)blk[i * 4 + 2] << 8) | blk[i * 4 + 3];
  }
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
  uint32_t e = st[4], f = st[5], g = st[6], h = st[7];
  for (int i = 0; i < 64; i++) {
    uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + s1 + ch + SHA_K[i] + w[i];
    uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = s0 + mj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  st[0] += a;
  st[1] += b;
  st[2] += c;
  st[3] += d;
  st[4] += e;
  st[5] += f;
  st[6] += g;
  st[7] += h;
}

void sha256_once(const uint8_t* msg, size_t len, uint8_t out[32]) {
  uint32_t st[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  uint8_t blk[64] = {0};
  size_t n = len < 56 ? len : 56;
  if (len < 64) n = len;
  memcpy(blk, msg, n);
  blk[n] = 0x80;
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++) blk[63 - i] = (uint8_t)(bits >> (8 * i));
  if (len >= 56 && len < 64) {
    sha256_compress(st, blk);
    memset(blk, 0, 64);
    for (int i = 0; i < 8; i++) blk[63 - i] = (uint8_t)(bits >> (8 * i));
  }
  sha256_compress(st, blk);
  for (int i = 0; i < 8; i++) {
    out[i * 4] = (uint8_t)(st[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(st[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(st[i] >> 8);
    out[i * 4 + 3] = (uint8_t)st[i];
  }
}

}  // namespace

extern "C" {

unsigned long clops_bench_md5_hs(int ms_budget) {
  if (ms_budget <= 0) ms_budget = 200;
  uint8_t blk[64];
  for (int i = 0; i < 64; i++) blk[i] = (uint8_t)(i * 7 + 1);
  uint32_t st[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
  unsigned long n = 0;
  auto t0 = std::chrono::steady_clock::now();
  for (;;) {
    uint32_t s[4] = {st[0], st[1], st[2], st[3]};
    md5_compress(s, blk);
    blk[0]++;
    n++;
    if ((n & 1023) == 0) {
      auto dt = std::chrono::steady_clock::now() - t0;
      if (std::chrono::duration_cast<std::chrono::milliseconds>(dt).count() >= ms_budget) break;
    }
  }
  auto ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
  if (ms <= 0) return n;
  return (unsigned long)((double)n * 1000.0 / (double)ms);
}

unsigned long clops_bench_sha256_hs(int ms_budget) {
  if (ms_budget <= 0) ms_budget = 200;
  uint8_t blk[64];
  for (int i = 0; i < 64; i++) blk[i] = (uint8_t)(i * 13 + 3);
  unsigned long n = 0;
  auto t0 = std::chrono::steady_clock::now();
  for (;;) {
    uint32_t s[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    sha256_compress(s, blk);
    blk[0]++;
    n++;
    if ((n & 1023) == 0) {
      auto dt = std::chrono::steady_clock::now() - t0;
      if (std::chrono::duration_cast<std::chrono::milliseconds>(dt).count() >= ms_budget) break;
    }
  }
  auto ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
  if (ms <= 0) return n;
  return (unsigned long)((double)n * 1000.0 / (double)ms);
}

int clops_md5_once(const unsigned char* msg, int len, unsigned char out16[16]) {
  if (!msg || len < 0 || len >= 64 || !out16) return -1;
  md5_once(msg, (size_t)len, out16);
  return 0;
}

int clops_sha256_once(const unsigned char* msg, int len, unsigned char out32[32]) {
  if (!msg || len < 0 || len >= 64 || !out32) return -1;
  sha256_once(msg, (size_t)len, out32);
  return 0;
}

int clops_cpu_brand(char* out, int out_cap) {
  if (!out || out_cap <= 0) return -1;
#if defined(__x86_64__) || defined(_M_X64)
#if defined(__GNUC__) || defined(__clang__)
  unsigned int regs[12] = {0};
  unsigned int* p = regs;
  for (int leaf = (int)0x80000002; leaf <= (int)0x80000004; leaf++) {
    unsigned int a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(leaf), "c"(0));
    *p++ = a;
    *p++ = b;
    *p++ = c;
    *p++ = d;
  }
  char brand[49];
  memcpy(brand, regs, 48);
  brand[48] = 0;
  // trim spaces
  int s = 0;
  while (brand[s] == ' ') s++;
  int e = 48;
  while (e > s && brand[e - 1] == ' ') e--;
  brand[e] = 0;
  snprintf(out, (size_t)out_cap, "%s", brand + s);
  return 0;
#else
  snprintf(out, (size_t)out_cap, "x86_64");
  return 0;
#endif
#else
  snprintf(out, (size_t)out_cap, "unknown-arch");
  return 0;
#endif
}

}  // extern C
