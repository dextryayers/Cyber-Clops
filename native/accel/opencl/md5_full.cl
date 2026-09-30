// Real MD5 batch kernel for OpenCL 1.2 plus devices.
// Build at runtime via clCreateProgramWithSource, cached in ~/.cache/clops/kernels.
// Same interface as the CUDA kernel. RFC 1321 constants.
// Verified against vector 900150983cd24fb0d6963f7d28e17f72.

uint rotl32(uint x, uint n) {
  return (x << n) | (x >> (32u - n));
}

void md5_compress(__private uint st[4], __private const uchar blk[64]) {
  const uint S[64] = {
    (uint)7, (uint)12, (uint)17, (uint)22, (uint)7, (uint)12, (uint)17, (uint)22,
    (uint)7, (uint)12, (uint)17, (uint)22, (uint)7, (uint)12, (uint)17, (uint)22,
    (uint)5, (uint)9, (uint)14, (uint)20, (uint)5, (uint)9, (uint)14, (uint)20,
    (uint)5, (uint)9, (uint)14, (uint)20, (uint)5, (uint)9, (uint)14, (uint)20,
    (uint)4, (uint)11, (uint)16, (uint)23, (uint)4, (uint)11, (uint)16, (uint)23,
    (uint)4, (uint)11, (uint)16, (uint)23, (uint)4, (uint)11, (uint)16, (uint)23,
    (uint)6, (uint)10, (uint)15, (uint)21, (uint)6, (uint)10, (uint)15, (uint)21,
    (uint)6, (uint)10, (uint)15, (uint)21, (uint)6, (uint)10, (uint)15, (uint)21,
  };
  const uint K[64] = {
    (uint)0xd76aa478, (uint)0xe8c7b756, (uint)0x242070db, (uint)0xc1bdceee,
    (uint)0xf57c0faf, (uint)0x4787c62a, (uint)0xa8304613, (uint)0xfd469501,
    (uint)0x698098d8, (uint)0x8b44f7af, (uint)0xffff5bb1, (uint)0x895cd7be,
    (uint)0x6b901122, (uint)0xfd987193, (uint)0xa679438e, (uint)0x49b40821,
    (uint)0xf61e2562, (uint)0xc040b340, (uint)0x265e5a51, (uint)0xe9b6c7aa,
    (uint)0xd62f105d, (uint)0x02441453, (uint)0xd8a1e681, (uint)0xe7d3fbc8,
    (uint)0x21e1cde6, (uint)0xc33707d6, (uint)0xf4d50d87, (uint)0x455a14ed,
    (uint)0xa9e3e905, (uint)0xfcefa3f8, (uint)0x676f02d9, (uint)0x8d2a4c8a,
    (uint)0xfffa3942, (uint)0x8771f681, (uint)0x6d9d6122, (uint)0xfde5380c,
    (uint)0xa4beea44, (uint)0x4bdecfa9, (uint)0xf6bb4b60, (uint)0xbebfbc70,
    (uint)0x289b7ec6, (uint)0xeaa127fa, (uint)0xd4ef3085, (uint)0x04881d05,
    (uint)0xd9d4d039, (uint)0xe6db99e5, (uint)0x1fa27cf8, (uint)0xc4ac5665,
    (uint)0xf4292244, (uint)0x432aff97, (uint)0xab9423a7, (uint)0xfc93a039,
    (uint)0x655b59c3, (uint)0x8f0ccc92, (uint)0xffeff47d, (uint)0x85845dd1,
    (uint)0x6fa87e4f, (uint)0xfe2ce6e0, (uint)0xa3014314, (uint)0x4e0811a1,
    (uint)0xf7537e82, (uint)0xbd3af235, (uint)0x2ad7d2bb, (uint)0xeb86d391,
  };
  uint a = st[0], b = st[1], c = st[2], d = st[3];
  uint m[16];
  for (int i = 0; i < 16; i++) {
    m[i] = ((uint)blk[i * 4]) | ((uint)blk[i * 4 + 1] << 8) |
           ((uint)blk[i * 4 + 2] << 16) | ((uint)blk[i * 4 + 3] << 24);
  }
  for (int i = 0; i < 64; i++) {
    uint f;
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
    f += a + K[i] + m[g];
    a = d;
    d = c;
    c = b;
    b += rotl32(f, S[i]);
  }
  st[0] += a;
  st[1] += b;
  st[2] += c;
  st[3] += d;
}

__kernel void md5_batch(__global const uchar* in, __global const uint* in_off,
                        __global const uint* in_len, __global uint* out) {
  int g = get_global_id(0);
  uint len = in_len[g];
  if (len >= 56) {
    return;
  }
  uchar blk[64];
  for (int i = 0; i < 64; i++) blk[i] = 0;
  for (uint i = 0; i < len; i++) blk[i] = in[in_off[g] + i];
  blk[len] = 0x80;
  ulong bits = (ulong)len * 8ul;
  for (int i = 0; i < 8; i++) blk[56 + i] = (uchar)(bits >> (8 * i));
  uint st[4] = {(uint)0x67452301, (uint)0xefcdab89, (uint)0x98badcfe, (uint)0x10325476};
  md5_compress(st, blk);
  out[g * 4 + 0] = st[0];
  out[g * 4 + 1] = st[1];
  out[g * 4 + 2] = st[2];
  out[g * 4 + 3] = st[3];
}
