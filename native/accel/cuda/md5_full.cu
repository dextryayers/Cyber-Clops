// Real MD5 batch kernel for NVIDIA GPUs.
// Build: nvcc -ptx -arch=sm_60 native/accel/cuda/md5_full.cu
// Host loader lives in native/cpp/dispatch when CL_OPS_ENABLE_CUDA=ON.
// Each thread hashes one 55 byte-or-less message with standard padding.
// MD5 constants per RFC 1321. Verified against vector 900150983cd24fb0d6963f7d28e17f72.

__device__ __forceinline__ unsigned int rotl32(unsigned int x, unsigned int n) {
  return (x << n) | (x >> (32u - n));
}

__device__ void md5_compress(unsigned int st[4], const unsigned char blk[64]) {
  static const unsigned int S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  };
  static const unsigned int K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
  };
  unsigned int a = st[0], b = st[1], c = st[2], d = st[3];
  unsigned int m[16];
  for (int i = 0; i < 16; i++) {
    m[i] = (unsigned int)blk[i * 4] | ((unsigned int)blk[i * 4 + 1] << 8) |
           ((unsigned int)blk[i * 4 + 2] << 16) | ((unsigned int)blk[i * 4 + 3] << 24);
  }
  for (int i = 0; i < 64; i++) {
    unsigned int f;
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

// in: packed messages, in_off[i] start, in_len[i] length under 56 bytes.
// out: 4 digest words per message, little endian word order.
extern "C" __global__ void md5_batch(const unsigned char* in, const unsigned int* in_off,
                                     const unsigned int* in_len, unsigned int* out, unsigned int n) {
  unsigned int g = blockDim.x * blockIdx.x + threadIdx.x;
  if (g >= n) return;
  unsigned int len = in_len[g];
  if (len >= 56) {
    return;
  }
  unsigned char blk[64];
  for (int i = 0; i < 64; i++) blk[i] = 0;
  for (unsigned int i = 0; i < len; i++) blk[i] = in[in_off[g] + i];
  blk[len] = 0x80;
  unsigned long long bits = (unsigned long long)len * 8ull;
  for (int i = 0; i < 8; i++) blk[56 + i] = (unsigned char)(bits >> (8 * i));
  unsigned int st[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
  md5_compress(st, blk);
  out[g * 4 + 0] = st[0];
  out[g * 4 + 1] = st[1];
  out[g * 4 + 2] = st[2];
  out[g * 4 + 3] = st[3];
}
