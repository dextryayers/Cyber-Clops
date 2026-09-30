// Real ISPC base64 bulk encoder. Scalar fallback must match.
// in: input bytes, n: length, out: caller buffer of at least 4*(n+2)/3 bytes.
// Returns bytes written.

static const char B64[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
};

export int base64_encode_block(uniform const char *in, uniform int n, uniform char *out) {
  uniform int triples = n / 3;
  uniform int rem = n - triples * 3;
  uniform int o = 0;
  foreach (t = 0 ... triples) {
    uniform int i = t * 3;
    unsigned int a = (unsigned char)in[i];
    unsigned int b = (unsigned char)in[i + 1];
    unsigned int c = (unsigned char)in[i + 2];
    out[o + 0] = B64[a >> 2];
    out[o + 1] = B64[((a & 3) << 4) | (b >> 4)];
    out[o + 2] = B64[((b & 15) << 2) | (c >> 6)];
    out[o + 3] = B64[c & 63];
    o += 4;
  }
  if (rem == 1) {
    unsigned int a = (unsigned char)in[triples * 3];
    out[o + 0] = B64[a >> 2];
    out[o + 1] = B64[(a & 3) << 4];
    out[o + 2] = '=';
    out[o + 3] = '=';
    o += 4;
  } else if (rem == 2) {
    unsigned int a = (unsigned char)in[triples * 3];
    unsigned int b = (unsigned char)in[triples * 3 + 1];
    out[o + 0] = B64[a >> 2];
    out[o + 1] = B64[((a & 3) << 4) | (b >> 4)];
    out[o + 2] = B64[(b & 15) << 2];
    out[o + 3] = '=';
    o += 4;
  }
  return o;
}
