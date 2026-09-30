// Scalar reference. Full MD5 and SHA256 land in Phase 6 with vector paths.
// This TU exists so clops_native always links, even on CPU only builds.
#include <cstdint>
#include <cstddef>
void clops_md5_block_scalar(const uint8_t in[64], uint32_t state[4]) {
  (void)in; (void)state;
}
void clops_sha256_block_scalar(const uint8_t in[64], uint32_t state[8]) {
  (void)in; (void)state;
}
