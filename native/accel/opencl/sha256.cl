// OpenCL SHA256 stub. Full kernel lands in Phase 6.
__kernel void sha256_batch(__global const uchar* in, __global uint* out) {
  int g = get_global_id(0);
  out[g] = (uint)g;
}
