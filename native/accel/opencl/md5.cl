// OpenCL MD5 stub. Full unrolled kernel lands in Phase 6.
// Interface frozen now: md5_batch(in, in_len, out).
__kernel void md5_batch(__global const uchar* in, __global uint* out) {
  int g = get_global_id(0);
  out[g] = (uint)g;
}
