// OpenCL common helpers. Vendored so build needs no system OpenCL headers.
#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable
uint rotl32(uint x, uint n) { return (x << n) | (x >> (32u - n)); }
