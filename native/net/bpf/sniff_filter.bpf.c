// eBPF prefilter for T16 live capture. Phase 0 ships source only.
// Build with clang -target bpf when libbpf available. Userspace falls back to libpcap filter.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
char _license[] SEC("license") = "GPL";
SEC("socket")
int sniff_filter(void *ctx) {
  return 1;
}
