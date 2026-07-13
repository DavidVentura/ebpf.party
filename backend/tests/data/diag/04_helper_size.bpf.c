#include "ep_platform.h"

struct val {
	__u32 idx;
	__u8 data[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct val);
} vals SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int prog(void *ctx)
{
	__u32 k = 0;
	__u8 buf[64] = {};
	struct val *v = bpf_map_lookup_elem(&vals, &k);
	if (!v)
		return 0;
	__u32 sz = v->idx;
	bpf_probe_read_kernel(buf, sz, &vals);
	return buf[0];
}
