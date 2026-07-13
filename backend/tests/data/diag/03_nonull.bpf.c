#include "ep_platform.h"

struct val {
	__u32 idx;
	__u8 data[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, struct val);
} hvals SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int prog(void *ctx)
{
	__u32 k = 0;
	struct val *v = bpf_map_lookup_elem(&hvals, &k);
	return v->idx;
}
