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

__attribute__((noinline)) int read_at(struct val *v, __u32 idx)
{
	return v->data[idx];
}

SEC("tp/syscalls/sys_enter_write")
int prog(void *ctx)
{
	__u32 k = 0;
	struct val *v = bpf_map_lookup_elem(&vals, &k);
	if (!v)
		return 0;
	return read_at(v, v->idx);
}
