#include "ep_platform.h"

struct vals32 {
	__u32 idx;
	__u32 arr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct vals32);
} v32 SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int prog(void *ctx)
{
	__u32 k = 0;
	struct vals32 *v = bpf_map_lookup_elem(&v32, &k);
	if (!v)
		return 0;
	__u32 idx = v->idx;
	if (idx > 16)
		return 0;
	return v->arr[idx];
}
