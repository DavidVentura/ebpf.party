#include "ep_platform.h"

struct big {
	__u32 arr[170];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct big);
} bigs SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int prog(void *ctx)
{
	__u32 k = 0;
	__u32 sum = 0;
	struct big *v = bpf_map_lookup_elem(&bigs, &k);
	if (!v)
		return 0;
	for (int i = 0; i < 200; i++)
		sum += v->arr[i];
	return sum;
}
