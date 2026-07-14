#include "ep_platform.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} counts SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int prog(void *ctx)
{
    __u64 *cnt = bpf_map_lookup_elem(&counts, ctx);
    if (!cnt)
        return 0;
    return *cnt;
}
