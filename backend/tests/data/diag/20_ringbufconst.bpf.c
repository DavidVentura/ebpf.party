#include "ep_platform.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int prog(void *ctx)
{
    __u32 n = bpf_get_current_pid_tgid();
    void *e = bpf_ringbuf_reserve(&rb, n, 0);
    if (!e)
        return 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
