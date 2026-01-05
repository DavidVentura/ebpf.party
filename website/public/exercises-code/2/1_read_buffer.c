#include "ep_platform.h"
#include "syscalls.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);    // PID
    __type(value, u64);  // Buffer pointer
} read_buffers SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_entry(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    if ((pid & 0xFFFF) == 1) return 0;
    u64 buf_ptr = ctx->args[1];  // The buffer pointer

    bpf_map_update_elem(&read_buffers, &pid, &buf_ptr, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Fill this in
    return 0;
}
