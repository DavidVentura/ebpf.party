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
    // Get current PID with bpf_get_current_pid_tgid()
    // Get buffer pointer from ctx->args[1]
    // Store in map with bpf_map_update_elem()

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Fill this in
    return 0;
}
