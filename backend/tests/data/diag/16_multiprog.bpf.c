#include "ep_platform.h"
#include "syscalls.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} m SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_open")
int first_prog(struct trace_event_raw_sys_enter *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&m, &pid, &pid, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int second_prog(struct trace_event_raw_sys_exit *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 *p = bpf_map_lookup_elem(&m, &pid);
    return *p;
}
