#include "ep_platform.h"
#include "syscalls.h"
#include "ep_sock.h"
#include <bpf/bpf_endian.h>

// Map 1: TEMPORARY - Track port during connect (PID → port)
// Lifetime: connect entry → exit only
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);   // pid
    __type(value, u16); // port
} connect_curr_port SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_entry(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in addr;
    // Read sockaddr from ctx->args[1] with bpf_probe_read_user()
    // Check if addr.sin_family == 2 (IPv4)
    // Convert port with bpf_ntohs(addr.sin_port)
    // Get PID with bpf_get_current_pid_tgid()
    // Store port in connect_curr_port map

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check if ctx->ret == 0 (successful connection)
    // Get PID with bpf_get_current_pid_tgid()
    // Look up port from connect_curr_port map
    // Check if lookup returned NULL
    // Submit the port with SUBMIT_NUM(*port)
    // Clean up map entry with bpf_map_delete_elem()

    return 0;
}