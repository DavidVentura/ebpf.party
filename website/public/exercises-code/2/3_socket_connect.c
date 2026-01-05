#include "ep_platform.h"
#include "syscalls.h"

// Map to track socket fds
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} tracked_sockets SEC(".maps");

// IPv4 socket address structure
struct sockaddr_in {
    u16 sin_family;
    u16 sin_port;
    u32 sin_addr;
    char __pad[8];
};

SEC("tracepoint/syscalls/sys_exit_socket")
int trace_socket_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check ctx->ret >= 0
    // Get socket fd
    // Store in tracked_sockets

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_entry(struct trace_event_raw_sys_enter *ctx)
{
    // Get sockfd from ctx->args[0]
    // Check if in tracked_sockets
    // Read sockaddr_in from ctx->args[1]
    // Check sin_family == 2
    // Extract port with bpf_ntohs()
    // Submit suspicious port

    return 0;
}
