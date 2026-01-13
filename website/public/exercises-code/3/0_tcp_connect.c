#include "ep_platform.h"
#include "ep_sock.h"
#include "syscalls.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Uncomment to see -115 (EINPROGRESS)
    // DEBUG_NUM("connect ret", ctx->ret); 
    return 0;
}

SEC("kprobe/tcp_finish_connect")
int trace_tcp_connected(struct pt_regs *ctx)
{
    // Get struct sock* from 1st parameter
    // Read destination port from sock
    // Convert port to little endian and submit
    return 0;
}
