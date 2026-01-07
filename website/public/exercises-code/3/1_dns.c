#include "ep_platform.h"
#include "syscalls.h"
#include <bpf/bpf_endian.h>

struct dns_header {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
};

// Map 1: TEMPORARY - Track buffer during recvfrom (PID → buffer pointer)
// Lifetime: recvfrom entry → exit only
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);   // pid
    __type(value, u64); // buffer pointer
} recvfrom_curr_buf SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_recvfrom_entry(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 buf_ptr = ctx->args[1];

    bpf_map_update_elem(&recvfrom_curr_buf, &pid, &buf_ptr, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_recvfrom_exit(struct trace_event_raw_sys_exit *ctx)
{
    // TODO: Check if ctx->ret > 0 (bytes received)
    // TODO: Get PID with bpf_get_current_pid_tgid()
    // TODO: Look up buffer pointer from recvfrom_curr_buf map
    // TODO: Check if lookup returned NULL

    // TODO: Declare local buffer (char buf[256])
    // TODO: Read DNS response with bpf_probe_read_user(buf, sizeof(buf), (void *)*buf_ptr)

    // Parse domain name from question section
    int pos = sizeof(struct dns_header);
    char domain[64];
    int out = 0;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        u8 len = buf[pos++];
        if (len == 0) break;

        #pragma unroll
        for (int j = 0; j < 63; j++) {
            if (j >= len) break;
            domain[out++] = buf[pos++];
        }

        if (buf[pos] != 0) domain[out++] = '.';
    }
    domain[out] = '\0';

    // TODO: Check if domain matches "ebpf.party" with bpf_strncmp(domain, sizeof(domain), "ebpf.party")
    // TODO: If not matching, return 0

    // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
    pos += 4;

    // Parse answer section
    // TODO: Skip NAME field (check if it's a pointer: if first byte >= 0xC0, skip 2 bytes, else skip until null)
    // TODO: Read TYPE (2 bytes) - should be 0x0001 for A record
    // TODO: Skip CLASS (2 bytes), TTL (4 bytes), RDLENGTH (2 bytes)
    // TODO: Read RDATA (4 bytes) - the IP address
    // TODO: Convert IP from network byte order with bpf_ntohl()
    // TODO: Submit with SUBMIT_NUM(ip)

    // TODO: Clean up map with bpf_map_delete_elem(&recvfrom_curr_buf, &pid)

    return 0;
}
