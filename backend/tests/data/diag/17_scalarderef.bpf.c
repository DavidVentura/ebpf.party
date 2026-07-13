#include "ep_platform.h"
#include "ep_sock.h"
#include "syscalls.h"
#include <bpf/bpf_tracing.h>

SEC("kprobe/tcp_finish_connect")
int trace_tcp_connected(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 port = sk->__sk_common.skc_dport;
    DEBUG_NUM("dp", port);
    return 0;
}
