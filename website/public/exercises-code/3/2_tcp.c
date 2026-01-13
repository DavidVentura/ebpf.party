#include "ep_platform.h"
#include "syscalls.h"
#include "kfuncs.h"

SEC("kprobe/tcp_sendmsg")
int trace_tcp_send(struct pt_regs *ctx)
{
    // Get msghdr from 2nd parameter
    // Read iov_iter from msg->msg_iter
    // Read iovec from iter 
    
    // Read data from the usersspace buf at iov.iov_base
    // Find the token in the buf, submit it

    return 0;
}
