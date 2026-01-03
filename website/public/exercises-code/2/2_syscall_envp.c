#include "ep_platform.h"
#include "syscalls.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    // Have fun!
    return 0;
}
