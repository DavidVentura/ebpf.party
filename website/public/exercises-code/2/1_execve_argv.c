#include "ep_platform.h"
#include "syscalls.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    // Get the argv pointer
    // While we haven't made it to the terminator (or 20 args):
    //  Get the pointer to the argument
    //    If it's NULL, stop
    //  Read the pointed value
    return 0;
}
