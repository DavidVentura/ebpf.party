#include "ep_platform.h"
#include "syscalls.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    char filename[32];
    
    // ctx->args[0] is the first syscall argument (filename pointer)
    // copy it to the buffer
    // bpf_probe_read_user_str(...);
    DEBUG_STR("filename", filename);
    
    return 0;
}
