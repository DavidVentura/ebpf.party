#include "ep_platform.h"
#include "syscalls.h"

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    char filename[32];
    
    // ctx->args[0] is the first syscall argument (filename pointer)
    // const char* ptr = ...;
    // copy it to the buffer
    // bpf_probe_read_user_str(dst, size, src);
    DEBUG_STR("filename", filename);
    
    return 0;
}
