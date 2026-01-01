#include "ep_platform.h"
#include "syscalls.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    char filename[256];
    
    // ctx->args[0] is the first syscall argument (filename pointer)
    bpf_probe_read_user_str(&filename, sizeof(filename), (void *)ctx->args[0]);
    bpf_printk("execve: %s\n", filename);
    
    return 0;
}
