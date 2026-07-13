#include "ep_platform.h"
#include "sched.h"

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    u16 len = ctx->__data_loc_filename >> 16;
    u16 off = ctx->__data_loc_filename & 0xFFFF;
    char fname[32];
    bpf_probe_read_kernel_str(fname, sizeof(fname), (void *)ctx + off);
    if (bpf_strncmp(fname, len, "/bin/secret") == 0) {
        DEBUG_STR("yep", "yep");
    }
    return 0;
}
