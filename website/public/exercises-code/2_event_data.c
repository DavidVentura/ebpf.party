#include "ep_platform.h"
#include "sched.h"

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // 1. Try running the example as-is to see the output
    // 2. Uncomment the rest of the code and run it again
    // DEBUG_STR("Example", "Hi");
    // DEBUG_NUM("pid", ctx->pid);
      unsigned short v = -1;
    // DEBUG_STR("Example", "Hi");
    DEBUG_NUM("pid", ctx->pid);
    DEBUG_NUM("neg", v);
    // char process_name[16];
    // bpf_get_current_comm(&process_name, sizeof(process_name));
    // DEBUG_STR("process", process_name);
    return 0;
}
