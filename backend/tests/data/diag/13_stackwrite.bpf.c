#include "ep_platform.h"
#include "sched.h"

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    char buffer[16];
    bpf_get_current_comm(&buffer, 17);
    DEBUG_STR("Command", buffer);
    return 0;
}
