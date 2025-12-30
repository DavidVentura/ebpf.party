#include "ep_platform.h"
#include "sched.h"

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // 1. Try running the example as-is to see the output
    // 2. Declare a buffer for the process name
    // 3. Copy the process name into the buffer with a helper
    // 4. Call DEBUG_STR on your buffer to see the output
    DEBUG_STR("Example", "Hi");
    return 0;
}