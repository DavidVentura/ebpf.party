#include "ep_platform.h"
#include "sched.h"

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // 1. Get and print the PID
    // 2. Calculate the offset
    // 3. Create the `fname` pointer
    // 4. Populate `fname` with a helper
    DEBUG_STR("Hi", "Welcome back");
    return 0;
}