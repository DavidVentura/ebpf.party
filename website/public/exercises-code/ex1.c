#include "task.h"
#include "sched.h"
#include <bpf/bpf_helpers.h>

#undef SEC
#define SEC(name) __attribute__((section(name), used))

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec* ctx) {
    // 1. Try running the example as-is to see the output
    // 2. Extract the filename pointer from the __data_loc field
    // 3. Pass it to DEBUG_STR to display it
    DEBUG_STR("Example", "Hi");
    return 0;
}