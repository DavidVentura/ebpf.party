#include "task.h"
#include "ep_platform.h"
#include "sched.h"

SEC("tp/sched/sched_process_exec")
int handle_exec(void *ctx) {
    // 1. Try running the example as-is to see the output
    // 2. Extract the filename pointer from the __data_loc field
    // 3. Pass it to DEBUG_STR to display it
    DEBUG_STR("Example", "Hi");
    // char process_name[16];
    // bpf_get_current_comm(&process_name, sizeof(process_name));
    // DEBUG_STR("process", process_name);
    return 0;
}
