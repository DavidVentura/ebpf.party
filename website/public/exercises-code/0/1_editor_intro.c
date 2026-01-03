#include "ep_platform.h"
#include "sched.h"

struct my_struct {
    u32 a_field;
    char five_chars[5];
};
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // Try running this to see the output!
    struct my_struct s = {a_field: 12345, five_chars: "ABCDE"};
    char c = -127;
    u64 u = 0xFFFFFFFFFFFFFFFF;
    DEBUG_STR("Example", "Hi");
    DEBUG_NUM("A small number", c);
    DEBUG_NUM("A very large number", u);
    DEBUG_STRUCT("A struct", s);
    // uncomment this to submit an answer
    // SUBMIT_STR("the answer");
    // "the answer" is the actual answer
    // for this level
    return 0;
}