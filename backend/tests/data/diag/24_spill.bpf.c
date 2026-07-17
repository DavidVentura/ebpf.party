#include "ep_platform.h"
#include "sched.h"

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	unsigned int n = (unsigned int)ctx;
	DEBUG_NUM("ctx as int", n);
	return 0;
}
