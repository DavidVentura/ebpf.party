#include "ep_platform.h"
#include "sched.h"

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	unsigned int n = (unsigned int)ctx->pid;
	while (n > 1) {
		for (int i = 0; i < 100; i++) {
			DEBUG_NUM("Collatz", n);
			n = n % 2 == 0 ? n / 2 : 3 * n + 1;
		}
	}
	return 0;
}
