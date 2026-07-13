#include "ep_platform.h"

struct tp_ctx {
	__u64 pad;
	__u64 args[3];
};

SEC("tp/syscalls/sys_enter_write")
int prog(struct tp_ctx *ctx)
{
	ctx->args[0] = 0;
	return 0;
}
