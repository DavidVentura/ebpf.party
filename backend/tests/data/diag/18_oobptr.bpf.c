#include "ep_platform.h"
#include "syscalls.h"
#include "kfuncs.h"

SEC("tp/syscalls/sys_enter_write")
int prog(void *ctx)
{
    char req[128] = {0};
    int pos = bpf_strstr(req, "GET ");
    return req[pos];
}
