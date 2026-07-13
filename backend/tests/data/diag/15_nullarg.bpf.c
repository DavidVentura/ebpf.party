#include "ep_platform.h"
#include "sched.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, char[16]);
} process_names SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int prog(void *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    char *comm = bpf_map_lookup_elem(&process_names, &pid);
    return bpf_strncmp(comm, 14, "exit_with_code");
}
