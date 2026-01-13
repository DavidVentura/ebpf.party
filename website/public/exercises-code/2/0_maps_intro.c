#include "ep_platform.h"
#include "sched.h"
#include "syscalls.h"

// Map to store process names, keyed by PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, char[16]);
} process_names SEC(".maps");

// When a process starts: store its name
SEC("tracepoint/sched/sched_process_exec")
int on_process_start(struct trace_event_raw_sched_process_exec *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    bpf_map_update_elem(&process_names, &pid, comm, BPF_ANY);
    return 0;
}

// When a process exits: check if we had stored it in the map
SEC("tracepoint/syscalls/sys_enter_exit")
int on_process_exit(struct trace_event_raw_sys_enter *ctx) {
    u64 pid = bpf_get_current_pid_tgid();

    // Look up the name we stored
    char *comm = bpf_map_lookup_elem(&process_names, &pid);
    if (!comm) return 0;

    // Debug: see all processes and their exit codes
    int exit_code = ctx->args[0];  // exit's first argument
    DEBUG_NUM("Exit code", exit_code);
    DEBUG_STR_LEN("Process", comm, 16);

    // TODO: If process name is "exit_with_code", submit the exit code

    // Clean up
    bpf_map_delete_elem(&process_names, &pid);
    return 0;
}
