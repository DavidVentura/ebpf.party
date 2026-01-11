#include "ep_platform.h"
#include "syscalls.h"

// Compound key for tracking (pid, fd) pairs
struct pid_fd_key {
    u64 pid;
    u32 fd;
};

// Current open in progress (PID → marker)
// Lifetime: open entry → exit only
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u8);
} open_curr_fd_interesting SEC(".maps");

// Tracked interesting FDs ((pid, fd) → marker)
// Lifetime: open exit → until we're done tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct pid_fd_key);
    __type(value, u8);
} open_interesting_fds SEC(".maps");

// Current read buffer (PID → buffer pointer)
// Lifetime: read entry → exit only
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} read_curr_fd_buf SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open_entry(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    u8 mark = 1;
    // Get pathname pointer from ctx->args[0]
    // Read pathname string into local buffer with `bpf_probe_read_user_str`
    // Check if pathname == "/tmp/password" with bpf_strncmp
    // If yes, mark PID in open_curr_fd_interesting with `bpf_map_update_elem`

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    // Check ctx->ret >= 0 (success)
    // Check if PID exists in open_curr_fd_interesting with `bpf_map_lookup_elem`
    // If yes:
    //   - Get fd from ctx->ret
    //   - Delete PID from open_curr_fd_interesting with `bpf_map_delete_elem`
    //   - Store (pid, fd) in open_interesting_fds

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_entry(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 fd = ctx->args[0];
    u64 buf_addr = ctx->args[1];
    // Check if (pid, fd) exists in open_interesting_fds
    // If yes, store buffer address, keyed by pid, in read_curr_fd_buf

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();

    // Check ctx->ret > 0
    // Lookup buffer pointer from read_curr_fd_buf
    // If found:
    //   - Create local buffer
    //   - Read from user space with bpf_probe_read_user
    //   - Submit with SUBMIT_STR_LEN
    //   - Cleanup: delete from read_curr_fd_buf

    return 0;
}
