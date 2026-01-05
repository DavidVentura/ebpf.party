#include "ep_platform.h"
#include "syscalls.h"

// Map 1: Temporary pathname storage (PID → pathname)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, char[64]);
} openat_paths SEC(".maps");

// Map 2: FD to filename mapping (fd → filename)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, char[64]);
} fd_to_filename SEC(".maps");

// Map 3: Read buffer tracking (PID → buffer pointer)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} read_buffers SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_entry(struct trace_event_raw_sys_enter *ctx)
{
    // Get PID
    // Get pathname pointer from ctx->args[1]
    // Read pathname string
    // Store in openat_paths

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check ctx->ret >= 0 (success)
    // Get PID
    // Get fd from ctx->ret
    // Lookup pathname from openat_paths
    // Store fd → filename in fd_to_filename
    // Cleanup openat_paths

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_entry(struct trace_event_raw_sys_enter *ctx)
{
    // Get fd from ctx->args[0]
    // Lookup filename from fd_to_filename
    // Check if filename == "config.toml"
    // If yes, get PID and store buffer pointer

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check ctx->ret > 0
    // Get PID
    // Lookup buffer pointer from read_buffers
    // Read buffer contents
    // Submit with SUBMIT_STR_LEN
    // Cleanup read_buffers

    return 0;
}
