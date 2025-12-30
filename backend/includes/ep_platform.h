#include "task.h"

#if __TINYC__
#define __builtin_classify_type(a) 6
#define __builtin_preserve_access_index(x) x
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#if __TINYC__
#undef SEC
#define SEC(name) __attribute__((section(name), used))
#endif

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(key_size, 0);
    __uint(value_size, 0);
    __uint(max_entries, 16384);
} _ep_debug_events SEC(".maps");

#define DEBUG_STRUCT(label_str, struct_val) do { \
    _Static_assert(__builtin_classify_type(struct_val) != 5, "need a struct by value"); \
    _Static_assert(sizeof(struct_val) < 256, "Struct is too big"); \
    __debug_struct(label_str, __COUNTER__, &struct_val, sizeof(struct_val)); \
} while (0)

#define DEBUG_STR(label_str, str_val) do { \
    _Static_assert(sizeof(str_val) < 256, "String is too big"); \
    __debug_str(label_str, __COUNTER__, &str_val, sizeof(str_val)); \
} while (0)

#define DEBUG_NUM(label_str, num_val) do { \
    _Static_assert(__builtin_classify_type(num_val) != 5, "need a number by value"); \
    __debug_num(label_str, __COUNTER__, &num_val, sizeof(num_val)); \
} while (0)

static __always_inline void __ep_debug_val(const char *label, __u8 counter, void *ptr, size_t size, __u8 type) {
    if (size > 256) return;
    char* buf = bpf_ringbuf_reserve(&_ep_debug_events, size+2, 0);
    if (!buf) {
	bpf_printk("bpf_ringbuf_reserve failed\n");
	return;
    }

    buf[0] = type;
    buf[1] = counter;
    bpf_probe_read_kernel(buf + 2, size, ptr);
    bpf_ringbuf_submit(buf, 0);
}

static __always_inline void __debug_str(const char *label, __u8 counter, void *ptr, size_t size) {
    __ep_debug_val(label, counter, ptr, size, 3);
}
static __always_inline void __debug_struct(const char *label, __u8 counter, void *ptr, size_t size) {
    __ep_debug_val(label, counter, ptr, size, 4);
}
static __always_inline void __debug_num(const char *label, __u8 counter, void* num, size_t size) {
    if (size > 8) size = 8; // no u128 for you sorry
    char* buf = bpf_ringbuf_reserve(&_ep_debug_events, 8+3, 0);
    if (!buf) {
	bpf_printk("bpf_ringbuf_reserve failed\n");
	return;
    }

    buf[0] = 2; // num i guess
    buf[1] = counter;
    buf[2] = size & 0xFF;
    bpf_probe_read_kernel(buf + 3, size, num);
    bpf_ringbuf_submit(buf, 0);
}
