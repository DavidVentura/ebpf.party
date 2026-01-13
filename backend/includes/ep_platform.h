#include "task.h"

#if __TINYC__
#define __builtin_preserve_access_index(x) x
#define __builtin_bswap16(x) x
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
    _Static_assert(__builtin_classify_type(struct_val) != 5, "DEBUG_STRUCT takes a struct by value, not reference"); \
    _Static_assert(sizeof(struct_val) < 256, "Struct is too big, max size is 255"); \
    __debug_struct(label_str, __COUNTER__, &struct_val, sizeof(struct_val), 0); \
} while (0)

// only doing _Static_assert here because the verifier
// requires `len` to be a constant
//_Static_assert((len) < 256, "Max string length is 255");
//
#define DEBUG_STR_PTR(label_str, str_ptr, len) do { \
    __debug_str(label_str, __COUNTER__, str_ptr, 255, len, 0); \
} while (0)

#define IS_ARRAY(x) (!__builtin_types_compatible_p(typeof(x), typeof(&(x)[0])))
#define DEBUG_STR(label_str, str_val) do { \
    _Static_assert(IS_ARRAY(str_val), "Use DEBUG_STR_PTR for pointers"); \
    _Static_assert(sizeof(str_val) < 256, "Max string length is 255"); \
    __debug_str(label_str, __COUNTER__, &str_val, sizeof(str_val), sizeof(str_val), 0); \
} while (0)

#define DEBUG_NUM(label_str, num_val) do { \
    _Static_assert(__builtin_classify_type(num_val) != 5, "DEBUG_NUM takes a number by value, not reference"); \
    __typeof__(num_val) _tmp = (num_val); \
    __debug_num(label_str, __COUNTER__, &_tmp, sizeof(num_val), 0); \
} while (0)

#define SUBMIT_STR(str_val) do { \
    _Static_assert(sizeof(str_val) < 256, "Max string length is 255"); \
    __debug_str("answer", __COUNTER__, &str_val, sizeof(str_val), sizeof(str_val), 1); \
} while (0)

// This is doing sizeof() so can't take a ptr
#define SUBMIT_STR_LEN(str_val, len) do { \
    _Static_assert(IS_ARRAY(str_val), "Use SUBMIT_STR_PTR for pointers"); \
    _Static_assert(sizeof(str_val) < 256, "Max string length is 255"); \
    __debug_str("answer", __COUNTER__, &str_val, sizeof(str_val), len, 1); \
} while (0)

#define SUBMIT_STR_PTR(str_ptr, len) do { \
    _Static_assert(!IS_ARRAY(str_ptr), "Use SUBMIT_STR_LEN for arrays"); \
    __debug_str("answer", __COUNTER__, str_ptr, 255, len, 1); \
} while (0)

#define SUBMIT_NUM(num_val) do { \
    _Static_assert(__builtin_classify_type(num_val) != 5, "SUBMIT_NUM takes a number by value, not reference"); \
    __typeof__(num_val) _tmp = (num_val); \
    __debug_num("answer", __COUNTER__, &_tmp, sizeof(num_val), 1); \
} while (0)

#define NUM_ID      0x02
#define STR_ID      0x03
#define STRUCT_ID   0x04
#define ANSWER_FLAG 0x80

// rsv size needs to be known at compile time.
// for dynamic-length data, we call this with rsv_size=255
static __always_inline void __ep_debug_val(const char *label, __u8 counter, void *ptr, size_t rsv_size, u8 valid_size, __u8 type) {
    if (rsv_size > 255) return;
    unsigned char* buf = bpf_ringbuf_reserve(&_ep_debug_events, rsv_size+3, 0);
    if (!buf)
        return;

    buf[0] = type;
    buf[1] = counter;
    buf[2] = valid_size;
    bpf_probe_read_kernel(buf + 3, valid_size, ptr);
    bpf_ringbuf_submit(buf, 0);
}

static __always_inline void __debug_struct(const char *label, __u8 counter, void *ptr, size_t size, bool is_answer) {
    u8 type = STRUCT_ID;
    if (is_answer)
            type |= ANSWER_FLAG;
    __ep_debug_val(label, counter, ptr, size, size, type);
}

static __always_inline void __debug_str(const char *label, __u8 counter, void *ptr, size_t rsv_size, u8 valid_size, bool is_answer) {
    u8 type = STR_ID;
    if (is_answer)
            type |= ANSWER_FLAG;
    __ep_debug_val(label, counter, ptr, rsv_size, valid_size, type);
}

static __always_inline void __debug_num(const char *label, __u8 counter, void* num, size_t size, bool is_answer) {
    if (size > 8) size = 8; // no u128 for you sorry
    unsigned char* buf = bpf_ringbuf_reserve(&_ep_debug_events, 8+3, 0);
    if (!buf)
        return;

    if (is_answer) {
        buf[0] = NUM_ID | ANSWER_FLAG;
    } else {
        buf[0] = NUM_ID;
    }
    buf[1] = counter;
    buf[2] = size & 0xFF;
    bpf_probe_read_kernel(buf + 3, size, num);
    bpf_ringbuf_submit(buf, 0);
}
