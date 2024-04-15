// go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct context_t {
    __u64 counter;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct context_t);
    __uint(max_entries, 1);
} context_map SEC(".maps");

__u64 test = 0;

SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    int zero = 0;
    struct context_t *c;
    c = bpf_map_lookup_elem(&context_map, &zero);
    if (c == NULL) {
        return 0;
    }

    if (c->counter < 2000000) {
        c->counter++;
    } else {
        c->counter = 0;
    }
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int tracepoint_dummy_tailcall(struct bpf_raw_tracepoint_args *ctx)
{
    return 0;
}
