// go:build ignore

#include <vmlinux.h>
#include <vmlinux_flavors.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct context_t {
    __u64 tid;
};

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 10);
} tailcall_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct context_t);
    __uint(max_entries, 1);
} context_map SEC(".maps");

// struct scratch_t {
//     struct context_t context;
// };
//
// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __type(key, __u32);
//     __type(value, struct scratch_t);
//     __uint(max_entries, 1);
// } scratch_map SEC(".maps");
//
// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __type(key, __u32);
//     __type(value, struct context_t);
//     __uint(max_entries, 10240);
// } tid_context_map SEC(".maps");

__u64 test = 0;

SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    int zero = 0;
    struct context_t *c;
    c = bpf_map_lookup_elem(&context_map, &zero);
    if (c == NULL) {
        return 0;
    }

    c->tid = tid;

    // bpf_tail_call(ctx, &tailcall_map, 0);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    int zero = 0;
    struct context_t *c;
    c = bpf_map_lookup_elem(&context_map, &zero);
    if (c == NULL) {
        bpf_printk("no context");
        return 0;
    }

    c->tid = tid;

    bpf_tail_call(ctx, &tailcall_map, 0);

    return 0;
}

SEC("raw_tracepoint/dummy_tailcall")
int tracepoint_dummy_tailcall(struct bpf_raw_tracepoint_args *ctx)
{
    char comm[32];
    bpf_get_current_comm(&comm, sizeof(comm));

    int zero = 0;
    struct context_t *c;
    c = bpf_map_lookup_elem(&context_map, &zero);
    if (c == NULL) {
        return 0;
    }

    __u64 tid = bpf_get_current_pid_tgid();
    if (tid != c->tid) {
        bpf_printk("%s %lu != %lu", comm, tid, c->tid);
    } else {
        // bpf_printk("same");
    }

    return 0;
}
