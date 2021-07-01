#!/usr/bin/python
#
# tcp_delack Trace TCP delayed ack.
#        For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcp_delack -h <HOST>
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from datetime import datetime
import argparse
import os
import socket


# arguments
examples = """examples:
    ./tcp_delack.py -h foo-bar.com
"""


parser = argparse.ArgumentParser(
    description="Trace TCP delayed ack",
    add_help=False)
parser.add_argument(
    "-h", "--host",
    help="trace specific host. should be IP or hostname",
    required=True)
args = parser.parse_args()

# define BPF program
script_dir = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(script_dir, "tcp_headers_3.10.h")) as f:
    tcp_headers = f.read()

bpf_text = tcp_headers
bpf_text += """
struct event_t {
    u16 port;
    u8 delayed;
    int kernel_stack_id;
    int user_stack_id;
};

struct check_ctx_t {
    int ofo_possible;
};

BPF_HASH(curr_check_ctx, u64, struct check_ctx_t);
BPF_STACK_TRACE(stack_traces, 1000);
BPF_PERF_OUTPUT(events);
"""

bpf_text += """
int kprobe____tcp_ack_snd_check(struct pt_regs *ctx,
    struct sock *sk, int ofo_possible) {
    u32 daddr = 0;
    bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    if (daddr != TARGET_HOST) {
        return 0;
    }

    struct check_ctx_t check_ctx = {};
    check_ctx.ofo_possible = ofo_possible;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    curr_check_ctx.update(&pid_tgid, &check_ctx);

    return 0;
}

static void record(struct pt_regs *ctx, struct sock *sk, u8 delayed) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct check_ctx_t *check_ctx = curr_check_ctx.lookup(&pid_tgid);
    if (check_ctx == 0) {
        return;
    }
    struct event_t event = {};
    u16 dport = 0;
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    event.port = ntohs(dport);
    event.delayed = delayed;
    event.kernel_stack_id = stack_traces.get_stackid(ctx, 0);
    event.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    events.perf_submit(ctx, &event, sizeof(event));

    curr_check_ctx.delete(&pid_tgid);
}

int kprobe__tcp_send_ack(struct pt_regs *ctx, struct sock *sk) {
    record(ctx, sk, 0);
    return 0;
}

int kprobe__tcp_send_delayed_ack(struct pt_regs *ctx, struct sock *sk) {
    record(ctx, sk, 1);
    return 0;
}
"""

# code substitutions
ip = socket.gethostbyname(args.host)
segs = [int(s) for s in ip.split('.')]
bpf_text = bpf_text.replace('TARGET_HOST', str(
    segs[0] + (segs[1] << 8) + (segs[2] << 16) + (segs[3] << 24)
))


def print_stack_traces(frames):
    for (i, addr) in enumerate(frames):
        symbol = b.ksym(addr, show_offset=True).decode('utf-8', 'replace')
        print("  {}: [0x{:x}] {}".format(i, addr, symbol))


def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-9s " % datetime.now().strftime("%H:%M:%S").encode('ascii'), nl="")
    printb(b"%-7d %-7d" % (
        event.port,
        event.delayed
    ))

    kernel_stack = [] if event.kernel_stack_id < 0 else stack_traces.walk(event.kernel_stack_id)
    user_stack = [] if event.user_stack_id < 0 else stack_traces.walk(event.user_stack_id)
    print("kernel stack:")
    print_stack_traces(kernel_stack)
    print("user stack:")
    print_stack_traces(user_stack)

    print("================")


# header
print("%-9s %-7s %-7s" % (
    "TIME", "DPORT", "DEL"
))


# initialize BPF
b = BPF(text=bpf_text)
stack_traces = b.get_table("stack_traces")

# read events
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
