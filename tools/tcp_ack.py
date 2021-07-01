#!/usr/bin/python
#
# tcp_wnd Trace TCP ack.
#        For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcp_ack -h <HOST>
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from datetime import datetime
import argparse
import os
import socket


# arguments
examples = """examples:
    ./tcp_ack.py -h foo-bar.com
"""


parser = argparse.ArgumentParser(
    description="Trace TCP ack",
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
    int kernel_stack_id;
};

BPF_STACK_TRACE(stack_traces, 1000);
BPF_PERF_OUTPUT(events);
"""

bpf_text += """
int kprobe____tcp_ack_snd_check(struct pt_regs *ctx, struct sock *sk, int ofo_possible) {
    u32 daddr = 0; u16 dport = 0;
    bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    if (daddr != TARGET_HOST) {
        return 0;
    }

    struct event_t event = {};
    event.port = ntohs(dport);
    event.kernel_stack_id = stack_traces.get_stackid(ctx, 0);
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}
"""

# code substitutions
ip = socket.gethostbyname(args.host)
segs = [int(s) for s in ip.split('.')]
bpf_text = bpf_text.replace('TARGET_HOST', str(
    segs[0] + (segs[1] << 8) + (segs[2] << 16) + (segs[3] << 24)
))


def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-9s " % datetime.now().strftime("%H:%M:%S").encode('ascii'), nl="")
    printb(b"%-7s" % (
        event.port
    ))

    kernel_stack = stack_traces.walk(event.kernel_stack_id)
    for (i, addr) in enumerate(kernel_stack):
        symbol = b.ksym(addr, show_offset=True).decode('utf-8', 'replace')
        print("  {}: [0x{:x}] {}".format(i, addr, symbol))

    print("================")


# header
print("%-9s %-7s" % (
    "TIME", "DPORT"
))


# initialize BPF
b = BPF(text=bpf_text)

# read events
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()