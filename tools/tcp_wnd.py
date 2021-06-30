#!/usr/bin/python
#
# tcp_wnd Trace TCP rcv window.
#        For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcp_wnd -p <PID> -h <HOST>
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from datetime import datetime
import argparse
import os
import socket


# arguments
examples = """examples:
    ./tcp_wnd.py -p 55301 -h foo-bar.com
"""


parser = argparse.ArgumentParser(
    description="Trace TCP rcv window",
    add_help=False)
parser.add_argument(
    "-h", "--host",
    help="trace specific host. should be IP or hostname",
    required=True)
parser.add_argument(
    "-p", "--pid",
    help="target PID",
    type=int,
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
    u32 rcv_wnd;
    u8 rcv_wscale;
};

BPF_HASH(curr_sock, u64, struct sock *);
BPF_HASH(curr_wnd, u16, u32);
BPF_PERF_OUTPUT(events);
"""

bpf_text += """
int kprobe____tcp_select_window(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) {
        return 0;
    }

    u32 daddr = 0;
    bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    if (daddr != TARGET_HOST) {
        return 0;
    }
    curr_sock.update(&pid_tgid, &sk);
    return 0;
}

int kretprobe____tcp_select_window(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = curr_sock.lookup(&pid_tgid);
    if (skpp == 0) {
        return 0;
    }

    struct sock *sk = *skpp;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u16 dport = 0;
    u16 rx_opt_bits = 0;
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read(&rx_opt_bits, sizeof(rx_opt_bits), &tp->rx_opt.opt_bits.data);

    u32 new_wnd = (u32)PT_REGS_RC(ctx);

    u32 *wnd = curr_wnd.lookup(&dport);
    if (wnd == 0 || *wnd != new_wnd) {
        curr_wnd.update(&dport, &new_wnd);
        struct event_t event = {};
        event.port = ntohs(dport);
        event.rcv_wnd = new_wnd;
        event.rcv_wscale = rx_opt_bits >> 12;
        events.perf_submit(ctx, &event, sizeof(event));
    }

    curr_sock.delete(&pid_tgid);
    return 0;
}
"""

# code substitutions
bpf_text = bpf_text.replace('TARGET_PID', str(args.pid))

ip = socket.gethostbyname(args.host)
segs = [int(s) for s in ip.split('.')]
bpf_text = bpf_text.replace('TARGET_HOST', str(
    segs[0] + (segs[1] << 8) + (segs[2] << 16) + (segs[3] << 24)
))


def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-9s " % datetime.now().strftime("%H:%M:%S").encode('ascii'), nl="")
    printb(b"%-7s %-10s %-10s" % (
        event.port,
        event.rcv_wnd,
        event.rcv_wscale
    ))


# header
print("%-9s %-7s %-10s %-10s" % (
    "TIME", "DPORT", "RCV_WND", "RCV_WSCALE"
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
