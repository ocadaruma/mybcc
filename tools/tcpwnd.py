#!/usr/bin/python
#
# tcpwnd Trace TCP rcv window.
#        For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpwnd -p <PID> -h <HOST>
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from datetime import datetime
import argparse
import os
import socket


# arguments
examples = """examples:
    ./tcpwnd.py -p 55301 -h foo-bar.com
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
int kprobe__tcp_select_window(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) {
        return 0;
    }

    u16 dport = 0; u32 daddr = 0;
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    if (daddr != TARGET_HOST) {
        return 0;
    }
    curr_sock.update(&pid_tgid, &sk);
    return 0;
}

int kretprobe__tcp_select_window(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = curr_sock.lookup(&pid_tgid);
    if (skpp == 0) {
        return 0;
    }

    struct sock *sk = *skpp;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u16 dport = 0; u32 rcv_wnd = 0; u8 rcv_wscale = 0;
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read(&rcv_wnd, sizeof(rcv_wnd), &tp->rcv_wnd);
    bpf_probe_read(&rcv_wscale, sizeof(rcv_wscale), &tp->rx_opt.rcv_wscale);

    u32 *wnd = curr_wnd.lookup(&dport);
    if (wnd == 0 || *wnd != rcv_wnd) {
        curr_wnd.update(&dport, &rcv_wnd);
    }

    struct event_t event = {};
    event.port = dport;
    event.rcv_wnd = rcv_wnd;
    event.rcv_wscale = rcv_wscale;
    events.perf_submit(ctx, &event, sizeof(event));

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
