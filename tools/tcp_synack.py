#!/usr/bin/python
#
# tcp_wnd Trace TCP SYN/ACK.
#        For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcp_synack -p <PID> -h <HOST>
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from datetime import datetime
import argparse
import os
import socket


# arguments
examples = """examples:
    ./tcp_synack.py -p 55301 -h foo-bar.com
"""


parser = argparse.ArgumentParser(
    description="Trace TCP SYN/ACK",
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
    u8 rcv_wscale;
};

BPF_PERF_OUTPUT(events);
"""

bpf_text += """
int kprobe__tcp_make_synack(
    struct pt_regs *ctx,
    struct sock *sk,
    struct dst_entry *dst,
    struct request_sock *req,
    struct tcp_fastopen_cookie *foc) {

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) {
        return 0;
    }

    u32 daddr = 0; u16 dport = 0;
    struct event_t event = {};
    event.port = ntohs(dport);
    event.rcv_wscale = 42;
    events.perf_submit(ctx, &event, sizeof(event));
    bpf_probe_read(&daddr, sizeof(daddr), &req->__req_common.skc_daddr);
    bpf_probe_read(&dport, sizeof(dport), &req->__req_common.skc_dport);

    if (daddr != TARGET_HOST) {
        return 0;
    }

    struct event_t event = {};
    event.port = ntohs(dport);
    event.rcv_wscale = 42;
    events.perf_submit(ctx, &event, sizeof(event));

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
    printb(b"%-7s %-10s" % (
        event.port,
        event.rcv_wscale
    ))


# header
print("%-9s %-7s %-10s" % (
    "TIME", "DPORT", "RCV_WSCALE"
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
