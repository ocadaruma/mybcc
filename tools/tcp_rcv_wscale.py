#!/usr/bin/python
#
# tcp_wnd Trace TCP rcv wscale
#        For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcp_rcv_wscale -h <HOST>
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from datetime import datetime
import argparse
import os
import socket


# arguments
examples = """examples:
    ./tcp_rcv_wscale.py -h foo-bar.com
"""


parser = argparse.ArgumentParser(
    description="Trace TCP rcv wscale",
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
    u8 rcv_wscale;
};

struct wnd_ctx_t {
    struct request_sock *req;
    struct sock *sk;
    u16 dport;
}

BPF_PERF_OUTPUT(events);
BPF_HASH(curr_wnd_ctx, u64, wnd_ctx_t);
"""

bpf_text += """
int kprobe__tcp_openreq_init_rwin(
    struct pt_regs *ctx,
    struct request_sock *req,
    struct sock *sk,
    struct dst_entry *dst) {

    u32 daddr = 0; u16 dport = 0;
    bpf_probe_read(&daddr, sizeof(daddr), &req->__req_common.skc_daddr);
    bpf_probe_read(&dport, sizeof(dport), &req->__req_common.skc_dport);

    if (daddr != TARGET_HOST) {
        return 0;
    }

    struct wnd_ctx_t wnd_ctx = {};
    wnd_ctx.req = req;
    wnd_ctx.sk = sk;
    wnd_ctx.dport = dport;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    curr_wnd_ctx.update(&pid_tgid, &wnd_ctx);

    return 0;
}

int kretprobe__tcp_openreq_init_rwin(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct wnd_ctx_t *wnd_ctx = curr_wnd_ctx.lookup(&pid_tgid);
    if (wnd_ctx == 0) {
        return 0;
    }

    struct my_inet_request_sock *ireq = (struct my_inet_request_sock *)wnd_ctx->req;
    u8 bits = 0;
    bpf_probe_read(&bits, sizeof(bits), &ireq->scale_bits);
    struct event_t event = {};
    event.port = ntohs(wnd_ctx->dport);
    event.rcv_wscale = bits >> 4;
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
