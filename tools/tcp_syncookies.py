#!/usr/bin/python
#
# tcp_wnd Trace TCP SYN cookies.
#        For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcp_syncookies -h <HOST>
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from datetime import datetime
import argparse
import os
import socket


# arguments
examples = """examples:
    ./tcp_syncookies.py -h foo-bar.com
"""


parser = argparse.ArgumentParser(
    description="Trace TCP SYN cookies",
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
    u32 window_clamp;
};

struct cookie_ctx_t {
    u32 *window_clamp;
};

BPF_HASH(curr_cookie_ctx, u64, struct cookie_ctx_t);
BPF_PERF_OUTPUT(events);
"""

bpf_text += """
int kprobe__cookie_v4_check(struct pt_regs *ctx,
    struct sock *sk,
    struct sk_buff *skb,
    struct ip_options *opt) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct cookie_ctx_t cookie_ctx = {};
    curr_cookie_ctx.update(&pid_tgid, &cookie_ctx);
    return 0;
}

// drop last argument for BPF limitation
int kprobe__tcp_select_initial_window(struct pt_regs *ctx,
    int __space, __u32 mss,
    __u32 *rcv_wnd, __u32 *window_clamp,
    int wscale_ok, __u8 *rcv_wscale) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct cookie_ctx_t *cookie_ctx = curr_cookie_ctx.lookup(&pid_tgid);
    if (cookie_ctx != 0) {
        cookie_ctx->window_clamp = window_clamp;
    }
    return 0;
}

int kretprobe__cookie_v4_check(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    
    u32 daddr = 0; u16 dport = 0;
    bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    if (daddr != TARGET_HOST) {
        return 0;
    }

    struct tcp_sock *tp = (struct tcp_sock *)sk;

    struct event_t event = {};
    event.port = ntohs(dport);

    u16 rx_opt_bits = 0;
    bpf_probe_read(&rx_opt_bits, sizeof(rx_opt_bits), &tp->rx_opt.opt_bits);
    event.rcv_wscale = rx_opt_bits >> 12;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cookie_ctx_t *cookie_ctx = curr_cookie_ctx.lookup(&pid_tgid);
    if (cookie_ctx != 0) {
        bpf_probe_read(&event.window_clamp, sizeof(u32), &cookie_ctx->window_clamp);
        curr_cookie_ctx.delete(&pid_tgid);
    }

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
    printb(b"%-7s %-10s %-10s" % (
        event.port,
        event.rcv_wscale,
        event.window_clamp
    ))


# header
print("%-9s %-7s %-10s %-10s" % (
    "TIME", "DPORT", "RCV_WSCALE", "WND_CLAMP"
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
