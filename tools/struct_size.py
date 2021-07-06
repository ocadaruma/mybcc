#!/usr/bin/python
#
# Check struct size.
#        For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: struct_size <struct name>
from __future__ import print_function
from bcc import BPF
import argparse
import os


# arguments
examples = """examples:
    ./struct_size.py <struct name>
"""


parser = argparse.ArgumentParser(
    description="Check struct size",
    add_help=False)
parser.add_argument(
    "struct_name",
    metavar="STRUCT_NAME",
    help="Target struct name")
args = parser.parse_args()

# define BPF program
script_dir = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(script_dir, "tcp_headers_3.10.h")) as f:
    tcp_headers = f.read()

bpf_text = tcp_headers
bpf_text += """
int kprobe__sys_clone(struct pt_regs *ctx) {
    size_t size = sizeof(STRUCT_NAME);
    bpf_trace_printk("%d\\n", size);
    return 0;
}
"""

bpf_text = bpf_text.replace('STRUCT_NAME', args.struct_name)

BPF(text=bpf_text).trace_print()
