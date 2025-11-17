#!/usr/bin/env python3
from bcc import BPF

b = BPF(src_file="tcp_stats.c")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("tcp_sendmsg at", event.ts)

b["events"].open_perf_buffer(print_event)

print("loaded OK, waiting events...")

while True:
    b.perf_buffer_poll()
