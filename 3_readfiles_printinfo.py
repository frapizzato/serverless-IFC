import os
from bcc import BPF

# Load eBPF program
bpf_program = """
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/limits.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
    char syscall[16];
    int dirfd;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(data.filename, sizeof(data.filename), args->filename);
    __builtin_strncpy(data.syscall, "open", sizeof(data.syscall));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(data.filename, sizeof(data.filename), args->filename);
    __builtin_strncpy(data.syscall, "openat", sizeof(data.syscall));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat2) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Openat2 has an additional struct to hold flags and filename
    bpf_probe_read_user_str(data.filename, sizeof(data.filename), args->filename);
    
    // Retrieve dirfd from args and set it
    data.dirfd = (int)args->dfd;

    __builtin_strncpy(data.syscall, "openat2", sizeof(data.syscall));
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=bpf_program)

# Event handler
def print_event(cpu, data, size):
    event = b["events"].event(data)
    if event.syscall.decode('utf-8') == "openat2":
        # Resolving the full path for openat2
        try:
            full_path = os.path.join(str(event.dirfd), event.filename.decode('utf-8'))
        except Exception as e:
            full_path = f"Error resolving path: {str(e)}"
        print(f"PID: {event.pid}, UID: {event.uid}, COMM: {event.comm.decode('utf-8')}, "
              f"SYSCALL: {event.syscall.decode('utf-8')}, FILENAME: {full_path}")
    else:
        print(f"PID: {event.pid}, UID: {event.uid}, COMM: {event.comm.decode('utf-8')}, "
              f"SYSCALL: {event.syscall.decode('utf-8')}, FILENAME: {event.filename.decode('utf-8')}")

# Attach perf event handler
b["events"].open_perf_buffer(print_event)

print("Tracing file opens... Press Ctrl+C to stop.")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching...")
