from bcc import BPF
import ctypes as ct
import os, sys, time, signal, json

if len(sys.argv) < 2:
    print("Usage: sudo python3 trace_unique_syscalls_exec.py <executable> [args...]")
    sys.exit(1)

exe_path = sys.argv[1]
exe_args = sys.argv[1:]

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(pid_map, u32, u8);
BPF_HASH(syscall_map, u64, u8);

struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

int trace_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u8 *flag = pid_map.lookup(&tgid);
    if (!flag)
        return 0;

    u64 syscall_id = ctx->id;
    u8 present = 1;
    syscall_map.update(&syscall_id, &present);
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_tracepoint(tp="raw_syscalls:sys_enter", fn_name="trace_sys_enter")

pid_map = b["pid_map"]
syscall_map = b["syscall_map"]

r, w = os.pipe()
child_pid = os.fork()
if child_pid == 0:
    os.close(w)
    os.read(r, 1)
    os.close(r)
    try:
        os.execvp(exe_path, exe_args)
    except Exception:
        os._exit(1)
else:
    os.close(r)
    flag = ct.c_ubyte(1)
    pid_map[ct.c_uint(child_pid)] = flag
    os.write(w, b"1")
    os.close(w)
    print(f"Tracing syscalls for child PID {child_pid}. Ctrl-C to stop.\n")

    def cleanup(sig, frame):
        print("\nDumping unique syscalls...")
        data = []
        for k, v in syscall_map.items():
            data.append({"id": int(k.value), "value": int(v.value)})
        with open("unique_syscalls.json", "w") as f:
            json.dump(data, f, indent=4)
        print(f"Dumped {len(data)} unique syscalls to unique_syscalls.json")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    while True:
        try:
            time.sleep(1)
            pid_status = os.waitpid(child_pid, os.WNOHANG)
            if pid_status and pid_status[0] == child_pid:
                cleanup(None, None)
        except KeyboardInterrupt:
            cleanup(None, None)

