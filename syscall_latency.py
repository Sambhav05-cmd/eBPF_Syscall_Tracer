from bcc import BPF
import ctypes as ct
import os, sys, signal, time, re, json

if len(sys.argv) < 2:
    print("Usage: sudo python3 trace_syscall_latency_exec.py <executable> [args...]")
    sys.exit(1)

exe_path = sys.argv[1]
exe_args = sys.argv[1:]

if not os.path.isabs(exe_path) and not os.path.dirname(exe_path):
    if os.path.exists(exe_path):
        exe_path = "./" + exe_path
        exe_args[0] = exe_path

LOG_LIMIT = 100000
OUT_PATH = "syscall_latencies.log"
JSON_PATH = "syscall_latencies.json"

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(pid_filter, u32, u8);

struct key_t {
    u64 pid_tgid;
    u32 id;
};
BPF_HASH(start_ts, struct key_t, u64);

struct event_t {
    u64 pid_tgid;
    u32 id;
    u64 enter_ts;
    u64 exit_ts;
    s64 ret;
};
BPF_PERF_OUTPUT(events);

struct trace_event_raw_sys_enter { long pad; long id; unsigned long long args[6]; };
struct trace_event_raw_sys_exit  { long pad; long id; long ret; };

int sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *enabled = pid_filter.lookup(&pid);
    if (!enabled) return 0;

    struct key_t key = {};
    key.pid_tgid = bpf_get_current_pid_tgid();
    key.id = (u32)ctx->id;
    u64 ts = bpf_ktime_get_ns();
    start_ts.update(&key, &ts);
    return 0;
}

int sys_exit(struct trace_event_raw_sys_exit *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *enabled = pid_filter.lookup(&pid);
    if (!enabled) return 0;

    struct key_t key = {};
    key.pid_tgid = bpf_get_current_pid_tgid();
    key.id = (u32)ctx->id;

    u64 *tsp = start_ts.lookup(&key);
    if (!tsp) return 0;

    struct event_t e = {};
    e.pid_tgid = key.pid_tgid;
    e.id = key.id;
    e.enter_ts = *tsp;
    e.exit_ts = bpf_ktime_get_ns();
    e.ret = ctx->ret;

    start_ts.delete(&key);
    events.perf_submit((void *)ctx, &e, sizeof(e));
    return 0;
}
"""

b = BPF(text=bpf_text)

def parse_unistd():
    paths = [
        "/usr/include/asm/unistd.h",
        "/usr/include/asm/unistd_64.h",
        "/usr/include/x86_64-linux-gnu/asm/unistd.h",
        "/usr/include/asm-generic/unistd.h",
    ]
    pat = re.compile(r'#\s*define\s+__NR_(\w+)\s+(\d+)')
    id2name = {}
    for p in paths:
        try:
            with open(p, "r") as f:
                for line in f:
                    m = pat.search(line)
                    if m:
                        name = m.group(1)
                        num = int(m.group(2))
                        id2name[num] = name
            if id2name:
                return id2name
        except Exception:
            continue
    return id2name

id2name = parse_unistd()

def try_attach_variants(name):
    variants = [name, name + "_time64", name + "_time32", name + "_time64_wrapper"]
    attached = []
    for v in variants:
        tp_e = "syscalls:sys_enter_" + v
        tp_x = "syscalls:sys_exit_" + v
        try:
            b.attach_tracepoint(tp=tp_e, fn_name="sys_enter")
            b.attach_tracepoint(tp=tp_x, fn_name="sys_exit")
            attached.append(v)
        except Exception:
            try:
                b.detach_tracepoint(tp_e)
            except Exception:
                pass
            try:
                b.detach_tracepoint(tp_x)
            except Exception:
                pass
    return attached

names = []
try:
    with open("syscall_names.txt", "r") as f:
        for line in f:
            n = line.strip()
            if n and not n.startswith("#"):
                names.append(n)
except Exception as e:
    print("cannot open syscall_names.txt", e)
    sys.exit(1)

attached_map = {}
for n in names:
    attached = try_attach_variants(n)
    if attached:
        attached_map[n] = attached

if not attached_map:
    try:
        b.attach_tracepoint(tp="syscalls:sys_enter", fn_name="sys_enter")
        b.attach_tracepoint(tp="syscalls:sys_exit", fn_name="sys_exit")
        print("Attached generic syscalls:sys_enter/sys_exit as fallback.")
    except Exception:
        print("Failed to attach any tracepoints. Exiting.")
        sys.exit(1)

class Event(ct.Structure):
    _fields_ = [
        ("pid_tgid", ct.c_uint64),
        ("id", ct.c_uint32),
        ("enter_ts", ct.c_uint64),
        ("exit_ts", ct.c_uint64),
        ("ret", ct.c_int64),
    ]

outfile = open(OUT_PATH, "a", buffering=1)
entry_count = 0
child_pid = None
json_data = {}

def cleanup_and_exit(msg=None, code=0):
    global child_pid
    try:
        if msg:
            sys.stdout.write(msg + "\n"); sys.stdout.flush()
    except Exception:
        pass
    try:
        if child_pid:
            try:
                os.kill(child_pid, signal.SIGTERM)
            except Exception:
                pass
    except Exception:
        pass
    try:
        b["events"].close()
    except Exception:
        pass
    try:
        b.cleanup()
    except Exception:
        pass
    try:
        outfile.close()
    except Exception:
        pass
    try:
        with open(JSON_PATH, "w") as jf:
            json.dump(json_data, jf, indent=2)
    except Exception:
        pass
    sys.exit(code)

def log_event(cpu, data, size):
    global entry_count
    ev = ct.cast(data, ct.POINTER(Event)).contents
    pid = ev.pid_tgid >> 32
    tid = ev.pid_tgid & 0xffffffff
    latency = ev.exit_ts - ev.enter_ts
    name = id2name.get(ev.id, f"id_{ev.id}")
    line = (f"syscall {name} (id {ev.id}) pid {pid} tid {tid} "
            f"enter {ev.enter_ts} ns exit {ev.exit_ts} ns latency {latency} ns ret {ev.ret}\n")
    try:
        outfile.write(line)
    except Exception:
        pass
    entry_key = f"{entry_count+1}_{name}"
    json_data[entry_key] = latency
    entry_count += 1
    if entry_count >= LOG_LIMIT:
        cleanup_and_exit(f"Reached {LOG_LIMIT} entries. Terminating gracefully.", 0)

signal.signal(signal.SIGINT, lambda s,f: cleanup_and_exit("Interrupted by user.", 0))
signal.signal(signal.SIGTERM, lambda s,f: cleanup_and_exit("Terminated.", 0))

b["events"].open_perf_buffer(log_event)

try:
    rfd, wfd = os.pipe()
except OSError as e:
    cleanup_and_exit(f"pipe failed: {e}", 1)

try:
    child_pid = os.fork()
except OSError as e:
    cleanup_and_exit(f"fork failed: {e}", 1)

if child_pid == 0:
    try:
        os.close(wfd)
        os.read(rfd, 1)
        os.close(rfd)
    except Exception:
        pass
    try:
        os.execvp(exe_path, exe_args)
    except FileNotFoundError:
        os._exit(127)
    except PermissionError:
        os._exit(126)
    except Exception:
        os._exit(1)
else:
    try:
        os.close(rfd)
    except Exception:
        pass
    try:
        pid_key = ct.c_uint(child_pid)
        pid_val = ct.c_ubyte(1)
        b["pid_filter"][pid_key] = pid_val
    except Exception:
        pass
    try:
        os.write(wfd, b"x")
    except Exception:
        pass
    try:
        os.close(wfd)
    except Exception:
        pass

    sys.stdout.write(f"Tracing syscalls for child PID {child_pid}. Logging to {OUT_PATH} and {JSON_PATH}. Ctrl-C to stop.\n")
    sys.stdout.flush()
    try:
        while True:
            b.perf_buffer_poll(timeout=1000)
            try:
                pid_status = os.waitpid(child_pid, os.WNOHANG)
                if pid_status and pid_status[0] == child_pid and pid_status[1] != 0:
                    cleanup_and_exit("Child exited; terminating tracer.", 0)
            except ChildProcessError:
                cleanup_and_exit("Child already exited.", 0)
    except KeyboardInterrupt:
        cleanup_and_exit("Interrupted by user.", 0)

