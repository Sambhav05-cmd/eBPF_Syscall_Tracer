# Syscall Latency Tracer using eBPF

## Prerequisites
- **Linux kernel ≥ 5.4** (with eBPF and tracepoints enabled)
- **Python 3**
- **BCC (BPF Compiler Collection)**
  Install via:
  ```bash
  sudo apt install bpfcc-tools python3-bpfcc
  ```
- Root privileges are required (`sudo`) to load eBPF programs.

---
- A file named syscall_table.txt is provided for mapping syscall names to ID.
- If any error or inconsistency arrives due to version mismatch :
###Run :
```bash
sudo ./syscall_table
```
- This will recreate the syscall_table.txt file
## 1. Identify Unique System Calls

This phase discovers which system calls are used by a target executable.

### Run:
```bash
sudo python3 trace_unique_syscalls_exec.py <path_to_executable>
```
### Note :
-For both the tracing codes , the program will terminate when the given executable terminates. You can also manually terminate by Control C which will stop the tracing and save the results till that time of tracing
### Example:
```bash
sudo python3 unique_syscalls.py ./trial
```
-Two example executable files ./trial and ./trial2 are provided for testing purposes. You can give your own executable as input also
### Output:
- Generates a file `unique_syscalls.json` listing all unique syscall IDs made by the process.

---
## 2. Translate syscall id to syscall names
This creates a text file syscall_names.txt which contains the names of all the syscalls :

### Run:
```bash
python3 translate.py
```

## 3. Trace Syscall Latencies

This phase measures the latency (in nanoseconds) of each syscall used by the process.

### Run:
```bash
sudo python3 syscall_latency.py <path_to_executable>
```

### Example:
```bash
sudo python3 trace_syscall_latency.py ./trial
```

### Output:
- Logs detailed syscall timings to:
  - `syscall_latencies.log` (text format)
  - `syscall_latencies.json` (structured JSON format)

---

## 3. Typical Workflow
1. Run **Phase 1** to generate `unique_syscalls.json`.
2. Extract syscall names using translate.py(the second script reads from `syscall_names.txt` or uses built-in mappings).
3. Run **Phase 2** to record syscall latencies for the same target binary.
4. Analyze the latency results from the JSON file.

---

## Notes
- Always execute both scripts with **sudo**.
- If BCC is not installed system-wide, ensure Python finds the `bcc` module in your environment.
- The tracer uses in-kernel timestamping (`bpf_ktime_get_ns()`) for nanosecond precision.
- Use Ctrl-C to gracefully terminate tracing and save output files.
