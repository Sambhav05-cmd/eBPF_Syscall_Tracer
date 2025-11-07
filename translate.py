import json

with open("unique_syscalls.json", "r") as f:
    syscall_entries = json.load(f)

syscall_table = {}
with open("syscall_table.txt", "r") as f:
    for line in f:
        line = line.strip()
        if "->" in line:
            name, num = line.split("->")
            name = name.strip()
            num = int(num.strip())
            syscall_table[num] = name

mapped_names = []
for entry in syscall_entries:
    syscall_id = entry.get("id")  # changed from "key" to "id"
    if syscall_id in syscall_table:
        mapped_names.append(syscall_table[syscall_id])
    else:
        mapped_names.append(f"unknown_{syscall_id}")

with open("syscall_names.txt", "w") as f:
    for name in mapped_names:
        f.write(name + "\n")

print(f"Mapped {len(mapped_names)} syscalls to names and saved to syscall_names.txt")

