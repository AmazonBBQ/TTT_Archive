# [Write-up] Defeating a Stripped Custom VM Crackme via Hardware Watchpoints & GDB Hooking

## Challenge overview
- **Category:** Reverse Engineering / Pwn  
- **Difficulty:** Hard  
- **Characteristics:**
  - Custom Virtual Machine (VM) architecture
  - Binary is **stripped** (no debugging symbols)
  - No built-in execution trace (unlike previous iterations)
  - Short-circuit evaluation on the password check (exits immediately on the first incorrect byte)

## Objective
Recover the correct **6-byte raw input** that passes the VM’s internal `cmp` checks, so the program prints **CORRECT!** and reads the flag.

---

## Step 1: Locate the input buffer (blindly)
Since the binary is stripped and provides no trace logs, static analysis was slow. Instead, we **followed the data**.

Set a breakpoint on `read` and run with a known 6-byte input:

```gdb
b read
r <<< "AAAAAA"
```

When the breakpoint hits, inspect syscall args:

- `$rsi` points to the destination buffer (e.g., `0x7ffdc582aef5`)
- `nbytes` is `6`, confirming the password length is exactly **6 bytes**

---

## Step 2: Hardware watchpoint (awatch)
With the input buffer address, set a hardware access watchpoint so execution stops whenever the VM **reads or writes** that memory:

```gdb
awatch *(char*)0x7ffdc582aef5
c
```

Observed behavior:

1. **Write by `read`:** `\x00 -> 'A'` as the syscall populates the buffer  
2. **Mutation by VM:** `'A' (0x41) -> 0x86` as the VM encrypts/transforms the byte in-place

Right after the first transformed byte is consumed, the program prints `INCORRECT!` and exits — proving the VM uses **short-circuit evaluation** (fails fast on the first wrong byte).

---

## Step 3: Catch the core `cmp`
Restart and step carefully (e.g., `ni`) right after the transformed byte is read. Use:

```gdb
display/8i $pc
```

Eventually you’ll land in the stripped dispatcher at the core compare instruction:

```asm
0x5c7e339a8772: cmp al, BYTE PTR [rbp-0x1]
```

At this point:

- `al` (backed by the byte at `$rbp-0x2`) holds **your transformed input byte** (example: `0x86`)
- `[rbp-0x1]` holds the **target transformed byte** (example: `0xcc`)

---

## Step 4: “God mode” GDB hooking to leak all target bytes
To bypass short-circuit evaluation and leak all **6** expected target bytes, set a breakpoint on the `cmp` instruction and attach commands that:

1. Print *your transformed byte* and the *target byte*
2. Overwrite your byte with the target byte (so the check passes)
3. Continue execution

```gdb
b *0x5c7e339a8772
commands
  silent
  printf "My encrypted char: 0x%x | Target char: 0x%x\n", \
    *(unsigned char*)($rbp-0x2), *(unsigned char*)($rbp-0x1)
  set {char}($rbp-0x2) = {char}($rbp-0x1)
  c
end
```

Run with input `AAAAAA` and record outputs. Example leak:

```
'A' -> 0x86 | Target: 0xcc
'A' -> 0x1b | Target: 0xd9
'A' -> 0x88 | Target: 0x3c
'A' -> 0x41 | Target: 0xce
'A' -> 0x72 | Target: 0x73
'A' -> 0xe7 | Target: 0x29
```

At this point, the program is “fooled” into printing `CORRECT!` and attempting to read the flag.

---

## Step 5: Compute the real 6-byte payload
Assume the VM transforms each byte with a simple per-position offset such that:

- `offset[i] = (encrypted_A[i] - 0x41) mod 256`
- `plaintext[i] = (target[i] - offset[i]) mod 256`

Where:
- `encrypted_A[i]` is the transformed value of `'A'` at position `i`
- `target[i]` is the leaked transformed target byte at position `i`

Python to derive the raw bytes:

```python
encrypted_A = [0x86, 0x1b, 0x88, 0x41, 0x72, 0xe7]
targets     = [0xcc, 0xd9, 0x3c, 0xce, 0x73, 0x29]

password = []
for i in range(6):
    offset = (encrypted_A[i] - 0x41) % 256
    real_char = (targets[i] - offset) % 256
    password.append(real_char)

print(bytes(password))
```

Resulting raw payload:

- **Bytes:** `b'\x87\xff\xf5\xce\x42\x83'`
- **Hex:** `87 ff f5 ce 42 83`

---

## Final: Send raw bytes (no GDB required)
Once you have the true plaintext bytes, you can send them directly:

```
from pwn import *

p = process("./challenge")
p.send(b"\x87\xff\xf5\xce\x42\x83")
p.interactive()
```

This satisfies the VM checks without runtime patching and triggers the flag read.

---

## Notes / gotchas
- Prefer `awatch` over `watch` for tight loops: hardware watchpoints are less disruptive than software watchpoints.
- Stripped binaries often require **data-driven** approaches (break on syscalls, watch buffer mutations) instead of symbol-driven navigation.
- Short-circuit comparisons are ideal targets for breakpoint + overwrite “hooking” to leak full target arrays.
