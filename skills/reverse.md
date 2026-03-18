# Reverse Engineering Playbook

## Static Analysis Workflow

### Step 1: Identify the Binary

```bash
file <binary>         # Architecture, linking (static/dynamic), stripped?
checksec <binary>     # Security features: NX, PIE, canary, RELRO (if checksec available)
```

**Key details:**
- ELF 32-bit vs 64-bit → determines register names and calling convention
- Statically linked → all library functions are embedded (larger, but self-contained)
- Stripped → no symbol names (harder to read disassembly)

### Step 2: String Extraction

```bash
strings <binary> | head -50                            # Overview
strings <binary> | grep -iE 'flag|ctf|pico|pass|key|secret|correct|wrong'
strings <binary> | grep -E '[A-Za-z0-9+/]{20,}={0,2}'  # Base64 candidates
strings <binary> | grep -E '[0-9a-f]{16,}'              # Hex candidates
```

Strings alone solve 20%+ of beginner reverse challenges — always start here.

### Step 3: Symbol Table

```bash
readelf -s <binary>    # List all symbols
nm <binary>            # Compact symbol listing
```

**Interesting function names:** `main`, `check_flag`, `validate`, `encrypt`, `decrypt`,
`check_password`, `verify`, `print_flag`, `win`, `get_flag`

### Step 4: Disassembly

```bash
objdump -d -M intel <binary>                    # Full disassembly (Intel syntax)
objdump -d -M intel <binary> | grep -A 30 main  # Focus on main
```

For more structured analysis, use Ghidra (free) or IDA Pro. Ghidra's decompiler
produces pseudo-C that's much easier to read than raw assembly.

## Common CTF Binary Patterns

### Pattern 1: strcmp / strncmp Comparison

The binary reads input and compares it against a hardcoded string:

```asm
; x86-64 typical pattern
lea  rdi, [rbp-0x40]     ; user input buffer
lea  rsi, [rip+0x...]     ; hardcoded string in .rodata
call strcmp
test eax, eax
je   correct_path
```

**Solution**: Find the `.rodata` string being compared. It's often the flag directly,
or a transformed version (base64, hex, reversed).

```bash
objdump -s -j .rodata <binary>   # Dump read-only data section
```

### Pattern 2: XOR Loop

The binary XORs input with a key and compares against expected output:

```asm
; Typical XOR loop
xor_loop:
    movzx eax, byte [rdi+rcx]   ; input[i]
    xor   al, byte [rsi+rcx]    ; key[i % key_len]
    cmp   al, byte [rdx+rcx]    ; expected[i]
    jne   wrong
    inc   rcx
    cmp   rcx, rax              ; length
    jl    xor_loop
```

**Solution**: Extract the key and expected arrays from `.rodata`, XOR them together
to get the flag:

```python
key = b"..."       # from .rodata
expected = b"..."  # from .rodata
flag = bytes(k ^ e for k, e in zip(key, expected))
print(flag.decode())
```

### Pattern 3: Character-by-Character Validation

Each character is checked individually (often with different transformations):

```asm
movzx eax, byte [rbp-0x40]   ; input[0]
cmp   al, 0x70                ; 'p'
jne   wrong
movzx eax, byte [rbp-0x3f]   ; input[1]
cmp   al, 0x69                ; 'i'
jne   wrong
; ... continues for each character
```

**Solution**: Extract each comparison value and reconstruct the string.

### Pattern 4: Anti-Debug / Obfuscation

**ptrace check:**
```asm
xor  edi, edi
call ptrace           ; ptrace(PTRACE_TRACEME, 0, 0, 0)
test rax, rax
js   exit_or_fake     ; if debugger attached, ptrace returns -1
```

**Bypass**: Patch the `js` to `jmp` (always take the good path), or use
`LD_PRELOAD` to hook ptrace.

**Time-based check:**
```asm
call rdtsc            ; read timestamp counter
; ... do work ...
call rdtsc
sub  rax, <saved>
cmp  rax, threshold
ja   exit_or_fake     ; too slow → debugger detected
```

## Dynamic Analysis with GDB

```bash
gdb ./binary

# Useful GDB commands
(gdb) info functions           # List all functions
(gdb) disas main               # Disassemble main
(gdb) break *main+42           # Break at specific offset
(gdb) break check_flag         # Break at function
(gdb) run                      # Start execution
(gdb) run <<< "test_input"     # Run with input
(gdb) ni                       # Next instruction (step over)
(gdb) si                       # Step into
(gdb) x/20s 0x<addr>           # Examine memory as strings
(gdb) x/20x $rsp               # Examine stack (hex)
(gdb) info registers           # Show all registers
(gdb) set $rax = 0             # Modify register (bypass checks)
(gdb) jump *0x<addr>           # Jump to address (skip code)
```

**GDB + pwntools for automation:**
```python
from pwn import *
p = process("./binary")
# or: p = gdb.debug("./binary", "break main\ncontinue")
p.sendline(b"my_input")
print(p.recvall())
```

## Script Deobfuscation

### Python

**exec/eval obfuscation**: The script builds a string and `exec()`s it.
Replace `exec()` with `print()` to see the deobfuscated code.

**Marshal/bytecode**: `marshal.loads()` followed by `exec()`.
Use `dis.dis()` to disassemble the bytecode.

**Base64 layers**: `exec(base64.b64decode(...))`. Decode iteratively until readable.

```python
# Generic Python deobfuscation
import base64
code = "..."  # the obfuscated payload
# Try iterative base64 decoding
while True:
    try:
        code = base64.b64decode(code).decode()
    except:
        break
print(code)
```

### JavaScript

**eval obfuscation**: Replace `eval()` with `console.log()`.

**String array obfuscation**: Tools like `de4js`, `js-beautify`, or manual analysis.

**JSFuck**: Encoding using only `[]()!+`. Use an online decoder or:
```javascript
// In browser console:
console.log(/* paste jsfuck here */)
```

### PHP

**eval + base64**: `eval(base64_decode("..."))` → decode the base64 to see the real code.

**Variable variables**: `$$var` chains. Trace the assignments manually.

## Assembly Quick Reference (x86-64)

### Registers
| Register | Convention | Notes |
|----------|-----------|-------|
| rdi | 1st argument | |
| rsi | 2nd argument | |
| rdx | 3rd argument | |
| rcx | 4th argument | Also loop counter |
| r8, r9 | 5th, 6th argument | |
| rax | Return value | Also used in mul/div |
| rsp | Stack pointer | |
| rbp | Base pointer | Frame pointer |

### Common Instructions
| Instruction | Meaning |
|------------|---------|
| `mov rax, rbx` | rax = rbx |
| `lea rax, [rbx+8]` | rax = address of rbx+8 (no dereference) |
| `xor rax, rax` | rax = 0 (common idiom) |
| `test rax, rax` | Set flags based on rax & rax (check if zero) |
| `cmp rax, rbx` | Set flags based on rax - rbx (compare) |
| `je / jz` | Jump if equal / zero |
| `jne / jnz` | Jump if not equal / not zero |
| `call <addr>` | Push return address, jump to function |
| `ret` | Pop return address, jump to it |
| `push rax` | Decrement rsp, store rax at [rsp] |
| `pop rax` | Load rax from [rsp], increment rsp |

### Calling Convention (System V AMD64)
- Arguments: rdi, rsi, rdx, rcx, r8, r9 (then stack)
- Return: rax
- Caller-saved: rax, rcx, rdx, rsi, rdi, r8-r11
- Callee-saved: rbx, rbp, r12-r15, rsp
