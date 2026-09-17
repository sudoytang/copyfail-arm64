# Copy Fail ARM64 Research (CVE-2026-31431)

Analysis and ARM64 reproduction of the [Copy Fail](https://copy.fail/) Linux kernel privilege escalation vulnerability (CVE-2026-31431), originally disclosed by [Xint](https://xint.io/blog/copy-fail-linux-distributions).

**Blog post:** [Copy Fail on ARM64: Understanding and Porting CVE-2026-31431](https://github.com/sudoytang/sudoytang/blob/main/posts/copy-fail-arm64.md)

## What's Included

| File | Description |
|------|-------------|
| `src/copy_fail_exp.py` | Original x86-64 PoC from [Xint/Theori](https://github.com/theori-io/copy-fail-CVE-2026-31431) |
| `src/copy_fail_exp_readable.py` | Deobfuscated version of the above with comments and proper variable names |
| `src/shellcode_analysis.py` | Script to parse the payload ELF with `lief` and disassemble with `capstone` |
| `arm64_syscall/call.s` | ARM64 assembly for the shellcode (setuid + execve + exit) |

## What's Excluded

The following files are **not included** in this repository. They constitute the complete ARM64 exploit build chain and are withheld to avoid lowering the barrier for misuse. ([Private gist](https://gist.github.com/sudoytang/fab3bd2d8ae094f8a193f05ccaa759cd))

- ARM64 minimal ELF builder
- Shellcode compression/hex extraction tool
- Compiled ARM64 binary
- Complete ARM64 exploit script with embedded payload

The linked blog post describes the construction approach in enough detail for a motivated researcher to reproduce the work independently.

## Disclaimer

This repository is for educational and authorized security research only. Do not use any of this material on systems without explicit authorization.
