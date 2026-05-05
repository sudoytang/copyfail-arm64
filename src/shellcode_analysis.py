import capstone as cs
import lief
import zlib

COMPRESSED_SHELLCODE = bytes.fromhex(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c"
    "301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10"
    "f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
)

raw = zlib.decompress(COMPRESSED_SHELLCODE)
print(f"Total payload: {len(raw)} bytes\n")

elf = lief.ELF.parse(list(raw))

print("=== ELF Header ===")
print(f"Class:       {elf.header.identity_class}")
print(f"Machine:     {elf.header.machine_type}")
print(f"Type:        {elf.header.file_type}")
print(f"Entry point: 0x{elf.header.entrypoint:x}")
print(f"PH offset:   0x{elf.header.program_header_offset:x}")
print(f"PH count:    {elf.header.numberof_segments}")

print("\n=== Segments ===")
for i, seg in enumerate(elf.segments):
    print(f"Segment {i}: type={seg.type} "
          f"offset=0x{seg.file_offset:x} "
          f"vaddr=0x{seg.virtual_address:x} "
          f"filesz=0x{seg.physical_size:x} "
          f"memsz=0x{seg.virtual_size:x} "
          f"flags={seg.flags}")

entry = elf.header.entrypoint
base = elf.segments[0].virtual_address if elf.segments else 0
code_offset = entry - base
code = bytes(raw[code_offset:])

print(f"\n=== Disassembly (from entry 0x{entry:x}, file offset 0x{code_offset:x}) ===")
md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
for insn in md.disasm(code, entry):
    print(f"0x{insn.address:04x}: {insn.bytes.hex():<16} {insn.mnemonic} {insn.op_str}")