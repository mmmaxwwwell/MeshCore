#!/usr/bin/env python3
"""Write a synthetic nRF52840 FICR page (4 KiB) for one emulated node.

Device-generic fields are those of a QIAA nRF52840 (rev AAD0); DEVICEID, DEVICEADDR
and the ER/IR root keys are random per node (fixed by the seed, so re-renders keep
the node's BLE address). Everything else reads erased (0xFF), like unprogrammed
factory words. The SoftDevice needs CODEPAGESIZE/CODESIZE: an all-zero FICR makes
its flash operations fail with NRF_ERROR_FORBIDDEN.

usage: gen-ficr.py <seed> <out.bin>
"""
import random, struct, sys

seed, out = sys.argv[1], sys.argv[2]
rng = random.Random(seed)
page = bytearray(b"\xff" * 0x1000)

def put(off, val):
    struct.pack_into("<I", page, off, val)

put(0x010, 0x1000)       # CODEPAGESIZE
put(0x014, 0x100)        # CODESIZE (pages)
for off in (0x060, 0x064):                  # DEVICEID[0..1]
    put(off, rng.getrandbits(32))
for off in range(0x080, 0x0A0, 4):          # ER[0..3], IR[0..3]
    put(off, rng.getrandbits(32))
put(0x0A0, 0xFFFFFFFF)   # DEVICEADDRTYPE: random
put(0x0A4, rng.getrandbits(32))             # DEVICEADDR[0]
put(0x0A8, 0xFFFF0000 | rng.getrandbits(16))  # DEVICEADDR[1]
put(0x100, 0x52840)      # INFO.PART
put(0x104, 0x41414430)   # INFO.VARIANT "AAD0"
put(0x108, 0x2004)       # INFO.PACKAGE QI
put(0x10C, 0x100)        # INFO.RAM 256 KiB
put(0x110, 0x400)        # INFO.FLASH 1 MiB

open(out, "wb").write(page)
