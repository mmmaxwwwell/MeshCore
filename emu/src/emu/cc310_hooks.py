#!/usr/bin/env python3
"""Generate Renode CPU hooks that stand in for the nRF52840 CC310 behind Adafruit's nRFCrypto
wrapper: real P-256 key generation and ECDH computed on the host, key material kept inside the
firmware's own nRFCrypto key objects (at object+8: 'EMUK' tag, then the key), so the firmware
binary is unchanged and BLE pairing stays LE Secure Connections.
usage: cc310_hooks.py firmware.elf > hooks.resc"""
import subprocess, sys, os

ELF = sys.argv[1]
NM = os.environ.get("NM", "arm-none-eabi-nm")
syms = {}
for line in subprocess.run([NM, "-C", ELF], capture_output=True, text=True).stdout.splitlines():
    p = line.split(" ", 2)
    if len(p) == 3 and p[1] in "Tt":
        syms[p[2]] = int(p[0], 16) & ~1

WANT = {
    "Adafruit_nRFCrypto::begin()": "begin",
    "Adafruit_nRFCrypto::end()": "end",
    "nRFCrypto_ECC::genKeyPair(nRFCrypto_ECC_PrivateKey&, nRFCrypto_ECC_PublicKey&)": "genkey",
    "nRFCrypto_ECC_PublicKey::toRaw(unsigned char*, unsigned long)": "pub_toraw",
    "nRFCrypto_ECC_PublicKey::fromRaw(unsigned char*, unsigned long)": "pub_fromraw",
    "nRFCrypto_ECC::SVDP_DH(nRFCrypto_ECC_PrivateKey&, nRFCrypto_ECC_PublicKey&, unsigned char*, unsigned long)": "dh",
}

PRELUDE = r'''
from System import Array, Byte
import os
from Antmicro.Renode.Peripherals.CPU import RegisterValue
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
A = P - 3
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
def inv(x): return pow(x, P - 2, P)
def add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if p1 == p2: l = (3 * x1 * x1 + A) * inv(2 * y1) % P
    else: l = (y2 - y1) * inv(x2 - x1) % P
    x3 = (l * l - x1 - x2) % P
    return (x3, (l * (x1 - x3) - y1) % P)
def mul(k, pt):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r
def rd(addr, n): return bytearray(machine.SystemBus.ReadBytes(addr, n))
def wr(addr, data): machine.SystemBus.WriteBytes(Array[Byte](bytearray(data)), addr)
def i2b(v): return bytearray((v >> (8 * (31 - i))) & 0xff for i in range(32))
def b2i(b):
    v = 0
    for c in b: v = (v << 8) | c
    return v
def reg(i): return self.GetRegisterUnsafe(i).RawValue
def ret(v=None):
    if v is not None: self.SetRegisterUnsafe(0, RegisterValue.Create(v, 32))
    self.PC = RegisterValue.Create(reg(14) & ~1, 32)
TAG = bytearray(b"EMUK")
'''

BODIES = {
    "begin": "ret(1)",
    "end": "ret()",
    # R0 = &private_key, R1 = &public_key
    "genkey": r'''
while True:
    d = b2i(bytearray(os.urandom(32))) % N
    if d: break
Q = mul(d, G)
wr(reg(0) + 8, TAG + i2b(d))
wr(reg(1) + 8, TAG + i2b(Q[0]) + i2b(Q[1]))
ret(1)''',
    # R0 = this (public key), R1 = buffer, R2 = size -> 0x04||X||Y, returns 65
    "pub_toraw": r'''
blob = rd(reg(0) + 8, 68)
if blob[:4] != TAG or reg(2) < 65:
    ret(0)
else:
    wr(reg(1), bytearray([4]) + blob[4:68]); ret(65)''',
    "pub_fromraw": r'''
raw = rd(reg(1), 65)
if reg(2) != 65 or raw[0] != 4:
    ret(0)
else:
    x = b2i(raw[1:33]); y = b2i(raw[33:65])
    if (y * y - (x * x * x + A * x + 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)) % P != 0:
        ret(0)
    else:
        wr(reg(0) + 8, TAG + raw[1:65]); ret(1)''',
    # R0 = &private_key, R1 = &peer_pubkey, R2 = shared_secret, R3 = bufsize -> X (big endian), returns 32
    "dh": r'''
pk = rd(reg(0) + 8, 36); qk = rd(reg(1) + 8, 68)
if pk[:4] != TAG or qk[:4] != TAG or reg(3) < 32:
    ret(0)
else:
    S = mul(b2i(pk[4:36]), (b2i(qk[4:36]), b2i(qk[36:68])))
    wr(reg(2), i2b(S[0])); ret(32)''',
}

for name, kind in WANT.items():
    if name not in syms:
        if kind in ("begin", "genkey", "dh"):
            sys.exit("missing symbol: " + name)
        sys.stderr.write("not linked, no hook: %s\n" % name)
        continue
    script = PRELUDE + BODIES[kind]
    print('cpu AddHook 0x%x """%s"""' % (syms[name], script.replace('"""', "'''")))
