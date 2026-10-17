#!/usr/bin/env python3
"""Reference vectors for test_findhub.cpp.

EID math is GoogleFindMyTools' FMDNCrypto/eid_generator.py (which decrypts real
Google trackers' reports, so it is the ground truth), restated with
`cryptography` and a textbook affine secp160r1 (nixpkgs flags python `ecdsa`
insecure). Run: nix shell --impure --expr 'with import <nixpkgs> {};
python3.withPackages (p: [p.cryptography])' -c python3 gen_vectors.py
"""
import hashlib, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# SEC 2 secp160r1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF
A = P - 3
N = 0x0100000000000000000001F4C8F927AED3CA752257
G = (0x4A96B5688EF573284664698968C38BB913CBFC82, 0x23A628553168947D59DCC912042351377AC5FB32)

def _add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if p1 == p2: l = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else: l = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (l * l - x1 - x2) % P
    return (x3, (l * (x1 - x3) - y1) % P)

def mul(k, pt=G):
    acc = None
    while k:
        if k & 1: acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc

K = 10

def aes_ecb(key, data, decrypt=False):
    c = Cipher(algorithms.AES(key), modes.ECB())
    op = c.decryptor() if decrypt else c.encryptor()
    return op.update(data) + op.finalize()

def eid(eik, counter):
    ts = (counter & ~((1 << K) - 1)).to_bytes(4, "big")
    seed = b"\xff" * 11 + bytes([K]) + ts + b"\x00" * 11 + bytes([K]) + ts
    r = int.from_bytes(aes_ecb(eik, seed), "big") % N
    R = mul(r)
    r20 = (r & ((1 << 160) - 1)).to_bytes(20, "big")
    return R[0].to_bytes(20, "big"), hashlib.sha256(r20).digest()[31]

def derived(eik, which):
    return hashlib.sha256(eik + bytes([which])).digest()[:8]

def auth(key, nonce, data_id, data_len, add=b"", response=False):
    msg = bytes([1]) + nonce + bytes([data_id, data_len]) + add + (b"\x01" if response else b"")
    return hmac.new(key, msg, hashlib.sha256).digest()[:8]

def c(b):
    return "{" + ", ".join(f"0x{x:02x}" for x in b) + "}"

if __name__ == "__main__":
    eik = bytes(range(32))
    eik2 = bytes.fromhex("a3" * 16 + "5c" * 16)
    print(f"// EIK_A = {c(eik)}")
    for e, name in ((eik, "A"), (eik2, "B")):
        for counter in (0, 1023, 1024, 1700000000 - 1690000000, 0xFFFFFC00):
            x, hx = eid(e, counter)
            print(f'{{EIK_{name}, {counter}u, {c(x)}, 0x{hx:02x}}},')
    print("ring key A", c(derived(eik, 2)))
    print("recovery key A", c(derived(eik, 1)))
    print("utp key A", c(derived(eik, 3)))
    nonce = bytes.fromhex("0102030405060708")
    rk = derived(eik, 2)
    print("ring req auth", c(auth(rk, nonce, 0x05, 12, bytes([0xff, 0x00, 0x64, 0x00]))))
    print("ring notify auth (started, ff, 100)", c(auth(rk, nonce, 0x05, 12, bytes([0x00, 0xff, 0x00, 0x64]), True)))
