#!/usr/bin/env python3
"""Delta (changes-only) firmware patches for LoRa OTA. Stdlib only.

A patch rebuilds NEW from BASE (the image the target runs now) with a
streaming decoder small enough for an nRF52 (src/helpers/LoraOTADelta.cpp):
it reads the patch front to back once, reads BASE mostly front to back, and
writes NEW strictly front to back.

Format "MCD1" (all integers little endian; varints are LEB128):

  header  magic "MCD1", flags u8, base_size u32, new_size u32
  body    (raw deflate when flags bit0 is set, see below) a list of
          records until new_size bytes are out:
            add varint, extra varint, seek zigzag-varint,
            add-region  : (zeros varint, n varint, n diff bytes) pairs
                          covering `add` bytes: NEW = BASE + diff (mod 256)
            extra-region: `extra` literal bytes of NEW
          then the base cursor moves by add + seek (bsdiff's control triple).

The matching is bsdiff's (Percival's scan loop) on a k-gram index instead of
a suffix array: firmware rebuilt after a small change keeps most code at a
fixed shift, with sparse differences where an address moved. Those runs come
out as add-regions that are mostly zeros.

Compression (flags bit0): raw deflate (RFC 1951, zlib's, so stdlib) with a
2 KiB window (WIN_BITS): the target's inflater keeps that window plus ~1 KB
of Huffman tables. The sparse diff bytes of a code shift repeat a handful of
values at short gaps, which Huffman coding packs well (an ESP32 rebuild with
128 bytes of new code: 64 KB of body, 23 KB deflated).

The patch is NOT trusted: the target hashes what it decoded and checks that
against the signed sha256 of NEW, so a patch that decodes to anything else
never activates.
"""
import struct

MAGIC = b"MCD1"
HDR = struct.Struct("<4sBII")
FLAG_DEFLATE = 0x01
WIN_BITS = 11        # deflate window: firmware LORA_OTA_DELTA_WIN_BITS

K = 8               # k-gram length of the match index
MAX_CANDIDATES = 24  # positions remembered per k-gram (0x00/0xFF runs repeat endlessly)


class DeltaError(Exception):
    pass


# ---------------------------------------------------------------- varints

def _uv(n, out):
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return


def _zz(n):
    return (n << 1) ^ (n >> 63) if n < 0 else n << 1


def _unzz(n):
    return (n >> 1) ^ -(n & 1)


# ---------------------------------------------------------------- matching

def _common(a, ai, b, bi, limit):
    """length of the common prefix of a[ai:] and b[bi:], at most limit"""
    n = 0
    step = 256
    while n < limit:
        s = min(step, limit - n)
        if a[ai + n:ai + n + s] == b[bi + n:bi + n + s]:
            n += s
            continue
        if s == 1:
            break
        step = max(1, s // 2)
    return n


class _Index:
    def __init__(self, base):
        self.base = base
        idx = {}
        mv = base
        for i in range(len(base) - K + 1):
            key = mv[i:i + K]
            lst = idx.get(key)
            if lst is None:
                idx[key] = [i]
            elif len(lst) < MAX_CANDIDATES:
                lst.append(i)
        self.idx = idx

    def search(self, new, scan, prefer):
        """longest match of new[scan:] in base: (len, pos); prefers pos == prefer"""
        if scan + K > len(new):
            return 0, 0
        cands = self.idx.get(new[scan:scan + K])
        if not cands:
            return 0, 0
        best, bpos = 0, 0
        limit = len(new) - scan
        if 0 <= prefer < len(self.base):
            n = _common(new, scan, self.base, prefer, min(limit, len(self.base) - prefer))
            if n >= K:
                best, bpos = n, prefer
        for p in cands:
            n = _common(new, scan, self.base, p, min(limit, len(self.base) - p))
            if n > best:
                best, bpos = n, p
        return best, bpos


def _controls(base, new):
    """bsdiff's scan loop -> [(add, extra, seek, lastscan, lastpos)]"""
    index = _Index(base)
    oldsize, newsize = len(base), len(new)
    out = []
    scan = ln = pos = lastscan = lastpos = lastoffset = 0
    while scan < newsize:
        oldscore = 0
        scan += ln
        scsc = scan
        while scan < newsize:
            ln, pos = index.search(new, scan, scan + lastoffset)
            while scsc < scan + ln:
                if scsc + lastoffset < oldsize and base[scsc + lastoffset] == new[scsc]:
                    oldscore += 1
                scsc += 1
            if (ln == oldscore and ln != 0) or ln > oldscore + 8:
                break
            if scan + lastoffset < oldsize and base[scan + lastoffset] == new[scan]:
                oldscore -= 1
            scan += 1
        if ln != oldscore or scan == newsize:
            s = sf = lenf = 0
            i = 0
            while lastscan + i < scan and lastpos + i < oldsize:
                if base[lastpos + i] == new[lastscan + i]:
                    s += 1
                i += 1
                if s * 2 - i > sf * 2 - lenf:
                    sf, lenf = s, i
            lenb = 0
            if scan < newsize:
                s = sb = 0
                i = 1
                while scan >= lastscan + i and pos >= i:
                    if base[pos - i] == new[scan - i]:
                        s += 1
                    if s * 2 - i > sb * 2 - lenb:
                        sb, lenb = s, i
                    i += 1
            if lastscan + lenf > scan - lenb:
                overlap = (lastscan + lenf) - (scan - lenb)
                s = ss = lens = 0
                for i in range(overlap):
                    if new[lastscan + lenf - overlap + i] == base[lastpos + lenf - overlap + i]:
                        s += 1
                    if new[scan - lenb + i] == base[pos - lenb + i]:
                        s -= 1
                    if s > ss:
                        ss, lens = s, i + 1
                lenf += lens - overlap
                lenb -= lens
            extra = (scan - lenb) - (lastscan + lenf)
            seek = (pos - lenb) - (lastpos + lenf)
            out.append((lenf, extra, seek, lastscan, lastpos))
            lastscan, lastpos, lastoffset = scan - lenb, pos - lenb, pos - scan
    return out


# ---------------------------------------------------------------- body

def _body(base, new):
    out = bytearray()
    for add, extra, seek, ns, bp in _controls(base, new):
        _uv(add, out)
        _uv(extra, out)
        _uv(_zz(seek), out)
        diff = bytes((new[ns + i] - base[bp + i]) & 0xFF for i in range(add))
        i = 0
        while i < add:
            z = i
            while z < add and diff[z] == 0:
                z += 1
            n = z
            # a literal run ends at 3+ zeros (a pair costs at least 2 bytes)
            while n < add and not (diff[n] == 0 and diff[n + 1:n + 3] == b"\0\0"):
                n += 1
            _uv(z - i, out)
            _uv(n - z, out)
            out += diff[z:n]
            i = n
        out += new[ns + add:ns + add + extra]
    return bytes(out)


# ---------------------------------------------------------------- deflate

def deflate(data):
    import zlib
    c = zlib.compressobj(9, zlib.DEFLATED, -WIN_BITS, 9)
    return c.compress(data) + c.flush()


def inflate(data):
    import zlib
    d = zlib.decompressobj(-WIN_BITS)
    try:
        out = d.decompress(data) + d.flush()
    except zlib.error as e:
        raise DeltaError(f"inflate: {e}")
    if not d.eof or d.unused_data:
        raise DeltaError("inflate: stream does not end where the patch does")
    return out


# ---------------------------------------------------------------- API

def make_patch(base: bytes, new: bytes, compress=None) -> bytes:
    """Patch from base to new. compress None = deflate it if that is smaller."""
    body = _body(base, new)
    if compress is None or compress:
        packed = deflate(body)
        if compress or len(packed) < len(body):
            return HDR.pack(MAGIC, FLAG_DEFLATE, len(base), len(new)) + packed
    return HDR.pack(MAGIC, 0, len(base), len(new)) + body


def apply_patch(base: bytes, patch: bytes) -> bytes:
    """Reference decoder (the firmware's does the same, streaming)."""
    if len(patch) < HDR.size:
        raise DeltaError("short patch")
    magic, flags, base_size, new_size = HDR.unpack_from(patch)
    if magic != MAGIC or flags & ~FLAG_DEFLATE:
        raise DeltaError("not a MCD1 patch")
    if base_size > len(base):
        raise DeltaError("patch wants a bigger base")
    body = patch[HDR.size:]
    if flags & FLAG_DEFLATE:
        body = inflate(body)
    out = bytearray()
    p = 0
    bpos = 0

    def uv():
        nonlocal p
        v = sh = 0
        while True:
            if p >= len(body) or sh > 28:
                raise DeltaError("bad varint")
            b = body[p]
            p += 1
            v |= (b & 0x7F) << sh
            sh += 7
            if not b & 0x80:
                return v

    while len(out) < new_size:
        add, extra, seek = uv(), uv(), _unzz(uv())
        if len(out) + add + extra > new_size or bpos + add > base_size:
            raise DeltaError("record out of range")
        done = 0
        while done < add:
            z, n = uv(), uv()
            if z + n == 0 or done + z + n > add or p + n > len(body):
                raise DeltaError("add-region out of range")
            out += base[bpos + done:bpos + done + z]
            for i in range(n):
                out.append((base[bpos + done + z + i] + body[p + i]) & 0xFF)
            p += n
            done += z + n
        if p + extra > len(body):
            raise DeltaError("extra out of range")
        out += body[p:p + extra]
        p += extra
        bpos += add + seek
        if not 0 <= bpos <= base_size:
            raise DeltaError("seek out of range")
    if p != len(body):
        raise DeltaError("trailing bytes")
    return bytes(out)


if __name__ == "__main__":
    import sys, time
    b, n = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
    t = time.monotonic()
    raw = make_patch(b, n, compress=False)
    packed = make_patch(b, n, compress=True)
    assert apply_patch(b, raw) == n and apply_patch(b, packed) == n
    print(f"{len(n)} new: patch {len(packed)} deflated, {len(raw)} raw ({time.monotonic() - t:.1f} s)")
