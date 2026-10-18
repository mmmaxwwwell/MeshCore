#!/usr/bin/env python3
"""Firmware over LoRa for MeshCore repeaters and companions built with LORA_OTA (see README.md).

  lora_ota.py keygen                       make the signing key (once)
  lora_ota.py pubkey                       print it for -D LORA_OTA_PUBKEY
  lora_ota.py sign IMAGE --board TAG       write IMAGE.mcota (manifest + signature)
  lora_ota.py push  --companion C --target T [--password-file F] [--delta-from BASE] IMAGE
  lora_ota.py push  --slow [--duty PCT | --pace S] [--resume] ...  over the mesh, a little at a time
  lora_ota.py eta   IMAGE [--duty PCT | --pace S] [--hops N]           how long a --slow push takes
  lora_ota.py delta BASE NEW -o PATCH      make a changes-only patch (push --delta-from does this itself)
  lora_ota.py status|confirm --companion C --target T --password-file F
  lora_ota.py settings make --target HEX|board:TAG --set KEY=VALUE ... [--reboot] -o BUNDLE
  lora_ota.py settings diff --companion C --target T [--password-file F] --set KEY=VALUE ... [--reboot] -o BUNDLE
                                           a bundle of only the keys that differ from the node's values
  lora_ota.py settings eta BUNDLE [--hops N | --flood] [--duty PCT]     packets and airtime of a push
  lora_ota.py settings push --companion C --target T [--password-file F] BUNDLE
  lora_ota.py settings show|status|confirm|revert --companion C --target T [--password-file F]

C is a companion radio: a /dev/... serial path or a BLE address.
T is the target: a contact name or a public-key hex prefix. A repeater or room server target
takes the admin password; a companion target takes OTA only from radios it has
favourited.
"""
import argparse, asyncio, hashlib, json, math, os, random, signal, struct, sys, time

DEFAULT_KEY = os.path.expanduser("~/.config/meshcore/ota-signing.key")
MARKER = b"MCOTA-ROLLBACK-v1"
BOARD_LEN = 32

REQ_BEGIN, REQ_DATA, REQ_STATUS, REQ_FINISH, REQ_ABORT, REQ_CONFIRM, REQ_RADIO = 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
RADIO_IDLE_SECS = 90   # target drops the fast settings after this long without OTA traffic
CONFIRM_SECS = 60   # firmware LORA_OTA_CONFIRM_SECS
REBOOT_SECS = 6     # firmware LORA_OTA_REBOOT_DELAY_MS
BITMAP_CHUNKS = 128 * 8
COMPANION_FRAME = 176   # a stock companion's max command frame (BaseSerialInterface MAX_FRAME_SIZE)
CHUNK = COMPANION_FRAME - 1 - 32 - 7   # minus CMD_SEND_BINARY_REQ + pubkey, DATA's type + session + index
STATUS_NAMES = {0: "ok", 1: "bad state", 2: "bad session", 3: "bad signature (or image for another board)",
                4: "too big", 5: "flash error", 6: "incomplete", 7: "hash mismatch", 8: "no LoRa-OTA marker",
                9: "activate failed", 10: "running image (or a settings bundle) not confirmed yet ('ota confirm' first)", 11: "bad argument",
                12: "working", 13: "the target does not run the base image of this delta"}
OK, BAD_SESSION, INCOMPLETE, HASH_MISMATCH, WORKING = 0, 2, 6, 7, 12
BAD_ARG, BASE_MISMATCH = 11, 13
# BEGIN flags byte (payload offset 101); both may be set
FLAG_DELTA = 0x01  # DATA carries a patch against the running image; base sha8 @102 + patch size u32 @110 follow
FLAG_LONG = 0x02   # slow session, long idle timeout, persisted bitmap
LONG_IDLE_SECS = 6 * 3600   # firmware LORA_OTA_LONG_IDLE_MS
STATE_DIR = os.path.expanduser("~/.local/state/meshcore-lora-ota")
WORK_SECS = 240   # longest a BEGIN (erase/stage) or FINISH (verify) may take on the target


class OtaError(Exception):
    pass


class DeltaRefused(OtaError):
    """the target will not take this delta (other base, no delta support, no room): send it whole"""


def manifest_message(board: str, size: int, sha: bytes) -> bytes:
    b = board.encode()
    if len(b) > BOARD_LEN:
        raise OtaError(f"board tag longer than {BOARD_LEN} bytes")
    return b"MCOTA1" + b.ljust(BOARD_LEN, b"\0") + struct.pack("<I", size) + sha


# ---------------------------------------------------------------- signed settings (LoraOTASettings.h)

REQ_SET_DATA, REQ_SET_APPLY, REQ_SET_CTRL = 0x67, 0x68, 0x69
SET_OP_STATUS, SET_OP_CONFIRM, SET_OP_REVERT, SET_OP_GET = 0, 1, 2, 3
SET_DOMAIN = b"MCSET1"   # firmware manifests sign "MCOTA1"...: one can never pass for the other
SET_MAX_BUNDLE = 512
SET_MAX_ENTRIES = 24
SET_MIN_PREFIX = 6
SET_CONFIRM_SECS = 60    # firmware LORA_OTA_SET_CONFIRM_SECS
SET_SWITCH_SECS = 1.5    # firmware LORA_OTA_SET_SWITCH_MS: radio changes take effect after the OK reply
SET_REBOOT_SECS = 6      # firmware LORA_OTA_SET_REBOOT_MS: a reboot=1 bundle reboots the node this long after CONFIRM
SET_REBOOT_KEY = "reboot"   # control entry (value "1"), not a setting
SET_CHUNK = COMPANION_FRAME - 1 - 32 - 6   # CMD_SEND_BINARY_REQ + pubkey, then type + total + offset + n
STATUS_NAMES.update({16: "version not newer than the last applied bundle", 17: "bundle is for another node",
                     18: "setting not on the whitelist", 19: "value out of range", 20: "bundle does not parse",
                     21: "another bundle is still on probation (confirm or revert it first)",
                     22: "this node has no such setting", 23: "could not save on the node"})
# the whitelist (the firmware's KEY_NAMES); the node checks the values again
SETTINGS_KEYS = ["radio", "tx", "af", "rxdelay", "txdelay", "direct.txdelay", "multi.acks", "path.hash.mode",
                 "int.thresh", "agc.reset.interval", "radio.rxgain", "flood.max", "flood.max.unscoped",
                 "flood.max.advert", "advert.interval", "flood.advert.interval", "loop.detect", "repeat", "regions",
                 "posreport.interval", "overlay"]
REPEATER_ONLY_KEYS = {"flood.max", "flood.max.unscoped", "flood.max.advert", "advert.interval",
                      "flood.advert.interval", "loop.detect", "regions"}
# our companion features: whitelisted only by firmware built with them (else "not on the whitelist")
COMPANION_FEATURE_KEYS = {"posreport.interval": "POSITION_REPORT", "overlay": "OVERLAY_MESH"}
# repeater CLI to read a key's current value
CLI_GET = {k: f"get {k}" for k in SETTINGS_KEYS}
CLI_GET["regions"] = "region list allowed"


def parse_target(t: str):
    """'board:TAG' or a public-key hex prefix (at least 6 bytes) -> (kind, bytes)"""
    if t.startswith("board:"):
        b = t[6:].encode()
        if not b or len(b) > BOARD_LEN:
            raise OtaError(f"board tag must be 1..{BOARD_LEN} bytes")
        return 2, b
    try:
        b = bytes.fromhex(t)
    except ValueError:
        raise OtaError(f"target {t!r}: give the node's public key (hex, at least {SET_MIN_PREFIX * 2} digits) "
                       "or board:TAG")
    if not SET_MIN_PREFIX <= len(b) <= 32:
        raise OtaError(f"target prefix must be {SET_MIN_PREFIX}..32 bytes")
    return 1, b


def bundle_body(version: int, target, entries) -> bytes:
    kind, tgt = target
    if not 0 < len(entries) <= SET_MAX_ENTRIES:
        raise OtaError(f"1..{SET_MAX_ENTRIES} settings per bundle")
    out = struct.pack("<IBB", version, kind, len(tgt)) + tgt + bytes([len(entries)])
    for k, v in entries:
        kb, vb = k.encode(), v.encode()
        if len(kb) > 255 or len(vb) > 255:
            raise OtaError(f"{k}: too long")
        out += bytes([len(kb)]) + kb + bytes([len(vb)]) + vb
    return out


def check_entries(entries):
    """the sender's whitelist check (the node checks everything again)"""
    seen = set()
    for k, v in entries:
        if k == SET_REBOOT_KEY:
            raise OtaError("reboot is not a setting: use --reboot")
        if k not in SETTINGS_KEYS:
            raise OtaError(f"{k!r} is not a setting this can change (whitelist: {', '.join(SETTINGS_KEYS)})")
        if k == "overlay" and v != "off":
            raise OtaError("overlay: only 'off' (turning it on needs the region name, which is the overlay's key: "
                           "use '#ovlset on' or the app)")
        if k in seen:
            raise OtaError(f"{k} given twice")
        seen.add(k)


def make_bundle(entries, target, version, key, check=True, reboot=False) -> bytes:
    """entries: [(key, value)]. Signed message: "MCSET1" || body; bundle = body || sig.
    reboot: add the control entry reboot=1 (the node reboots once, after the CONFIRM)."""
    if check:
        check_entries(entries)
    if reboot:
        entries = list(entries) + [(SET_REBOOT_KEY, "1")]
    body = bundle_body(version, target, entries)
    blob = body + key.sign(SET_DOMAIN + body)
    if len(blob) > SET_MAX_BUNDLE:
        raise OtaError(f"bundle is {len(blob)} bytes, the node takes {SET_MAX_BUNDLE}")
    return blob


def parse_bundle(blob: bytes) -> dict:
    body, sig = blob[:-64], blob[-64:]
    if len(body) < 7:
        raise OtaError("not a settings bundle")
    version, kind, tlen = struct.unpack("<IBB", body[:6])
    i = 6
    tgt = body[i:i + tlen]; i += tlen
    n = body[i]; i += 1
    entries = []
    for _ in range(n):
        kl = body[i]; i += 1
        k = body[i:i + kl].decode(); i += kl
        vl = body[i]; i += 1
        v = body[i:i + vl].decode(); i += vl
        entries.append((k, v))
    if i != len(body):
        raise OtaError("not a settings bundle (trailing bytes)")
    return {"version": version, "target": (kind, tgt), "entries": entries, "sig": sig}


def bundle_reboots(b: dict) -> bool:
    return any(k == SET_REBOOT_KEY for k, _ in b["entries"])


def norm_value(key, v):
    """a value as the node would hold it, for comparing what we want with what the node reports"""
    v = str(v).strip()
    if v.startswith("> "):
        v = v[2:].strip()
    if key == "regions":
        return frozenset(x.strip() for x in v.split(",") if x.strip())
    out = []
    for part in v.split(","):
        part = part.strip().lower()
        try:
            out.append(round(float(part) * 1000))
        except ValueError:
            out.append(part)
    return tuple(out)


def diff_entries(current: dict, wanted):
    """[(key, value)] of the wanted settings whose value differs from current (unknown counts as different)"""
    changed = []
    for k, v in wanted:
        cur = current.get(k)
        if cur is None or str(cur).startswith("?") or norm_value(k, cur) != norm_value(k, v):
            changed.append((k, v))
    return changed


def target_text(target):
    kind, t = target
    return f"board {t.decode()}" if kind == 2 else f"node {t.hex()}"


def radio_tuple(value: str):
    """'910.525,62.5,7,5' -> (910.525, 62.5, 7, 5), as set_radio takes it"""
    f, bw, sf, cr = value.split(",")
    return float(f), float(bw), int(sf), int(cr)


def set_status(r) -> dict:
    """CTRL STATUS/CONFIRM/REVERT reply"""
    if not r or len(r) < 13:
        return None
    return {"status": r[0], "pending": r[1], "was": r[2], "version": struct.unpack("<I", r[3:7])[0],
            "pending_version": struct.unpack("<I", r[7:11])[0], "secs_left": struct.unpack("<H", r[11:13])[0],
            # older firmware sends 13 bytes: no reboot flags
            "reboot_asked": bool(len(r) > 13 and r[13] & 1), "reboot_due": bool(len(r) > 13 and r[13] & 2)}


class SettingsSender:
    """Pushes one bundle over a link (see OtaSender) and confirms it.

    radio: the sending companion's radio, with async get() -> tuple and
    async set(tuple); used when the bundle changes the node's radio: after
    APPLY the companion follows the node to send the CONFIRM, and goes back
    to its own settings afterwards, whatever happened. sleep: async, seconds
    (the simulator advances its clock)."""

    def __init__(self, link, bundle, radio=None, log=print, timeout=8.0, retries=6, sleep=None):
        self.link, self.blob, self.radio, self.log = link, bundle, radio, log
        self.timeout, self.retries = timeout, retries
        self.sleep = sleep or asyncio.sleep
        try:
            self.b = parse_bundle(bundle)
        except (OtaError, IndexError, UnicodeDecodeError, struct.error):
            self.b = {"version": 0, "entries": []}   # not ours to judge: the node checks it (tests send junk on purpose)
        self.version = self.b["version"]
        self.reboot = bundle_reboots(self.b)
        self.new_radio = next((radio_tuple(v) for k, v in self.b["entries"] if k == "radio"), None)

    async def ask(self, payload, what, tries=None):
        for attempt in range(tries or self.retries):
            r = await self.link.request(payload, True, self.timeout)
            if r:
                return r
            self.log(f"  {what}: no reply (attempt {attempt + 1})")
        return None

    async def ctrl(self, op, tries=None):
        return set_status(await self.ask(bytes([REQ_SET_CTRL, op]), "settings", tries))

    async def upload(self):
        total = len(self.blob)
        have, stalls = 0, 0
        while have < total:
            n = min(SET_CHUNK, total - have)
            r = await self.ask(bytes([REQ_SET_DATA]) + struct.pack("<HHB", total, have, n) + self.blob[have:have + n], "DATA")
            if r is None:
                raise OtaError("DATA: target not answering")
            if r[0] != OK:
                raise OtaError(f"DATA refused: {STATUS_NAMES.get(r[0], r[0])}")
            got = struct.unpack("<H", r[1:3])[0]
            stalls = stalls + 1 if got <= have else 0
            if stalls > 4:
                raise OtaError("DATA: no progress")
            have = got

    async def apply(self):
        """-> 'ok' | 'unknown' (it was being checked when the replies stopped). Raises on a refusal."""
        h = hashlib.sha256(self.blob).digest()[:8]
        req = bytes([REQ_SET_APPLY]) + struct.pack("<H", len(self.blob)) + h
        seen_working, t0 = False, time.monotonic()
        for _ in range(60):
            r = await self.ask(req, "APPLY")
            if r is None:
                if seen_working:
                    return "unknown"
                raise OtaError("APPLY: target not answering")
            if r[0] == WORKING:
                seen_working = True
                await self.sleep(1)
                continue
            if r[0] == INCOMPLETE:
                await self.upload()
                continue
            if r[0] != OK:
                raise OtaError(f"settings refused: {STATUS_NAMES.get(r[0], r[0])}")
            left = struct.unpack("<H", r[5:7])[0] if len(r) >= 7 else SET_CONFIRM_SECS
            self.log(f"node: bundle v{self.version} applied, on probation ({left} s to confirm)")
            return "ok"
        raise OtaError("APPLY: the node never finished checking the bundle")

    async def confirm(self, window):
        """CONFIRM until the node says it is confirmed; False if it never answers."""
        t0 = None
        while True:
            st = await self.ctrl(SET_OP_CONFIRM, tries=1)
            if st:
                if st["status"] == OK and st["pending"] == 0 and st["version"] >= self.version:
                    if st["version"] > self.version:
                        raise OtaError(f"the node has a newer bundle (v{st['version']})")
                    self.log("node: settings confirmed" + ("" if st["was"] else " (an earlier CONFIRM landed)"))
                    if self.reboot and st["was"]:
                        self.log(f"node: reboots in ~{SET_REBOOT_SECS} s (the bundle asked for it)")
                    return True
                if st["status"] == OK and st["pending"] == 0 and st["version"] < self.version:
                    raise OtaError("the node does not have this bundle (it was not applied)")
                if st["status"] not in (OK, WORKING):
                    raise OtaError(f"confirm failed on the node: {STATUS_NAMES.get(st['status'], st['status'])}")
            await self.sleep(1)
            window -= 1 + (0 if st else self.timeout)
            if window <= 0:
                return False

    async def run(self, confirm=True):
        """upload, apply, follow a radio change, confirm, put the companion back. -> True = confirmed"""
        await self.upload()
        await self.apply()
        if not confirm:
            self.log(f"not confirming: the node reverts {SET_CONFIRM_SECS} s after the change")
            return False
        own = None
        try:
            if self.new_radio and self.radio:
                own = await self.radio.get()
                if tuple(own[:4]) != tuple(self.new_radio):
                    await self.sleep(SET_SWITCH_SECS + 1)   # the node switches 1.5 s after its OK reply
                    await self.radio.set(self.new_radio)
                    self.log(f"companion follows to {self.new_radio} to confirm")
                else:
                    own = None
            ok = await self.confirm(SET_CONFIRM_SECS - 10)
        finally:
            if own is not None:
                await self.radio.set(own)
                self.log("companion back on its own radio settings")
        if not ok:
            self.log(f"no CONFIRM got through: the node puts its old settings back by itself "
                     f"within {SET_CONFIRM_SECS} s of the change")
        return ok


# ---------------------------------------------------------------- signing

def load_key(path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with open(path) as f:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))


def pubkey_hex(key):
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def cmd_keygen(a):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    if os.path.exists(a.key):
        raise OtaError(f"{a.key} exists; refusing to overwrite a signing key")
    os.makedirs(os.path.dirname(a.key), exist_ok=True)
    k = Ed25519PrivateKey.generate()
    seed = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    fd = os.open(a.key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(seed.hex() + "\n")
    print(pubkey_hex(k))


def cmd_pubkey(a):
    print(pubkey_hex(load_key(a.key)))


def sign_image(image: bytes, board: str, key) -> dict:
    if image[:1] == b"\xe9" and len(image) > 0x8002 and image[0x8000:0x8002] == b"\xaa\x50":   # ESP32 merged
        raise OtaError("this is a merged USB image (bootloader + partition table); sign the app-only firmware.bin")
    if MARKER not in image:
        raise OtaError("image has no LoRa-OTA marker: it could not confirm or roll back, the target would refuse it")
    sha = hashlib.sha256(image).digest()
    sig = key.sign(manifest_message(board, len(image), sha))
    return {"format": "mcota1", "board": board, "size": len(image), "sha256": sha.hex(),
            "sig": sig.hex(), "pubkey": pubkey_hex(key)}


def cmd_sign(a):
    image = open(a.image, "rb").read()
    m = sign_image(image, a.board, load_key(a.key))
    with open(a.image + ".mcota", "w") as f:
        json.dump(m, f, indent=1)
    print(f"{a.image}.mcota: board {a.board}, {len(image)} bytes, key {m['pubkey'][:16]}...")


def load_signed(path):
    image = open(path, "rb").read()
    m = json.load(open(path + ".mcota"))
    if m.get("format") != "mcota1" or m["size"] != len(image) or bytes.fromhex(m["sha256"]) != hashlib.sha256(image).digest():
        raise OtaError(f"{path}.mcota does not match {path}")
    return image, m


def running_sha(image: bytes) -> bytes:
    """What the target reports for this image once it runs it (CONFIRM's sha):
    ESP32 reports the SHA-256 esptool appends to the image (byte 23 of the
    header says one is appended), which covers everything but those last 32
    bytes; nRF52 hashes the app image itself."""
    if image[:1] == b"\xe9" and len(image) > 64 and image[23] == 1:
        return image[-32:]
    return hashlib.sha256(image).digest()


# ---------------------------------------------------------------- airtime and pacing (--slow)

MESH_PRESET = (62.5, 7, 5)   # bw kHz, SF, CR 4/x: the US/CT Mesh MeshCore preset
PREAMBLE = 16                # MeshCore's preamble length (CustomSX1262 begin)
DUTY_DEFAULT = 2.0           # % of the channel's airtime the transfer may use, relays included
FLOOD_TX = 10                # transmissions per packet assumed for a flood (unknown repeater count)
JITTER = 0.25                # +-25 % on every gap: never lock step with another periodic sender
SLOW_ROUND = 256             # --slow: DATA chunks between STATUS polls (progress lands in the state file)
REPLY_LEN = {REQ_BEGIN: 9, REQ_STATUS: 5 + 128, REQ_FINISH: 1, REQ_ABORT: 1, REQ_CONFIRM: 14,
             REQ_SET_DATA: 3, REQ_SET_APPLY: 7, REQ_SET_CTRL: 14}


def lora_airtime(pl, bw_khz=MESH_PRESET[0], sf=MESH_PRESET[1], cr=MESH_PRESET[2], preamble=PREAMBLE):
    """Time on air (s) of a pl-byte LoRa packet: explicit header, CRC on (Semtech AN1200.13)."""
    tsym = (1 << sf) / (bw_khz * 1000.0)
    de = 1 if tsym > 0.016 else 0   # low data rate optimisation
    n = 8 + max(math.ceil((8 * pl - 4 * sf + 28 + 16) / (4 * (sf - 2 * de))) * cr, 0)
    return (preamble + 4.25) * tsym + n * tsym


def datagram_len(body, path_bytes=0):
    """On-air bytes of a REQ/RESPONSE datagram carrying `body` (the 4-byte tag added):
    header + path_len + path + dest/src hash + MAC + AES-padded ciphertext."""
    return 1 + 1 + path_bytes + 1 + 1 + 2 + 16 * math.ceil((4 + body) / 16)


class Pacer:
    """Spaces every transmission of a --slow push: either a fixed --pace (s between
    packets) or a --duty share of the channel's airtime, counting each relay's
    re-send of the packet and the target's reply. sleep/clock are injectable (sim)."""

    def __init__(self, duty=None, pace=None, hops=0, hash_size=1, flood=False, jitter=JITTER,
                 sleep=asyncio.sleep, clock=time.monotonic, rng=random.random):
        if pace is None and duty is None:
            duty = DUTY_DEFAULT
        self.duty, self.pace, self.jitter = duty, pace, jitter
        self.hops, self.flood = hops, flood
        self.tx = FLOOD_TX if flood else hops + 1   # transmissions of each packet on the channel
        self.path_bytes = 0 if flood else hops * hash_size
        self.sleep, self.clock, self.rng = sleep, clock, rng
        self.next = None
        self.airtime = 0.0   # channel seconds spent so far
        self.packets = 0

    def cost(self, req_len, reply_len=0):
        t = lora_airtime(datagram_len(req_len, self.path_bytes))
        if reply_len:
            t += lora_airtime(datagram_len(reply_len, self.path_bytes))
        return t * self.tx

    def gap(self, req_len, reply_len=0):
        return self.pace if self.pace is not None else self.cost(req_len, reply_len) / (self.duty / 100.0)

    async def before(self, payload):
        reply = REPLY_LEN.get(payload[0], 0)
        now = self.clock()
        if self.next is not None and now < self.next:
            await self.sleep(self.next - now)
        g = self.gap(len(payload), reply) * (1 + self.jitter * (2 * self.rng() - 1))
        self.next = self.clock() + g
        self.airtime += self.cost(len(payload), reply)
        self.packets += 1

    def describe(self):
        how = f"one packet per {self.pace:g} s" if self.pace is not None else f"{self.duty:g}% of the channel's airtime"
        route = "FLOOD" if self.flood else ("direct" if self.hops == 0 else f"{self.hops} hop(s)")
        return f"{how}, {route} ({self.tx} transmission(s) per packet)"


def slow_eta(size, pacer, chunk=CHUNK):
    """Seconds a lossless --slow push takes: DATA plus the STATUS polls between rounds."""
    n = math.ceil(size / chunk)
    data = n * pacer.gap(1 + 6 + chunk)
    polls = math.ceil(n / SLOW_ROUND) + math.ceil(n / BITMAP_CHUNKS) + 2   # rounds + the final sweep + BEGIN/FINISH
    return data + polls * pacer.gap(7, REPLY_LEN[REQ_STATUS])


def settings_packets(size):
    """[(request length, reply length)] of a lossless settings push: STATUS, the DATA chunks,
    APPLY (WORKING, then the result), CONFIRM"""
    out = [(2, REPLY_LEN[REQ_SET_CTRL])]
    for off in range(0, size, SET_CHUNK):
        out.append((6 + min(SET_CHUNK, size - off), REPLY_LEN[REQ_SET_DATA]))
    out += [(11, 1), (11, REPLY_LEN[REQ_SET_APPLY]), (2, REPLY_LEN[REQ_SET_CTRL])]
    return out


def settings_eta(size, pacer):
    """(round trips, channel airtime s, seconds at the pacer's duty) of a lossless settings push"""
    pk = settings_packets(size)
    return len(pk), sum(pacer.cost(q, a) for q, a in pk), sum(pacer.gap(q, a) for q, a in pk)


def describe_settings_eta(size, hops=0, flood=False, duty=None):
    p = Pacer(duty=duty, hops=hops, flood=flood)
    n, air, t = settings_eta(size, p)
    route = "flood" if flood else ("direct" if hops == 0 else f"{hops} hop(s)")
    return (f"{n} round trips, {route}: {air:.1f} s of channel airtime ({p.tx} transmission(s) per packet); "
            f"~{t:.0f} s if held to {p.duty:g}% of the channel")


def fmt_secs(t):
    return f"{t / 3600:.1f} h" if t >= 5400 else f"{t / 60:.0f} min"


def save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)   # a crash mid-write keeps the previous state


def state_path(target_pubkey, sha_hex):
    return os.path.join(STATE_DIR, f"{target_pubkey[:12]}-{sha_hex[:16]}.json")


# ---------------------------------------------------------------- protocol

class OtaSender:
    """Drives one transfer over a link with:
         async request(payload, want_reply, timeout) -> reply body | None
       (None = no reply in time). Transport-agnostic: radio or simulator."""

    def __init__(self, link, image, manifest, log=print, status_timeout=8.0, retries=6, keepalive=None, chunk=CHUNK,
                 pacer=None, state_file=None, resume=None, target="", patch=None, base_sha8=None):
        """patch + base_sha8: send a delta (DATA carries the patch); the manifest still
        describes the NEW image, which the target rebuilds and checks against it."""
        self.link, self.m, self.log = link, manifest, log
        self.delta = patch is not None
        self.image = patch if self.delta else image   # the bytes DATA carries
        self.base_sha8 = base_sha8
        self.keepalive = keepalive   # async callable, run before each round
        self.status_timeout, self.retries = status_timeout, retries
        self.want_chunk = chunk
        self.work_poll = 1.0 if status_timeout else 0
        self.session = self.chunk = self.chunks = None
        # --slow: every transmission paced, a LONG session on the target, progress in a state file
        self.pacer, self.state_file, self.target = pacer, state_file, target
        self.long = pacer is not None
        self.flags = (FLAG_LONG if self.long else 0) | (FLAG_DELTA if self.delta else 0)
        self.round = SLOW_ROUND if self.long else None
        self.acked = None        # bytearray bitmap: chunks the target has confirmed (STATUS) this session
        self.resume_state = resume   # a loaded state file (dict) to continue from
        self.rebegins = 0
        self.long_ok = None      # did the target accept LONG?

    async def tx(self, payload, want_reply, timeout):
        if self.pacer:
            await self.pacer.before(payload)
        return await self.link.request(payload, want_reply, timeout)

    async def ask(self, payload, what):
        for attempt in range(self.retries):
            r = await self.tx(payload, True, self.status_timeout)
            if r:
                return r
            self.log(f"  {what}: no reply (attempt {attempt + 1})")
        raise OtaError(f"{what}: target not answering")

    async def ask_done(self, payload, what):
        """BEGIN/FINISH answer WORKING while the target prepares/verifies: ask again."""
        t0 = time.monotonic()
        while True:
            r = await self.ask(payload, what)
            if r[0] != WORKING:
                return r
            if time.monotonic() - t0 > WORK_SECS:
                raise OtaError(f"{what}: target still working after {WORK_SECS} s")
            await asyncio.sleep(self.work_poll)

    async def begin(self):
        p = (bytes([REQ_BEGIN]) + struct.pack("<I", self.m["size"]) + bytes.fromhex(self.m["sha256"]) +
             bytes.fromhex(self.m["sig"]) + bytes([self.want_chunk]))
        if self.flags:
            p += bytes([self.flags])
        if self.delta:
            assert len(self.base_sha8) == 8
            p += self.base_sha8 + struct.pack("<I", len(self.image))
        r = await self.ask_done(p, "BEGIN")
        if self.delta and r[0] in (BASE_MISMATCH, BAD_ARG, 4):   # 4 = too big: no room for the patch
            raise DeltaRefused(f"delta refused: {STATUS_NAMES.get(r[0], r[0])}")
        if r[0] != OK:
            raise OtaError(f"BEGIN refused: {STATUS_NAMES.get(r[0], r[0])}")
        old = self.session
        self.session, self.chunk, self.chunks = struct.unpack("<IBH", r[1:8])
        self.sess = struct.pack("<I", self.session)
        if self.long:
            accepted = r[8] if len(r) > 8 else 0   # an older target sends 8 bytes (+ zero padding)
            if self.long_ok is None and not accepted & FLAG_LONG:
                self.log("WARNING: the target does not know LONG sessions: it drops the session after "
                         "5 min of silence and a reboot restarts the transfer")
            self.long_ok = bool(accepted & FLAG_LONG)
        prev = self.resume_state
        if (prev and prev.get("session") == self.session and prev.get("chunk") == self.chunk and
                prev.get("chunks") == self.chunks and bool(prev.get("delta")) == self.delta and self.acked is None):
            self.acked = bytearray.fromhex(prev["acked"])   # the same live session: what it had, it still has
            self.log(f"resuming session {self.session:08x}: {self.count_acked()}/{self.chunks} chunks already acked")
        elif old != self.session or self.acked is None:
            self.acked = bytearray((self.chunks + 7) // 8)   # a new session (or the target restored one): ask
        self.resume_state = None
        self.save_state()

    def count_acked(self):
        return sum(bin(b).count("1") for b in self.acked) if self.acked else 0

    def save_state(self):
        if not self.state_file or self.session is None:
            return
        save_json(self.state_file, {
            "format": "mcota-push1", "target": self.target, "size": self.m["size"], "sha256": self.m["sha256"],
            "session": self.session, "chunk": self.chunk, "chunks": self.chunks, "acked": self.acked.hex(),
            "delta": self.delta, "xfer_size": len(self.image),
            "duty": self.pacer.duty if self.pacer else None, "pace": self.pacer.pace if self.pacer else None,
            "updated": int(time.time())})

    def is_acked(self, i):
        return self.acked[i >> 3] & (1 << (i & 7))

    async def session_lost(self, what):
        """LONG: the target dropped the session (idle past its timeout, or rebooted). BEGIN
        again: it re-checks the signature and takes back whatever chunks it had persisted."""
        self.rebegins += 1
        if not self.long or self.rebegins > 20:
            raise OtaError(f"{what}: {STATUS_NAMES[BAD_SESSION]}")
        self.log(f"{what}: the target lost the session (idle timeout or reboot); BEGIN again")
        await self.begin()
        self.log(f"session {self.session:08x}: the target kept {await self.count_target()} chunks")

    async def count_target(self):
        return self.chunks - len(await self.missing(full=True))

    async def missing(self, full=False, windows=None):
        """Ask the target which chunks it lacks, one STATUS per 1024 chunks. Windows the
        target has already acked in full (this session) are skipped unless full=True;
        `windows` limits the poll to those window numbers (a --slow round's progress)."""
        out = []
        for w, base in enumerate(range(0, self.chunks, BITMAP_CHUNKS)):
            span = range(base, min(base + BITMAP_CHUNKS, self.chunks))
            if (windows is not None and w not in windows) or (not full and all(self.is_acked(i) for i in span)):
                out += [i for i in span if not self.is_acked(i)]
                continue
            r = await self.ask(bytes([REQ_STATUS]) + self.sess + struct.pack("<H", base), "STATUS")
            if r[0] == BAD_SESSION:
                await self.session_lost("STATUS")
                return await self.missing(full=True)
            if r[0] != OK:
                raise OtaError(f"STATUS: {STATUS_NAMES.get(r[0], r[0])}")
            bitmap = r[5:5 + 128]
            for j, i in enumerate(span):
                if bitmap[j >> 3] & (1 << (j & 7)):
                    self.acked[i >> 3] |= 1 << (i & 7)
                else:
                    self.acked[i >> 3] &= ~(1 << (i & 7)) & 0xFF
                    out.append(i)
        self.save_state()
        return out

    async def send(self, indices):
        t0, n = time.monotonic(), len(indices)
        every = 20 if self.long else 200
        for k, i in enumerate(indices):
            if self.keepalive and k % 1000 == 999:
                await self.keepalive()
            data = self.image[i * self.chunk:(i + 1) * self.chunk]
            await self.tx(bytes([REQ_DATA]) + self.sess + struct.pack("<H", i) + data, False, 0)
            if k % every == every - 1 or k == n - 1:
                if self.long:
                    self.log(f"  sent {k + 1}/{n} chunks; channel airtime used {self.pacer.airtime:.0f} s")
                else:
                    rate = (k + 1) * self.chunk / max(time.monotonic() - t0, 1e-3)
                    self.log(f"  sent {k + 1}/{n} chunks, {rate / 1024:.1f} KiB/s")

    async def finish(self):
        """FINISH: True = image set; False = send more (what is missing was re-polled)."""
        self.log(f"node: got all {self.chunks} chunks; checking the SHA-256")
        r = await self.ask_done(bytes([REQ_FINISH]) + self.sess, "FINISH")
        if r[0] == OK:
            self.log(f"node: checksum good, image set, rebooting in {REBOOT_SECS} s")
            if self.state_file and os.path.exists(self.state_file):
                os.unlink(self.state_file)
            return True
        if r[0] == HASH_MISMATCH and self.mismatches < 1:   # a bad flash write: once more
            self.mismatches += 1
            self.log("  FINISH: hash mismatch, resending everything")
            return False
        if r[0] == INCOMPLETE:
            return False
        if r[0] == BAD_SESSION:
            await self.session_lost("FINISH")
            return False
        raise OtaError(f"FINISH refused: {STATUS_NAMES.get(r[0], r[0])}")

    async def run(self):
        await self.begin()
        self.log(f"session {self.session:08x}: {self.chunks} chunks of {self.chunk} bytes")
        self.mismatches = 0
        if self.long:
            return await self.run_slow()
        stalled, last_missing = 0, None
        while True:
            if self.keepalive:
                await self.keepalive()
            todo = await self.missing(full=True)
            if not todo:
                if await self.finish():
                    return
                continue
            stalled = stalled + 1 if last_missing is not None and len(todo) >= last_missing else 0
            if stalled >= 4:
                raise OtaError(f"no progress: {len(todo)} chunks still missing")
            last_missing = len(todo)
            self.log(f"{len(todo)} chunks to send")
            await self.send(todo)

    async def run_slow(self):
        """--slow: rounds of SLOW_ROUND chunks, each followed by a STATUS of just the
        windows it touched, so progress reaches the state file every few hours at most."""
        todo = await self.missing()   # windows a resumed session already acked in full are skipped
        stalled = 0
        while True:
            if self.keepalive:
                await self.keepalive()
            if not todo:
                if await self.finish():
                    return
                todo = await self.missing(full=True)
                continue
            batch = todo[:self.round]
            before = self.count_acked()
            self.log(f"{len(todo)} chunks to send ({before}/{self.chunks} acked); this round {len(batch)}")
            await self.send(batch)
            todo = await self.missing(windows={i // BITMAP_CHUNKS for i in batch})
            stalled = stalled + 1 if self.count_acked() <= before else 0
            if stalled >= 10:
                raise OtaError(f"no progress in 10 rounds: {len(todo)} chunks still missing")

    async def abort(self):
        if self.session is not None:
            await self.tx(bytes([REQ_ABORT]) + self.sess, True, self.status_timeout)


def plan_delta(base_path, image, log=print):
    """(patch, base_sha8) for push --delta-from, or None when the whole image is as good"""
    import delta as D
    base = open(base_path, "rb").read()
    t0 = time.monotonic()
    patch = D.make_patch(base, image)
    if D.apply_patch(base, patch) != image:   # never send a patch we cannot decode ourselves
        raise OtaError("delta: the patch does not rebuild the image (bug in delta.py)")
    log(f"delta from {os.path.basename(base_path)}: patch {len(patch)} bytes for a {len(image)}-byte image "
        f"({100 * len(patch) / len(image):.1f}%, {time.monotonic() - t0:.0f} s to make)")
    if len(patch) >= len(image):
        log("delta: no smaller than the image; sending it whole")
        return None
    return patch, running_sha(base)[:8]


async def send_image(link, image, m, plan=None, log=print, **kw):
    """Send a delta if there is a plan and the target takes it, else the whole image.
    The target checks the base at BEGIN, before any DATA: it must RUN that image.
    (CONFIRM would tell us its sha too, but it also confirms a pending image.)
    Returns True if the delta went through."""
    if plan:
        try:
            await OtaSender(link, image, m, log=log, patch=plan[0], base_sha8=plan[1], **kw).run()
            return True
        except DeltaRefused as e:
            log(f"{e}: the node runs another image (or cannot stage a patch); sending the whole image instead")
    await OtaSender(link, image, m, log=log, **kw).run()
    return False


def cmd_delta(a):
    import delta as D
    base, new = open(a.base, "rb").read(), open(a.new, "rb").read()
    patch = D.make_patch(base, new)
    if D.apply_patch(base, patch) != new:
        raise OtaError("the patch does not rebuild NEW (bug in delta.py)")
    with open(a.output, "wb") as f:
        f.write(patch)
    print(f"{a.output}: {len(patch)} bytes for a {len(new)}-byte image ({100 * len(patch) / len(new):.1f}%); "
          f"base sha8 {running_sha(base)[:8].hex()}")


async def confirm_new_image(link, since, log=print, window=REBOOT_SECS + CONFIRM_SECS, sha=None):
    """Send CONFIRM until the NEW image answers. The reply's sha256[0:8] must be
    the image we sent: after a rollback the old image answers too, with a short
    uptime, so uptime alone proves nothing (seen on Rhea 2026-10-18)."""
    while time.monotonic() - since < window:
        r = await link.request(bytes([REQ_CONFIRM]), True, 3.0)
        if r and len(r) >= 14:
            up = struct.unpack("<I", r[2:6])[0]
            running = r[6:14]
            if r[0] != OK:
                raise OtaError(f"confirm failed on the node: {STATUS_NAMES.get(r[0], r[0])}")
            if sha is not None and running != sha[:8]:
                if up < time.monotonic() - since:
                    raise OtaError(f"the node rebooted into a DIFFERENT image (sha {running.hex()}, up {up} s): "
                                   "the new one was rolled back")
                await asyncio.sleep(1)   # still the old image, before its reboot
                continue
            if up < time.monotonic() - since:
                # was_pending 0 with the right sha: an earlier CONFIRM landed and its reply was lost
                log(f"node: new image confirmed ({up} s after boot)" if r[1] else
                    f"node: new image confirmed ({up} s after boot; a retry, the first reply was lost)")
                return True
        else:
            await asyncio.sleep(1)
    return False


# ---------------------------------------------------------------- radio

class CompanionLink:
    """REQ datagrams through a companion radio (CMD_SEND_BINARY_REQ)."""

    def __init__(self, mc, contact):
        from meshcore import EventType
        self.mc, self.ct, self.ET = mc, contact, EventType
        self.pubkey = bytes.fromhex(contact["public_key"])
        self.replies = {}
        mc.subscribe(EventType.BINARY_RESPONSE, self._on_reply)

    async def _on_reply(self, ev):
        self.replies[ev.payload["tag"]] = bytes.fromhex(ev.payload["data"])

    async def request(self, payload, want_reply, timeout):
        frame = b"\x32" + self.pubkey + payload
        for attempt in range(50):   # companion TX queue full: wait for it to drain
            res = await self.mc.commands.send(frame, [self.ET.MSG_SENT, self.ET.ERROR])
            if res.type == self.ET.MSG_SENT:
                break
            await asyncio.sleep(0.05 * (attempt + 1))
        else:
            raise OtaError("companion keeps refusing to queue packets")
        if not want_reply:
            return None
        tag = res.payload["expected_ack"].hex()
        deadline = time.monotonic() + max(timeout, res.payload.get("suggested_timeout", 0) / 1000)
        while time.monotonic() < deadline:
            if tag in self.replies:
                return self.replies.pop(tag)
            await asyncio.sleep(0.02)
        return None


async def connect(addr):
    from meshcore import MeshCore
    if addr.startswith("/dev/"):
        return await asyncio.wait_for(MeshCore.create_serial(addr, 115200), 60)
    import re
    from bleak.backends.device import BLEDevice
    hci = sorted((n for n in os.listdir("/sys/class/bluetooth") if re.fullmatch(r"hci[0-9]+", n)), key=lambda n: int(n[3:]))[0]
    dev = BLEDevice(addr, None, {"path": f"/org/bluez/{hci}/dev_{addr.upper().replace(':', '_')}", "props": {}})
    return await asyncio.wait_for(MeshCore.create_ble(address=addr, device=dev, auto_reconnect=False), 60)


class Admin:
    """Login + CLI to the target through the companion."""

    def __init__(self, mc, target, password):
        from meshcore import EventType
        self.mc, self.ET, self.password = mc, EventType, password
        self.target = target
        self.ct = None

    async def login(self, tries=3):
        await self.mc.ensure_contacts()
        self.ct = self.mc.get_contact_by_name(self.target) or self.mc.get_contact_by_key_prefix(self.target)
        if self.ct is None:
            raise OtaError(f"no contact {self.target!r} on the companion")
        for _ in range(tries):
            res = await self.mc.commands.send_login_sync(self.ct, self.password, min_timeout=20)
            if res and res.type == self.ET.LOGIN_SUCCESS:
                return
        raise OtaError(f"login to {self.ct['adv_name']} failed")

    async def cli(self, cmd, tries=3, timeout=30):
        await self.mc.start_auto_message_fetching()
        for _ in range(tries):
            await self.mc.commands.send_cmd(self.ct, cmd)
            ev = await self.mc.wait_for_event(self.ET.CONTACT_MSG_RECV,
                                              attribute_filters={"pubkey_prefix": self.ct["public_key"][:12]}, timeout=timeout)
            if ev:
                return ev.payload.get("text", "")
        raise OtaError(f"no reply to {cmd!r}")


def parse_fast(s):
    f, bw, sf, cr = s.split(",")
    return float(f), float(bw), int(sf), int(cr)


INSTALL_SECS = 90   # nRF52: back up the running image + copy the new one in, before it boots


def find_contact(mc, target):
    ct = mc.get_contact_by_name(target) or mc.get_contact_by_key_prefix(target)
    if ct is None:
        raise OtaError(f"no contact {target!r} on the companion")
    return ct


async def cmd_push(a):
    image, m = load_signed(a.image)
    fast = None if a.slow else parse_fast(a.fast)
    plan = plan_delta(a.delta_from, image) if a.delta_from else None   # before the radio work: takes seconds
    mc = await connect(a.companion)
    restore = None
    try:
        await mc.ensure_contacts()
        ct = find_contact(mc, a.target)
        kind = {2: "repeater", 3: "room server"}.get(ct.get("type"), "companion")
        repeater = kind != "companion"
        adm = None
        if repeater:   # repeaters and room servers take OTA requests from a logged-in admin
            if not a.password_file:
                raise OtaError(f"a {kind} target needs --password-file (its admin password)")
            adm = Admin(mc, a.target, open(a.password_file).read().strip())
            await adm.login()
            st = await adm.cli("ota status")
            print(f"target: {st}")
            if "PENDING" in st:
                raise OtaError("target runs an unconfirmed image: confirm it (or let it roll back) first")
        link = CompanionLink(mc, ct)

        probe = bytes([REQ_STATUS]) + b"\0" * 6

        async def answers():
            return bool(await link.request(probe, True, 8.0) or await link.request(probe, True, 8.0))

        async def go_fast():
            nonlocal restore
            if restore is None:
                info = mc.self_info
                tun = await mc.commands.get_tuning()
                # set_radio without the repeat flag switches client repeat OFF (and saves it): keep it as it is
                dq = await mc.commands.send_device_query()
                repeat = 1 if (dq.payload or {}).get("repeat") else 0
                restore = (info["radio_freq"], info["radio_bw"], info["radio_sf"], info["radio_cr"],
                           tun.payload["rx_delay"], tun.payload["airtime_factor"], repeat)
            await mc.commands.set_radio(*fast, repeat=0)   # never repeat on the transfer channel
            await mc.commands.set_tuning(0, 0)   # no airtime budget wait between our packets
            await mc.commands.change_contact_path(ct, "")   # zero-hop direct: no repeaters out here

        # does it speak LoRa OTA, and does it accept us? (a companion: only from a favourite)
        already_fast = False
        if not await answers():
            if fast:   # an interrupted run can leave it on the transfer channel for up to RADIO_IDLE_SECS
                await go_fast()
                already_fast = await answers()
            if not already_fast:
                raise OtaError(f"{ct['adv_name']} does not answer LoRa OTA requests: no OTA firmware, or "
                               "(companion) this radio is not one of its favourites")
        print(f"target {ct['adv_name']}: speaks LoRa OTA ({kind})"
              + (", still on the transfer channel" if already_fast else ""))

        if fast:
            req = bytes([REQ_RADIO]) + struct.pack("<IIBBH", int(fast[0] * 1000), int(fast[1] * 1000),
                                                   fast[2], fast[3], RADIO_IDLE_SECS)
            r = await link.request(req, True, 8.0) or await link.request(req, True, 8.0)
            if not r or r[0] != OK:
                raise OtaError(f"fast radio refused: {STATUS_NAMES.get(r[0], r[0]) if r else 'no reply'}")
            if not already_fast:
                await asyncio.sleep(2.5)   # the target switches 1.5 s after replying
                await go_fast()
            print(f"on {fast[0]} MHz / {fast[1]} kHz / SF{fast[2]}; the target drops back "
                  f"by itself after {RADIO_IDLE_SECS} s without OTA traffic")

        pacer = state_file = prev = None
        if a.slow:
            # over the mesh: through the contact's learned path, or a flood (every repeater re-sends it)
            plen = ct.get("out_path_len", -1)
            flood = plen is None or plen < 0
            hops = 0 if flood else plen & 0x3F
            hsz = 1 if flood else max(ct.get("out_path_hash_mode", 0), 0) + 1
            if a.hops is not None:
                hops, flood = a.hops, False
            elif flood:
                print(f"WARNING: no learned path to {ct['adv_name']}: every packet FLOODS the mesh and every "
                      f"repeater in reach re-sends it. Pacing assumes {FLOOD_TX} transmissions per packet. "
                      "Get a path first (message the target and wait for the reply), or give --hops.")
            pacer = Pacer(duty=a.duty, pace=a.pace, hops=hops, hash_size=hsz, flood=flood)
            state_file = a.state or state_path(ct["public_key"], m["sha256"])
            if a.resume:
                if not os.path.exists(state_file):
                    raise OtaError(f"--resume: no state file {state_file}")
                prev = json.load(open(state_file))
                if prev.get("sha256") != m["sha256"] or prev.get("target") != ct["public_key"]:
                    raise OtaError(f"{state_file} is for another image or target")
                if a.duty is None and a.pace is None:   # keep the pacing the push started with
                    pacer.duty, pacer.pace = prev.get("duty"), prev.get("pace")
                    if pacer.duty is None and pacer.pace is None:
                        pacer.duty = DUTY_DEFAULT
            elif os.path.exists(state_file):
                print(f"note: {state_file} exists from an earlier push; starting over (--resume continues it)")
            print(f"slow push: {pacer.describe()}")
            xfer = len(plan[0]) if plan else len(image)
            print(f"ETA: {xfer / 1024:.0f} KiB{' (delta)' if plan else ''} -> ~{fmt_secs(slow_eta(xfer, pacer))} without losses "
                  f"(DATA {lora_airtime(datagram_len(1 + 6 + CHUNK, pacer.path_bytes)) * 1000:.0f} ms on air per "
                  f"transmission); progress saved to {state_file}")
        kw = dict(pacer=pacer, state_file=state_file, resume=prev, target=ct["public_key"],
                  retries=20 if a.slow else 6, status_timeout=30.0 if a.slow else 8.0)
        t0 = time.monotonic()
        # no ABORT on failure: the target drops a silent session after 5 min by itself (a --slow
        # LONG one after 6 h, keeping its chunks), and until then a new push of the same image resumes it
        await send_image(link, image, m, plan, **kw)
        rebooting = time.monotonic()
        print(f"transfer took {fmt_secs(rebooting - t0)}"
              + (f", {pacer.packets} packets, {pacer.airtime:.0f} s of channel airtime" if pacer else ""))
        if restore:   # the new image boots on the node's own radio settings
            await mc.commands.set_radio(*restore[:4], repeat=restore[6])
            await mc.commands.set_tuning(*restore[4:6])
            restore = None
        if a.no_confirm:
            print(f"not confirming: the node rolls back {CONFIRM_SECS} s after it boots")
            return
        window = REBOOT_SECS + INSTALL_SECS + CONFIRM_SECS
        if not await confirm_new_image(link, rebooting, window=window, sha=running_sha(image)):
            raise OtaError(f"no answer from the new image within {CONFIRM_SECS} s of its boot: "
                           "it rolls back to the old image by itself")
        if adm:
            try:
                await adm.login(tries=2)
                print(f"ver: {await adm.cli('ver')}")
                print(f"status: {await adm.cli('ota status')}")
            except OtaError as e:
                print(f"(confirmed; follow-up check failed: {e})")
    finally:
        async def cleanup():
            if restore:
                await mc.commands.set_radio(*restore[:4], repeat=restore[6])
                await mc.commands.set_tuning(*restore[4:6])
                print(f"companion back on its radio settings; the target drops back within {RADIO_IDLE_SECS} s")
            try:
                await mc.disconnect()
            except Exception:
                pass   # BlueZ sometimes drops the D-Bus reply on disconnect; nothing to undo
        await asyncio.shield(cleanup())   # a Ctrl-C mid-transfer must still put the companion back


async def cmd_confirm(a):
    """Confirm a freshly booted image (e.g. right after a WiFi OTA): keeps
    sending CONFIRM for --wait seconds. The node knows us from an earlier login."""
    mc = await connect(a.companion)
    try:
        await mc.ensure_contacts()
        ct = mc.get_contact_by_name(a.target) or mc.get_contact_by_key_prefix(a.target)
        if ct is None:
            raise OtaError(f"no contact {a.target!r} on the companion")
        link = CompanionLink(mc, ct)
        deadline = time.monotonic() + a.wait
        while time.monotonic() < deadline:
            r = await link.request(bytes([REQ_CONFIRM]), True, 3.0)
            if r and len(r) >= 6:
                up = struct.unpack("<I", r[2:6])[0]
                if r[0] != OK:
                    raise OtaError(f"confirm failed: {STATUS_NAMES.get(r[0], r[0])}")
                print(("confirmed" if r[1] else "nothing pending") + f" (node up {up} s, image sha {r[6:14].hex()}...)")
                return
        raise OtaError("no answer (if it had an unconfirmed image, it rolls back by itself)")
    finally:
        await mc.disconnect()


def cmd_eta(a):
    size = os.path.getsize(a.image) if os.path.exists(a.image) else int(a.image)
    route = "flood" if a.flood else f"{a.hops} hop(s)"
    for duty in ([a.duty] if a.duty else [0.5, 1, 2, 5]) if a.pace is None else [None]:
        p = Pacer(duty=duty, pace=a.pace, hops=a.hops, flood=a.flood)
        print(f"{size / 1024:.0f} KiB, {route}, {p.describe().split(',')[0]}: ~{fmt_secs(slow_eta(size, p))}")


async def cmd_cli(a, cmd):
    mc = await connect(a.companion)
    try:
        adm = Admin(mc, a.target, open(a.password_file).read().strip())
        await adm.login()
        print(await adm.cli(cmd))
    finally:
        await mc.disconnect()


def cmd_settings_make(a):
    entries = parse_sets(a.set)
    target = parse_target(a.target)
    version = a.version if a.version is not None else int(time.time())
    write_bundle(a, entries, target, version)


def parse_sets(sets):
    entries = []
    for kv in sets:
        if "=" not in kv:
            raise OtaError(f"--set {kv!r}: want KEY=VALUE")
        k, v = kv.split("=", 1)
        entries.append((k.strip(), v.strip()))
    return entries


def write_bundle(a, entries, target, version):
    blob = make_bundle(entries, target, version, load_key(a.key), reboot=a.reboot)
    with open(a.output, "wb") as f:
        f.write(blob)
    print(f"{a.output}: v{version} for {target_text(target)}, {len(blob)} bytes" +
          (f", node reboots ~{SET_REBOOT_SECS} s after the CONFIRM" if a.reboot else ""))
    for k, v in entries:
        print(f"  {k} = {v}")
    print(f"  over the mesh: {describe_settings_eta(len(blob))}")
    return blob


def cmd_settings_eta(a):
    size = len(open(a.bundle, "rb").read()) if os.path.exists(a.bundle) else int(a.bundle)
    for duty in [a.duty] if a.duty else [DUTY_DEFAULT]:
        print(f"{size} bytes: {describe_settings_eta(size, a.hops, a.flood, duty)}")


async def cmd_settings_diff(a):
    wanted = parse_sets(a.set)
    check_entries(wanted)   # before touching the radio
    mc, ct, adm, link = await settings_session(a)
    try:
        cur = await read_current(mc, ct, link, adm, [k for k, _ in wanted])
    finally:
        await mc.disconnect()
    changed = diff_entries(cur, wanted)
    print(f"{ct['adv_name']}:")
    for k, v in wanted:
        print(f"  {k}: {cur.get(k, '?')}" + (f" -> {v}" if (k, v) in changed else " (unchanged)"))
    if not changed:
        print("nothing to change: no bundle written")
        return
    target = parse_target(a.bundle_target or ct["public_key"][:16])
    version = a.version if a.version is not None else int(time.time())
    write_bundle(a, changed, target, version)



async def read_current(mc, ct, link, adm, keys):
    """current values of keys: repeater CLI if logged in, else the node's GET (LoRa-OTA-settings firmware)"""
    cur = {}
    if adm:
        for k in keys:
            try:
                r = await adm.cli(CLI_GET[k])
                cur[k] = r[2:].strip() if r.startswith("> ") else r.strip()
            except OtaError as e:
                cur[k] = f"? ({e})"
        return cur
    start = 0
    while start != 0xFF:
        r = await link.request(bytes([REQ_SET_CTRL, SET_OP_GET, start]), True, 8.0)
        if not r or r[0] != OK:
            break
        for line in r[2:].decode(errors="replace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                cur[k] = v
        start = r[1]
    return {k: cur.get(k, "?") for k in keys} if keys else cur


class CompanionRadio:
    """the sending companion's radio, for SettingsSender"""

    def __init__(self, mc, ct):
        self.mc, self.ct, self.repeat = mc, ct, 0

    async def get(self):
        info = self.mc.self_info
        dq = await self.mc.commands.send_device_query()
        self.repeat = 1 if (dq.payload or {}).get("repeat") else 0   # set_radio without it turns repeat off
        return (info["radio_freq"], info["radio_bw"], info["radio_sf"], info["radio_cr"])

    async def set(self, r):
        await self.mc.commands.set_radio(*r, repeat=self.repeat)
        await self.mc.commands.change_contact_path(self.ct, "")   # direct: repeaters on the way keep the old settings


async def settings_session(a):
    mc = await connect(a.companion)
    await mc.ensure_contacts()
    ct = find_contact(mc, a.target)
    repeater = ct.get("type") in (2, 3)
    adm = None
    if repeater:
        if not a.password_file:
            raise OtaError("a repeater target needs --password-file (its admin password)")
        adm = Admin(mc, a.target, open(a.password_file).read().strip())
        await adm.login()
    return mc, ct, adm, CompanionLink(mc, ct)


async def cmd_settings_push(a):
    blob = open(a.bundle, "rb").read()
    b = parse_bundle(blob)
    mc, ct, adm, link = await settings_session(a)
    try:
        kind, tgt = b["target"]
        if kind == 1 and not bytes.fromhex(ct["public_key"]).startswith(tgt):
            raise OtaError(f"bundle is for {target_text(b['target'])}, {ct['adv_name']} is {ct['public_key'][:16]}...")
        keys = [k for k, _ in b["entries"] if k in SETTINGS_KEYS]
        cur = await read_current(mc, ct, link, adm, keys)
        print(f"{ct['adv_name']}: bundle v{b['version']} ({target_text(b['target'])})")
        for k, v in b["entries"]:
            if k == SET_REBOOT_KEY:
                print(f"  (reboot ~{SET_REBOOT_SECS} s after the CONFIRM)")
            else:
                print(f"  {k}: {cur.get(k, '?')} -> {v}")
        st = set_status(await link.request(bytes([REQ_SET_CTRL, SET_OP_STATUS]), True, 8.0))
        if st is None:
            raise OtaError(f"{ct['adv_name']} does not answer signed-settings requests (no such firmware, or "
                           "(companion) this radio is not one of its favourites)")
        print(f"node: last bundle v{st['version']}" + (f", v{st['pending_version']} ON PROBATION" if st["pending"] else ""))
        sender = SettingsSender(link, blob, radio=CompanionRadio(mc, ct))
        ok = await sender.run(confirm=not a.no_confirm)   # puts the companion's radio back itself
        if ok and adm:
            try:
                await adm.login(tries=2)
                print(f"status: {await adm.cli('ota settings')}")
            except OtaError as e:
                print(f"(confirmed; follow-up check failed: {e})")
        if not ok and not a.no_confirm:
            raise OtaError("not confirmed: the node goes back to its old settings by itself")
    finally:
        await mc.disconnect()


async def cmd_settings_ctrl(a):
    mc, ct, adm, link = await settings_session(a)
    try:
        if a.settings_cmd == "show":
            # repeater: its CLI (any firmware); companion: GET over LoRa (signed-settings firmware only)
            keys = [k for k in SETTINGS_KEYS if k not in COMPANION_FEATURE_KEYS] if adm else []
            for k, v in (await read_current(mc, ct, link, adm, keys)).items():
                print(f"{k} = {v}")
            return
        op = {"status": SET_OP_STATUS, "confirm": SET_OP_CONFIRM, "revert": SET_OP_REVERT}[a.settings_cmd]
        st = set_status(await link.request(bytes([REQ_SET_CTRL, op]), True, 8.0) or
                        await link.request(bytes([REQ_SET_CTRL, op]), True, 8.0))
        if st is None:
            raise OtaError("no answer")
        if st["status"] != OK:
            raise OtaError(STATUS_NAMES.get(st["status"], st["status"]))
        print(f"last bundle v{st['version']}" +
              (f", v{st['pending_version']} on probation, {st['secs_left']} s left" if st["pending"] else ", nothing pending") +
              ({SET_OP_CONFIRM: " (confirmed now)", SET_OP_REVERT: " (reverted now)"}.get(op, "") if st["was"] else ""))
    finally:
        await mc.disconnect()


async def cancellable(coro):
    """SIGINT/SIGTERM cancel the transfer ONCE, so its finally (radio restore) runs to the end."""
    task = asyncio.ensure_future(coro)
    loop = asyncio.get_running_loop()
    def stop():
        if not task.cancelled():
            print("interrupted: restoring the companion's radio settings", file=sys.stderr)
            task.cancel()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)
            loop.add_signal_handler(sig, lambda: None)   # ignore further signals until cleanup ends
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop)
    try:
        return await task
    except asyncio.CancelledError:
        raise OtaError("interrupted")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key", default=DEFAULT_KEY)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    sub.add_parser("pubkey")
    s = sub.add_parser("sign")
    s.add_argument("image")
    s.add_argument("--board", required=True)
    d = sub.add_parser("delta")
    d.add_argument("base")
    d.add_argument("new")
    d.add_argument("-o", "--output", required=True)
    e = sub.add_parser("eta", help="how long a --slow push takes")
    e.add_argument("image", help="image file, or a size in bytes")
    e.add_argument("--duty", type=float)
    e.add_argument("--pace", type=float)
    e.add_argument("--hops", type=int, default=0)
    e.add_argument("--flood", action="store_true")
    for name in ("push", "status", "confirm"):
        p = sub.add_parser(name)
        p.add_argument("--companion", required=True)
        p.add_argument("--target", required=True)
        p.add_argument("--password-file", required=(name == "status"),
                       help="the target's admin password (repeater and room server targets only)")
        if name == "confirm":
            p.add_argument("--wait", type=float, default=150, help="keep trying this many seconds")
        if name == "push":
            p.add_argument("image")
            p.add_argument("--fast", default="919.0,500,5,5", help="freq,bw,sf,cr for the transfer")
            p.add_argument("--slow", action="store_true",
                           help="stay on the mesh radio settings, paced: hours to days on the shared channel")
            p.add_argument("--duty", type=float, help=f"--slow: %% of channel airtime to use, relays included "
                                                      f"(default {DUTY_DEFAULT:g})")
            p.add_argument("--pace", type=float, help="--slow: seconds between packets instead of --duty")
            p.add_argument("--hops", type=int, help="--slow: hops to the target (default: the contact's learned path)")
            p.add_argument("--state", help="--slow: progress file (default under ~/.local/state/meshcore-lora-ota)")
            p.add_argument("--resume", action="store_true", help="--slow: continue from the progress file")
            p.add_argument("--no-confirm", action="store_true")
            p.add_argument("--delta-from", metavar="BASE",
                           help="send only the changes from BASE, the image the target runs now "
                                "(falls back to the whole image if it runs something else)")
    st = sub.add_parser("settings", help="signed settings bundles (README: Signed settings)")
    ssub = st.add_subparsers(dest="settings_cmd", required=True)
    m = ssub.add_parser("make")
    m.add_argument("--target", required=True, help="node public key hex prefix (>= 12 digits) or board:TAG")
    m.add_argument("--set", action="append", required=True, metavar="KEY=VALUE")
    m.add_argument("--version", type=int, help="default: the current unix time")
    m.add_argument("-o", "--output", required=True)
    m.add_argument("--reboot", action="store_true", help=f"the node reboots once, ~{SET_REBOOT_SECS} s after the CONFIRM")
    se = ssub.add_parser("eta", help="packets and airtime of a settings push over the mesh")
    se.add_argument("bundle", help="bundle file, or a size in bytes")
    se.add_argument("--hops", type=int, default=0)
    se.add_argument("--flood", action="store_true")
    se.add_argument("--duty", type=float)
    for name in ("push", "show", "status", "confirm", "revert", "diff"):
        p = ssub.add_parser(name)
        p.add_argument("--companion", required=True)
        p.add_argument("--target", required=True)
        p.add_argument("--password-file", help="the target's admin password (repeater targets)")
        if name == "push":
            p.add_argument("bundle")
            p.add_argument("--no-confirm", action="store_true")
        if name == "diff":
            p.add_argument("--set", action="append", required=True, metavar="KEY=VALUE")
            p.add_argument("--reboot", action="store_true", help=f"the node reboots once, ~{SET_REBOOT_SECS} s after the CONFIRM")
            p.add_argument("--version", type=int, help="default: the current unix time")
            p.add_argument("--bundle-target", help="target in the bundle (default: the node's 8-byte key prefix)")
            p.add_argument("-o", "--output", required=True)
    a = ap.parse_args()
    if a.cmd == "push" and not a.slow and (a.duty or a.pace or a.resume or a.hops is not None):
        ap.error("--duty/--pace/--hops/--resume go with --slow")
    if a.cmd == "push" and a.duty is not None and a.pace is not None:
        ap.error("--duty or --pace, not both")
    try:
        if a.cmd == "keygen": cmd_keygen(a)
        elif a.cmd == "pubkey": cmd_pubkey(a)
        elif a.cmd == "sign": cmd_sign(a)
        elif a.cmd == "delta": cmd_delta(a)
        elif a.cmd == "eta": cmd_eta(a)
        elif a.cmd == "push": asyncio.run(cancellable(cmd_push(a)))
        elif a.cmd == "confirm": asyncio.run(cmd_confirm(a))
        elif a.cmd == "settings" and a.settings_cmd == "make": cmd_settings_make(a)
        elif a.cmd == "settings" and a.settings_cmd == "eta": cmd_settings_eta(a)
        elif a.cmd == "settings" and a.settings_cmd == "diff": asyncio.run(cmd_settings_diff(a))
        elif a.cmd == "settings" and a.settings_cmd == "push": asyncio.run(cancellable(cmd_settings_push(a)))
        elif a.cmd == "settings": asyncio.run(cmd_settings_ctrl(a))
        else: asyncio.run(cmd_cli(a, f"ota {a.cmd}"))
    except OtaError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
