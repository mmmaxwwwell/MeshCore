#!/usr/bin/env python3
"""Firmware over LoRa for MeshCore repeaters and companions built with LORA_OTA (see README.md).

  lora_ota.py keygen                       make the signing key (once)
  lora_ota.py pubkey                       print it for -D LORA_OTA_PUBKEY
  lora_ota.py sign IMAGE --board TAG       write IMAGE.mcota (manifest + signature)
  lora_ota.py push  --companion C --target T [--password-file F] IMAGE
  lora_ota.py status|confirm --companion C --target T --password-file F
  lora_ota.py settings make --target HEX|board:TAG --set KEY=VALUE ... -o BUNDLE
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
                12: "working"}
OK, INCOMPLETE, HASH_MISMATCH, WORKING = 0, 6, 7, 12
WORK_SECS = 240   # longest a BEGIN (erase/stage) or FINISH (verify) may take on the target


class OtaError(Exception):
    pass


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
SET_CHUNK = COMPANION_FRAME - 1 - 32 - 6   # CMD_SEND_BINARY_REQ + pubkey, then type + total + offset + n
STATUS_NAMES.update({16: "version not newer than the last applied bundle", 17: "bundle is for another node",
                     18: "setting not on the whitelist", 19: "value out of range", 20: "bundle does not parse",
                     21: "another bundle is still on probation (confirm or revert it first)",
                     22: "this node has no such setting", 23: "could not save on the node"})
# the whitelist (the firmware's KEY_NAMES); the node checks the values again
SETTINGS_KEYS = ["radio", "tx", "af", "rxdelay", "txdelay", "direct.txdelay", "multi.acks", "path.hash.mode",
                 "int.thresh", "agc.reset.interval", "radio.rxgain", "flood.max", "flood.max.unscoped",
                 "flood.max.advert", "advert.interval", "flood.advert.interval", "loop.detect", "repeat", "regions"]
REPEATER_ONLY_KEYS = {"flood.max", "flood.max.unscoped", "flood.max.advert", "advert.interval",
                      "flood.advert.interval", "loop.detect", "repeat", "regions"}
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


def make_bundle(entries, target, version, key, check=True) -> bytes:
    """entries: [(key, value)]. Signed message: "MCSET1" || body; bundle = body || sig."""
    if check:
        seen = set()
        for k, _ in entries:
            if k not in SETTINGS_KEYS:
                raise OtaError(f"{k!r} is not a setting this can change (whitelist: {', '.join(SETTINGS_KEYS)})")
            if k in seen:
                raise OtaError(f"{k} given twice")
            seen.add(k)
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
            "pending_version": struct.unpack("<I", r[7:11])[0], "secs_left": struct.unpack("<H", r[11:13])[0]}


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


# ---------------------------------------------------------------- protocol

class OtaSender:
    """Drives one transfer over a link with:
         async request(payload, want_reply, timeout) -> reply body | None
       (None = no reply in time). Transport-agnostic: radio or simulator."""

    def __init__(self, link, image, manifest, log=print, status_timeout=8.0, retries=6, keepalive=None, chunk=CHUNK):
        self.link, self.image, self.m, self.log = link, image, manifest, log
        self.keepalive = keepalive   # async callable, run before each round
        self.status_timeout, self.retries = status_timeout, retries
        self.want_chunk = chunk
        self.work_poll = 1.0 if status_timeout else 0
        self.session = self.chunk = self.chunks = None

    async def ask(self, payload, what):
        for attempt in range(self.retries):
            r = await self.link.request(payload, True, self.status_timeout)
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
        r = await self.ask_done(p, "BEGIN")
        if r[0] != OK:
            raise OtaError(f"BEGIN refused: {STATUS_NAMES.get(r[0], r[0])}")
        self.session, self.chunk, self.chunks = struct.unpack("<IBH", r[1:8])
        self.sess = struct.pack("<I", self.session)

    async def missing(self):
        """Ask the target which chunks it lacks, one STATUS per 1024 chunks."""
        out = []
        for base in range(0, self.chunks, BITMAP_CHUNKS):
            r = await self.ask(bytes([REQ_STATUS]) + self.sess + struct.pack("<H", base), "STATUS")
            if r[0] != OK:
                raise OtaError(f"STATUS: {STATUS_NAMES.get(r[0], r[0])}")
            bitmap = r[5:5 + 128]
            for j in range(min(BITMAP_CHUNKS, self.chunks - base)):
                if not bitmap[j >> 3] & (1 << (j & 7)):
                    out.append(base + j)
        return out

    async def send(self, indices):
        t0, n = time.monotonic(), len(indices)
        for k, i in enumerate(indices):
            if self.keepalive and k % 1000 == 999:
                await self.keepalive()
            data = self.image[i * self.chunk:(i + 1) * self.chunk]
            await self.link.request(bytes([REQ_DATA]) + self.sess + struct.pack("<H", i) + data, False, 0)
            if k % 200 == 199 or k == n - 1:
                rate = (k + 1) * self.chunk / max(time.monotonic() - t0, 1e-3)
                self.log(f"  sent {k + 1}/{n} chunks, {rate / 1024:.1f} KiB/s")

    async def run(self):
        await self.begin()
        self.log(f"session {self.session:08x}: {self.chunks} chunks of {self.chunk} bytes")
        stalled, last_missing, mismatches = 0, None, 0
        while True:
            if self.keepalive:
                await self.keepalive()
            todo = await self.missing()
            if not todo:
                self.log(f"node: got all {self.chunks} chunks; checking the SHA-256")
                r = await self.ask_done(bytes([REQ_FINISH]) + self.sess, "FINISH")
                if r[0] == OK:
                    self.log(f"node: checksum good, image set, rebooting in {REBOOT_SECS} s")
                    return
                if r[0] == HASH_MISMATCH and mismatches < 1:   # a bad flash write: once more
                    mismatches += 1
                    self.log("  FINISH: hash mismatch, resending everything")
                    continue
                if r[0] == INCOMPLETE:
                    continue
                raise OtaError(f"FINISH refused: {STATUS_NAMES.get(r[0], r[0])}")
            stalled = stalled + 1 if last_missing is not None and len(todo) >= last_missing else 0
            if stalled >= 4:
                raise OtaError(f"no progress: {len(todo)} chunks still missing")
            last_missing = len(todo)
            self.log(f"{len(todo)} chunks to send")
            await self.send(todo)

    async def abort(self):
        if self.session is not None:
            await self.link.request(bytes([REQ_ABORT]) + self.sess, True, self.status_timeout)


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

        sender = OtaSender(link, image, m)
        t0 = time.monotonic()
        # no ABORT on failure: the target drops a silent session after 5 min by itself,
        # and until then a new push of the same image resumes it
        await sender.run()
        rebooting = time.monotonic()
        print(f"transfer took {rebooting - t0:.0f} s")
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


async def cmd_cli(a, cmd):
    mc = await connect(a.companion)
    try:
        adm = Admin(mc, a.target, open(a.password_file).read().strip())
        await adm.login()
        print(await adm.cli(cmd))
    finally:
        await mc.disconnect()


def cmd_settings_make(a):
    entries = []
    for kv in a.set:
        if "=" not in kv:
            raise OtaError(f"--set {kv!r}: want KEY=VALUE")
        k, v = kv.split("=", 1)
        entries.append((k.strip(), v.strip()))
    target = parse_target(a.target)
    version = a.version if a.version is not None else int(time.time())
    blob = make_bundle(entries, target, version, load_key(a.key))
    with open(a.output, "wb") as f:
        f.write(blob)
    print(f"{a.output}: v{version} for {target_text(target)}, {len(blob)} bytes")
    for k, v in entries:
        print(f"  {k} = {v}")


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
        keys = [k for k, _ in b["entries"]]
        cur = await read_current(mc, ct, link, adm, keys)
        print(f"{ct['adv_name']}: bundle v{b['version']} ({target_text(b['target'])})")
        for k, v in b["entries"]:
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
            keys = SETTINGS_KEYS if adm else []
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
                           help="stay on the mesh radio settings (hours on the shared channel)")
            p.add_argument("--no-confirm", action="store_true")
    st = sub.add_parser("settings", help="signed settings bundles (README: Signed settings)")
    ssub = st.add_subparsers(dest="settings_cmd", required=True)
    m = ssub.add_parser("make")
    m.add_argument("--target", required=True, help="node public key hex prefix (>= 12 digits) or board:TAG")
    m.add_argument("--set", action="append", required=True, metavar="KEY=VALUE")
    m.add_argument("--version", type=int, help="default: the current unix time")
    m.add_argument("-o", "--output", required=True)
    for name in ("push", "show", "status", "confirm", "revert"):
        p = ssub.add_parser(name)
        p.add_argument("--companion", required=True)
        p.add_argument("--target", required=True)
        p.add_argument("--password-file", help="the target's admin password (repeater targets)")
        if name == "push":
            p.add_argument("bundle")
            p.add_argument("--no-confirm", action="store_true")
    a = ap.parse_args()
    try:
        if a.cmd == "keygen": cmd_keygen(a)
        elif a.cmd == "pubkey": cmd_pubkey(a)
        elif a.cmd == "sign": cmd_sign(a)
        elif a.cmd == "push": asyncio.run(cancellable(cmd_push(a)))
        elif a.cmd == "confirm": asyncio.run(cmd_confirm(a))
        elif a.cmd == "settings" and a.settings_cmd == "make": cmd_settings_make(a)
        elif a.cmd == "settings" and a.settings_cmd == "push": asyncio.run(cancellable(cmd_settings_push(a)))
        elif a.cmd == "settings": asyncio.run(cmd_settings_ctrl(a))
        else: asyncio.run(cmd_cli(a, f"ota {a.cmd}"))
    except OtaError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
