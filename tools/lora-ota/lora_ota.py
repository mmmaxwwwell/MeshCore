#!/usr/bin/env python3
"""Firmware over LoRa for MeshCore repeaters and companions built with LORA_OTA (see README.md).

  lora_ota.py keygen                       make the signing key (once)
  lora_ota.py pubkey                       print it for -D LORA_OTA_PUBKEY
  lora_ota.py sign IMAGE --board TAG       write IMAGE.mcota (manifest + signature)
  lora_ota.py push  --companion C --target T [--password-file F] IMAGE
  lora_ota.py push  --slow [--duty PCT | --pace S] [--resume] ...  over the mesh, a little at a time
  lora_ota.py eta   IMAGE [--duty PCT | --pace S] [--hops N]           how long a --slow push takes
  lora_ota.py status|confirm --companion C --target T --password-file F

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
                9: "activate failed", 10: "running image not confirmed yet ('ota confirm' first)", 11: "bad argument",
                12: "working"}
OK, BAD_SESSION, INCOMPLETE, HASH_MISMATCH, WORKING = 0, 2, 6, 7, 12
FLAG_LONG = 0x02   # BEGIN flags byte (payload offset 101): slow session, long idle timeout, persisted bitmap
                   # (0x01 is reserved for delta images)
LONG_IDLE_SECS = 6 * 3600   # firmware LORA_OTA_LONG_IDLE_MS
STATE_DIR = os.path.expanduser("~/.local/state/meshcore-lora-ota")
WORK_SECS = 240   # longest a BEGIN (erase/stage) or FINISH (verify) may take on the target


class OtaError(Exception):
    pass


def manifest_message(board: str, size: int, sha: bytes) -> bytes:
    b = board.encode()
    if len(b) > BOARD_LEN:
        raise OtaError(f"board tag longer than {BOARD_LEN} bytes")
    return b"MCOTA1" + b.ljust(BOARD_LEN, b"\0") + struct.pack("<I", size) + sha


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
REPLY_LEN = {REQ_BEGIN: 9, REQ_STATUS: 5 + 128, REQ_FINISH: 1, REQ_ABORT: 1, REQ_CONFIRM: 14}


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
                 pacer=None, state_file=None, resume=None, target=""):
        self.link, self.image, self.m, self.log = link, image, manifest, log
        self.keepalive = keepalive   # async callable, run before each round
        self.status_timeout, self.retries = status_timeout, retries
        self.want_chunk = chunk
        self.work_poll = 1.0 if status_timeout else 0
        self.session = self.chunk = self.chunks = None
        # --slow: every transmission paced, a LONG session on the target, progress in a state file
        self.pacer, self.state_file, self.target = pacer, state_file, target
        self.long = pacer is not None
        self.flags = FLAG_LONG if self.long else 0
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
        r = await self.ask_done(p, "BEGIN")
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
        if prev and prev.get("session") == self.session and prev.get("chunk") == self.chunk and self.acked is None:
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
            print(f"ETA: {len(image) / 1024:.0f} KiB -> ~{fmt_secs(slow_eta(len(image), pacer))} without losses "
                  f"(DATA {lora_airtime(datagram_len(1 + 6 + CHUNK, pacer.path_bytes)) * 1000:.0f} ms on air per "
                  f"transmission); progress saved to {state_file}")
        sender = OtaSender(link, image, m, pacer=pacer, state_file=state_file, resume=prev,
                           target=ct["public_key"], retries=20 if a.slow else 6,
                           status_timeout=30.0 if a.slow else 8.0)
        t0 = time.monotonic()
        # no ABORT on failure: the target drops a silent session after 5 min by itself (a --slow
        # LONG one after 6 h, keeping its chunks), and until then a new push of the same image resumes it
        await sender.run()
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
    a = ap.parse_args()
    if a.cmd == "push" and not a.slow and (a.duty or a.pace or a.resume or a.hops is not None):
        ap.error("--duty/--pace/--hops/--resume go with --slow")
    if a.cmd == "push" and a.duty is not None and a.pace is not None:
        ap.error("--duty or --pace, not both")
    try:
        if a.cmd == "keygen": cmd_keygen(a)
        elif a.cmd == "pubkey": cmd_pubkey(a)
        elif a.cmd == "sign": cmd_sign(a)
        elif a.cmd == "eta": cmd_eta(a)
        elif a.cmd == "push": asyncio.run(cancellable(cmd_push(a)))
        elif a.cmd == "confirm": asyncio.run(cmd_confirm(a))
        else: asyncio.run(cmd_cli(a, f"ota {a.cmd}"))
    except OtaError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
