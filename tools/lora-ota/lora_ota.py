#!/usr/bin/env python3
"""Firmware over LoRa for MeshCore repeaters and companions built with LORA_OTA (see README.md).

  lora_ota.py keygen                       make the signing key (once)
  lora_ota.py pubkey                       print it for -D LORA_OTA_PUBKEY
  lora_ota.py sign IMAGE --board TAG       write IMAGE.mcota (manifest + signature)
  lora_ota.py push  --companion C --target T [--password-file F] IMAGE
  lora_ota.py status|confirm --companion C --target T --password-file F

C is a companion radio: a /dev/... serial path or a BLE address.
T is the target: a contact name or a public-key hex prefix. A repeater target
takes the admin password; a companion target takes OTA only from radios it has
favourited.
"""
import argparse, asyncio, hashlib, json, math, os, random, struct, sys, time

DEFAULT_KEY = os.path.expanduser("~/.config/meshcore/ota-signing.key")
MARKER = b"MCOTA-ROLLBACK-v1"
BOARD_LEN = 32

REQ_BEGIN, REQ_DATA, REQ_STATUS, REQ_FINISH, REQ_ABORT, REQ_CONFIRM, REQ_RADIO = 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
RADIO_IDLE_SECS = 90   # target drops the fast settings after this long without OTA traffic
CONFIRM_SECS = 60   # firmware LORA_OTA_CONFIRM_SECS
REBOOT_SECS = 6     # firmware LORA_OTA_REBOOT_DELAY_MS
BITMAP_CHUNKS = 128 * 8
STATUS_NAMES = {0: "ok", 1: "bad state", 2: "bad session", 3: "bad signature (or image for another board)",
                4: "too big", 5: "flash error", 6: "incomplete", 7: "hash mismatch", 8: "no LoRa-OTA marker",
                9: "activate failed", 10: "running image not confirmed yet ('ota confirm' first)", 11: "bad argument"}
OK, INCOMPLETE, HASH_MISMATCH = 0, 6, 7


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


# ---------------------------------------------------------------- protocol

class OtaSender:
    """Drives one transfer over a link with:
         async request(payload, want_reply, timeout) -> reply body | None
       (None = no reply in time). Transport-agnostic: radio or simulator."""

    def __init__(self, link, image, manifest, log=print, status_timeout=8.0, retries=6, keepalive=None):
        self.link, self.image, self.m, self.log = link, image, manifest, log
        self.keepalive = keepalive   # async callable, run before each round
        self.status_timeout, self.retries = status_timeout, retries
        self.session = self.chunk = self.chunks = None

    async def ask(self, payload, what):
        for attempt in range(self.retries):
            r = await self.link.request(payload, True, self.status_timeout)
            if r:
                return r
            self.log(f"  {what}: no reply (attempt {attempt + 1})")
        raise OtaError(f"{what}: target not answering")

    async def begin(self):
        p = bytes([REQ_BEGIN]) + struct.pack("<I", self.m["size"]) + bytes.fromhex(self.m["sha256"]) + bytes.fromhex(self.m["sig"])
        r = await self.ask(p, "BEGIN")
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
                r = await self.ask(bytes([REQ_FINISH]) + self.sess, "FINISH")
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


async def confirm_new_image(link, since, log=print, window=REBOOT_SECS + CONFIRM_SECS):
    """Send CONFIRM until the REBOOTED node answers (uptime shorter than the
    time since `since`, a monotonic timestamp taken when it said rebooting).
    An answer from the old image, before its reboot, does not count."""
    while time.monotonic() - since < window:
        r = await link.request(bytes([REQ_CONFIRM]), True, 3.0)
        if r and len(r) >= 6:
            up = struct.unpack("<I", r[2:6])[0]
            if r[0] == OK and up < time.monotonic() - since:
                log(f"node: new image confirmed ({up} s after boot)" if r[1] else
                    f"node: new image already confirmed ({up} s after boot)")
                return True
            if r[0] != OK:
                raise OtaError(f"confirm failed on the node: {STATUS_NAMES.get(r[0], r[0])}")
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
        repeater = ct.get("type") == 2
        adm = None
        if repeater:   # repeaters take OTA requests from a logged-in admin
            if not a.password_file:
                raise OtaError("a repeater target needs --password-file (its admin password)")
            adm = Admin(mc, a.target, open(a.password_file).read().strip())
            await adm.login()
            st = await adm.cli("ota status")
            print(f"target: {st}")
            if "PENDING" in st:
                raise OtaError("target runs an unconfirmed image: confirm it (or let it roll back) first")
        link = CompanionLink(mc, ct)

        # does it speak LoRa OTA, and does it accept us? (a companion: only from a favourite)
        r = await link.request(bytes([REQ_STATUS]) + b"\0" * 6, True, 8.0)
        if not r:
            r = await link.request(bytes([REQ_STATUS]) + b"\0" * 6, True, 8.0)
        if not r:
            raise OtaError(f"{ct['adv_name']} does not answer LoRa OTA requests: no OTA firmware, or "
                           "(companion) this radio is not one of its favourites")
        print(f"target {ct['adv_name']}: speaks LoRa OTA ({'repeater' if repeater else 'companion'})")

        if fast:
            info = mc.self_info
            tun = await mc.commands.get_tuning()
            req = bytes([REQ_RADIO]) + struct.pack("<IIBBH", int(fast[0] * 1000), int(fast[1] * 1000),
                                                   fast[2], fast[3], RADIO_IDLE_SECS)
            r = await link.request(req, True, 8.0) or await link.request(req, True, 8.0)
            if not r or r[0] != OK:
                raise OtaError(f"fast radio refused: {STATUS_NAMES.get(r[0], r[0]) if r else 'no reply'}")
            restore = (info["radio_freq"], info["radio_bw"], info["radio_sf"], info["radio_cr"],
                       tun.payload["rx_delay"], tun.payload["airtime_factor"])
            await asyncio.sleep(2.5)   # the target switches 1.5 s after replying
            await mc.commands.set_radio(*fast)
            await mc.commands.set_tuning(0, 0)   # no airtime budget wait between our packets
            await mc.commands.change_contact_path(ct, "")   # zero-hop direct: no repeaters out here
            print(f"moved to {fast[0]} MHz / {fast[1]} kHz / SF{fast[2]}; the target drops back "
                  f"by itself after {RADIO_IDLE_SECS} s without OTA traffic")

        sender = OtaSender(link, image, m)
        t0 = time.monotonic()
        try:
            await sender.run()
        except BaseException:
            try:
                await sender.abort()
            except Exception:
                pass
            raise
        rebooting = time.monotonic()
        print(f"transfer took {rebooting - t0:.0f} s")
        if restore:   # the new image boots on the node's own radio settings
            await mc.commands.set_radio(*restore[:4])
            await mc.commands.set_tuning(*restore[4:])
            restore = None
        if a.no_confirm:
            print(f"not confirming: the node rolls back {CONFIRM_SECS} s after it boots")
            return
        window = REBOOT_SECS + INSTALL_SECS + CONFIRM_SECS
        if not await confirm_new_image(link, rebooting, window=window):
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
        if restore:
            await mc.commands.set_radio(*restore[:4])
            await mc.commands.set_tuning(*restore[4:])
            print(f"companion back on its radio settings; the target drops back within {RADIO_IDLE_SECS} s")
        await mc.disconnect()


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
                print(("confirmed" if r[1] else "nothing pending") + f" (node up {up} s)")
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
                       help="the target's admin password (repeater targets only)")
        if name == "confirm":
            p.add_argument("--wait", type=float, default=150, help="keep trying this many seconds")
        if name == "push":
            p.add_argument("image")
            p.add_argument("--fast", default="919.0,500,5,5", help="freq,bw,sf,cr for the transfer")
            p.add_argument("--slow", action="store_true",
                           help="stay on the mesh radio settings (hours on the shared channel)")
            p.add_argument("--no-confirm", action="store_true")
    a = ap.parse_args()
    try:
        if a.cmd == "keygen": cmd_keygen(a)
        elif a.cmd == "pubkey": cmd_pubkey(a)
        elif a.cmd == "sign": cmd_sign(a)
        elif a.cmd == "push": asyncio.run(cmd_push(a))
        elif a.cmd == "confirm": asyncio.run(cmd_confirm(a))
        else: asyncio.run(cmd_cli(a, f"ota {a.cmd}"))
    except OtaError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
