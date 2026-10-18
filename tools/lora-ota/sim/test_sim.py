#!/usr/bin/env python3
"""End-to-end test of the LoRa OTA protocol: the real sender (lora_ota.py)
against the real receiver core (src/helpers/LoraOTA.cpp) built for the host.
Run from anywhere: python3 tools/lora-ota/sim/test_sim.py"""
import asyncio, hashlib, os, struct, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../.."))
sys.path.insert(0, os.path.dirname(HERE))
import lora_ota as L
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BOARD = "test_board"


def build(out):
    crypto = None
    for d in sorted(os.listdir(os.path.join(REPO, ".pio/libdeps"))):
        c = os.path.join(REPO, ".pio/libdeps", d, "Crypto")
        if os.path.exists(os.path.join(c, "SHA256.cpp")):
            crypto = c
            break
    if crypto is None:
        sys.exit("no rweather Crypto under .pio/libdeps (build any env once)")
    ed = os.path.join(REPO, "lib/ed25519")
    srcs = [os.path.join(HERE, "ota_sim.cpp"), os.path.join(REPO, "src/helpers/LoraOTA.cpp")] + \
           [os.path.join(crypto, f) for f in ("SHA256.cpp", "Hash.cpp", "Crypto.cpp")]
    objs = []
    for c in sorted(f for f in os.listdir(ed) if f.endswith(".c")):
        o = os.path.join(os.path.dirname(out), c + ".o")
        subprocess.check_call(["cc", "-O2", "-c", "-I", ed, os.path.join(ed, c), "-o", o])
        objs.append(o)
    subprocess.check_call(["c++", "-O2", "-Wall", "-Wno-unused-function", "-DLORA_OTA_HOST_TEST",
                           "-I", os.path.join(REPO, "src/helpers"), "-I", ed, "-I", crypto,
                           *srcs, *objs, "-o", out])


class SimLink:
    def __init__(self, sim, args, out, cut_after=None, events=None, clock=None):
        self.p = subprocess.Popen([sim, "--board", BOARD, "--out", out, *args],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.cut_after, self.data_sent, self.frames = cut_after, 0, 0
        self.events = dict(events or {})   # DATA count -> ("gap", seconds) | ("reboot",): what happens to the target then
        self.clock = clock                 # a VClock: the sender's paced gaps pass on the target too
        self.log = []                      # (sender time, type, STATUS base)

    def control(self, frame):
        self.p.stdin.write(struct.pack("<H", len(frame)) + frame)
        self.p.stdin.flush()
        assert self.p.stdout.read(2) == b"\0\0"

    def advance(self, secs):
        """time passes on the target (it runs its main loop meanwhile)"""
        self.control(b"\xf0" + struct.pack("<I", int(secs * 1000)))

    def reboot(self):
        self.control(b"\xf1")

    async def request(self, payload, want_reply, timeout):
        # what a stock companion accepts: CMD_SEND_BINARY_REQ + 32-byte pubkey + payload in one frame
        assert 1 + 32 + len(payload) <= L.COMPANION_FRAME, f"{len(payload)}-byte request will not fit a companion frame"
        if payload[0] == L.REQ_DATA:
            self.data_sent += 1
            if self.cut_after is not None and self.data_sent > self.cut_after:
                raise ConnectionError("link cut")
            ev = self.events.pop(self.data_sent, None)
            if ev and ev[0] == "gap":
                if self.clock:
                    self.clock.t += ev[1]
                self.advance(ev[1])
            elif ev and ev[0] == "reboot":
                self.reboot()
        self.log.append((self.clock.t if self.clock else 0, payload[0],
                         struct.unpack("<H", payload[5:7])[0] if payload[0] == L.REQ_STATUS else None))
        self.frames += 1
        # MeshCore encrypts tag + payload in 16-byte AES blocks: the target sees zero padding
        payload = payload + b"\0" * ((-(4 + len(payload))) % 16)
        self.p.stdin.write(struct.pack("<H", len(payload)) + payload)
        self.p.stdin.flush()
        n = struct.unpack("<H", self.p.stdout.read(2))[0]
        body = self.p.stdout.read(n)
        return body if n else None

    def close(self):
        self.p.stdin.close()
        self.p.wait()


class VClock:
    """The paced sender's clock: its sleeps pass instantly here and on the target."""
    def __init__(self):
        self.t, self.link = 0.0, None

    def clock(self):
        return self.t

    async def sleep(self, dt):
        self.t += dt
        if self.link:
            self.link.advance(dt)


def make_image(size, marker=True, seed=7):
    import random
    r = random.Random(seed)
    img = bytearray(r.getrandbits(8) for _ in range(size))
    img[0] = 0xE9
    if marker:
        pos = 1024 - 6   # straddles the receiver's 1 KiB read blocks
        img[pos:pos + len(L.MARKER)] = L.MARKER
    return bytes(img)


def sign(img, key, board=BOARD, check_marker=True):
    if check_marker:
        return L.sign_image(img, board, key)
    sha = hashlib.sha256(img).digest()
    return {"size": len(img), "sha256": sha.hex(), "sig": key.sign(L.manifest_message(board, len(img), sha)).hex()}


def run(sim, tmp, img, m, args=(), cut_after=None, link=None, slow=None, events=None, state=None, resume=None):
    """slow: Pacer kwargs (duty/pace) for a --slow sender on a virtual clock"""
    out = os.path.join(tmp, "flash.out")
    if os.path.exists(out) and link is None:
        os.unlink(out)
    pacer = None
    if slow is not None:
        vc = link.clock if link and link.clock else VClock()
        pacer = L.Pacer(**slow, sleep=vc.sleep, clock=vc.clock)
    link = link or SimLink(sim, list(args), out, cut_after, events, vc if pacer else None)
    if pacer:
        link.clock.link = link
    s = L.OtaSender(link, img, m, log=lambda *_: None, status_timeout=0, retries=8,
                    pacer=pacer, state_file=state, resume=resume)
    err = None
    try:
        asyncio.run(s.run())
    except (L.OtaError, ConnectionError) as e:
        err = e
    return link, s, out, err


def main():
    tmp = tempfile.mkdtemp()
    sim = os.path.join(tmp, "ota_sim")
    build(sim)
    key = Ed25519PrivateKey.generate()
    pub = L.pubkey_hex(key)
    img = make_image(1_171_000)   # Heltec V3 repeater size, not a chunk multiple
    m = sign(img, key)
    failures = []

    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail and not cond else ""))
        if not cond:
            failures.append(name)

    def finished_ok(link, out, err):
        link.close()
        return err is None and os.path.exists(out) and open(out, "rb").read() == img

    link, s, out, err = run(sim, tmp, img, m, ["--pubkey", pub])
    frames = link.frames
    check("clean transfer", finished_ok(link, out, err), str(err))
    check("clean transfer is one pass", frames <= s.chunks + 40, f"{frames} frames for {s.chunks} chunks")
    check("sender's chunk size used", s.chunk == L.CHUNK, f"chunk {s.chunk}")

    link, s, out, err = run(sim, tmp, img, m, ["--pubkey", pub, "--drop", "20", "--seed", "3"])
    check("20% packet loss", finished_ok(link, out, err), str(err))

    link, s, out, err = run(sim, tmp, img, m, ["--pubkey", pub, "--corrupt-chunk", "4000"])
    check("bad flash write -> hash mismatch -> resend", finished_ok(link, out, err), str(err))

    other = Ed25519PrivateKey.generate()
    link, s, out, err = run(sim, tmp, img, sign(img, other), ["--pubkey", pub]); link.close()
    check("foreign key refused", err is not None and "bad signature" in str(err), str(err))

    link, s, out, err = run(sim, tmp, img, sign(img, key, board="other_board"), ["--pubkey", pub]); link.close()
    check("other board refused", err is not None and "bad signature" in str(err), str(err))

    bare = make_image(300_000, marker=False)
    try:
        L.sign_image(bare, BOARD, key)
        check("sign refuses an image without marker", False)
    except L.OtaError:
        check("sign refuses an image without marker", True)
    link, s, out, err = run(sim, tmp, bare, sign(bare, key, check_marker=False), ["--pubkey", pub]); link.close()
    check("target refuses an image without marker", err is not None and "marker" in str(err) and not os.path.exists(out), str(err))

    link, s, out, err = run(sim, tmp, img, m, ["--pubkey", pub, "--pending"]); link.close()
    check("refused while running image is unconfirmed", err is not None and "not confirmed" in str(err), str(err))

    link, s, out, err = run(sim, tmp, img, m, ["--pubkey", pub, "--capacity", "1000000"]); link.close()
    check("too big for the partition", err is not None and "too big" in str(err), str(err))

    tampered = bytearray(img); tampered[500_000] ^= 0xFF
    link, s, out, err = run(sim, tmp, bytes(tampered), m, ["--pubkey", pub]); link.close()
    check("image altered after signing never activates", err is not None and not os.path.exists(out), str(err))

    # resume: the link dies half way; a new sender on the same target picks up
    link, s1, out, err = run(sim, tmp, img, m, ["--pubkey", pub], cut_after=4000)
    session = s1.session
    link.cut_after, link.frames = None, 0
    link, s2, out, err = run(sim, tmp, img, m, link=link)
    frames = link.frames
    check("resume after a dropped link", finished_ok(link, out, err) and s2.session == session, str(err))
    check("resume sends only what is missing", frames < s2.chunks - 3500, f"{frames} frames")

    # ---------------------------------------------------------------- --slow: paced LONG sessions
    simg = make_image(300_000, seed=11)   # 2206 chunks: three STATUS windows
    sm = sign(simg, key)

    def slow_ok(link, out, err):
        link.close()
        return err is None and os.path.exists(out) and open(out, "rb").read() == simg

    link, s, out, err = run(sim, tmp, simg, sm, ["--pubkey", pub, "--drop", "15", "--seed", "5"], slow={"duty": 2})
    t_end, airtime = link.clock.t, s.pacer.airtime
    times = [t for t, typ, _ in link.log]
    gaps = [b - a for a, b in zip(times, times[1:])]
    data_gap = s.pacer.gap(7 + L.CHUNK)
    check("paced transfer, 15% loss", slow_ok(link, out, err) and s.long_ok, str(err))
    check("paced: about the asked share of airtime", 0.015 < airtime / t_end < 0.025, f"{100 * airtime / t_end:.2f}%")
    check("paced: never two packets closer than the gap minus jitter",
          min(gaps) >= (1 - L.JITTER) * min(data_gap, s.pacer.gap(7)) - 1e-6, f"min gap {min(gaps):.2f} s")
    check("paced: STATUS polls are paced too (each one's airtime, reply included, buys its own gap)",
          any(ty == L.REQ_STATUS for _, ty, _ in link.log) and
          all(g >= (1 - L.JITTER) * s.pacer.gap(7, L.REPLY_LEN[L.REQ_STATUS]) - 1e-6
              for (t0, ty0, _), g in zip(link.log, gaps) if ty0 == L.REQ_STATUS),
          "a packet went out too soon after a STATUS")
    eta = L.slow_eta(len(simg), L.Pacer(duty=2))
    check("ETA within 30% of a 15%-loss run", eta < t_end < eta * 1.6, f"eta {eta:.0f} s, took {t_end:.0f} s")

    # resume from the sender's state file: the sender dies, the target's session lives on
    st = os.path.join(tmp, "push-state.json")
    link, s1, out, err = run(sim, tmp, simg, sm, ["--pubkey", pub], cut_after=1500, slow={"duty": 2}, state=st)
    saved = __import__("json").load(open(st))
    link.cut_after, link.frames, link.log = None, 0, []
    link, s2, out, err = run(sim, tmp, simg, sm, link=link, slow={"duty": 2}, state=st, resume=saved)
    resent = link.data_sent - 1501
    polled = {base for _, typ, base in link.log if typ == L.REQ_STATUS}
    check("resume from the state file: same session, finishes", slow_ok(link, out, err) and s2.session == s1.session,
          str(err))
    check("resume: window 0 (acked in the file) is never polled again", 0 not in polled, f"polled {sorted(polled)}")
    check("resume: sends only what the file lacks", resent < s2.chunks - 1500 + 300, f"{resent} chunks resent")
    check("resume: state file gone after FINISH", not os.path.exists(st))

    # a long gap: under the LONG idle timeout the session stays, past it the target drops it
    link, s, out, err = run(sim, tmp, simg, sm, ["--pubkey", pub], slow={"pace": 30},
                            events={700: ("gap", 5 * 3600)})
    check("LONG: a 5 h silence keeps the session", slow_ok(link, out, err) and s.rebegins == 0, f"{err}, {s.rebegins}")
    link, s, out, err = run(sim, tmp, simg, sm, ["--pubkey", pub], slow={"pace": 30},
                            events={700: ("gap", 7 * 3600)})
    sent = link.data_sent
    check("LONG: a 7 h silence drops the session; BEGIN again keeps the chunks",
          slow_ok(link, out, err) and s.rebegins == 1 and sent < s.chunks + L.SLOW_ROUND,   # the rest of that round
          f"{err}, {s.rebegins}, {sent} DATA")                                               # went to the old session

    # the target reboots mid-transfer: the persisted bitmap (saved every 16 chunks) survives
    link, s, out, err = run(sim, tmp, simg, sm, ["--pubkey", pub], slow={"pace": 30}, events={1300: ("reboot",)})
    sent = link.data_sent
    check("LONG: target reboot resumes from the persisted bitmap",
          slow_ok(link, out, err) and s.rebegins == 1 and sent < s.chunks + L.SLOW_ROUND,
          f"{err}, {s.rebegins}, {sent} DATA")
    link, s, out, err = run(sim, tmp, simg, sm, ["--pubkey", pub, "--no-persist"], slow={"pace": 30},
                            events={1300: ("reboot",)})
    sent = link.data_sent
    check("LONG without a session store: a reboot restarts, still finishes",
          slow_ok(link, out, err) and sent >= s.chunks + 1000, f"{err}, {sent} DATA")

    # a fast (not LONG) session still drops after 5 min, and a fast sender gives up
    link, s, out, err = run(sim, tmp, simg, sm, ["--pubkey", pub], events={700: ("gap", 6 * 60)}); link.close()
    check("fast session: 6 min of silence still drops it", err is not None and "bad session" in str(err), str(err))

    # confirm after reboot: only an answer from the REBOOTED image counts
    class FakeNode:
        """before boots_after: the old image; after: the new one (or the old again: a rollback)"""
        def __init__(self, boots_after, replies=True, rolled_back=False):
            self.t0, self.boots_after, self.replies, self.rolled_back = time.monotonic(), boots_after, replies, rolled_back
        async def request(self, payload, want_reply, timeout):
            assert payload == bytes([L.REQ_CONFIRM])
            await asyncio.sleep(0.01)
            if not self.replies:
                return None
            age = time.monotonic() - self.t0
            booted = age >= self.boots_after
            up = int(age - self.boots_after) if booted else 3600
            sha = NEW_SHA if booted and not self.rolled_back else OLD_SHA
            return bytes([L.OK, 1 if booted and not self.rolled_back else 0]) + struct.pack("<I", up) + sha[:8]
    NEW_SHA, OLD_SHA = hashlib.sha256(b"new").digest(), hashlib.sha256(b"old").digest()
    q = lambda *_: None
    check("confirm waits for the rebooted image",
          asyncio.run(L.confirm_new_image(FakeNode(0.3), time.monotonic(), q, window=2, sha=NEW_SHA)))
    check("old image's answer never counts",
          not asyncio.run(L.confirm_new_image(FakeNode(99), time.monotonic(), q, window=0.5, sha=NEW_SHA)))
    check("silent node -> not confirmed",
          not asyncio.run(L.confirm_new_image(FakeNode(0, replies=False), time.monotonic(), q, window=0.5, sha=NEW_SHA)))
    try:
        asyncio.run(L.confirm_new_image(FakeNode(0.3, rolled_back=True), time.monotonic(), q, window=2, sha=NEW_SHA))
        check("a rollback is reported, not taken for success", False)
    except L.OtaError as e:
        check("a rollback is reported, not taken for success", "rolled back" in str(e), str(e))

    body = make_image(70000)
    body = body[:23] + b"\x01" + body[24:]   # header: "hash appended"
    esp = body + hashlib.sha256(body).digest()
    check("ESP32 running sha = esptool's appended hash", L.running_sha(esp) == hashlib.sha256(esp[:-32]).digest())
    check("other images: the file's sha", L.running_sha(b"\x00" * 100) == hashlib.sha256(b"\x00" * 100).digest())

    # nRF52 staging: littlefs v1 file -> physical extents -> raw writes (LoraOTALfs.h)
    lfs_dir = None
    for d in sorted(os.listdir(os.path.expanduser("~/.platformio/packages"))):
        c = os.path.expanduser(f"~/.platformio/packages/{d}/libraries/Adafruit_LittleFS/src/littlefs")
        if os.path.exists(os.path.join(c, "lfs.c")):
            lfs_dir = c
    if lfs_dir is None:
        check("nRF52 littlefs staging (needs the Adafruit nRF52 framework installed)", False)
    else:
        exe = os.path.join(tmp, "lfs_extents_test")
        objs = []
        for c in ("lfs.c", "lfs_util.c"):
            o = os.path.join(tmp, c + ".o")
            subprocess.check_call(["cc", "-O1", "-w", "-c", "-I", lfs_dir, os.path.join(lfs_dir, c), "-o", o])
            objs.append(o)
        subprocess.check_call(["c++", "-O1", "-Wall", "-I", lfs_dir, "-I", os.path.join(REPO, "src/helpers"),
                               os.path.join(HERE, "lfs_extents_test.cpp"), *objs, "-o", exe])
        r = subprocess.run([exe], capture_output=True, text=True)
        check("nRF52 littlefs staging: extents, raw out-of-order writes, remount, backup", r.returncode == 0, r.stdout)

    # LoraOTAService (radio switch, confirm window, rollback) with -ffast-math like the nRF52 build
    crypto = next(os.path.join(REPO, ".pio/libdeps", d, "Crypto") for d in sorted(os.listdir(os.path.join(REPO, ".pio/libdeps")))
                  if os.path.exists(os.path.join(REPO, ".pio/libdeps", d, "Crypto", "SHA256.cpp")))
    exe = os.path.join(tmp, "service_test")
    ed = os.path.join(REPO, "lib/ed25519")
    subprocess.check_call(["c++", "-O2", "-ffast-math", "-w", "-DLORA_OTA_ENABLED", "-DLORA_OTA_HOST_TEST",
                           '-DLORA_OTA_PUBKEY="' + pub + '"', '-DLORA_OTA_BOARD="test"',
                           "-I", os.path.join(HERE, "stubs"), "-I", os.path.join(REPO, "src/helpers"), "-I", ed, "-I", crypto,
                           os.path.join(HERE, "service_test.cpp"), os.path.join(REPO, "src/helpers/LoraOTAService.cpp"),
                           os.path.join(REPO, "src/helpers/LoraOTA.cpp"),
                           *[os.path.join(crypto, f) for f in ("SHA256.cpp", "Hash.cpp", "Crypto.cpp")],
                           *[os.path.join(ed, f) for f in sorted(os.listdir(ed)) if f.endswith(".c")], "-o", exe])
    svc = make_image(50_000, seed=3)
    sm = sign(svc, key, board="test")
    begin = (bytes([L.REQ_BEGIN]) + struct.pack("<I", len(svc)) + bytes.fromhex(sm["sha256"]) +
             bytes.fromhex(sm["sig"]) + bytes([L.CHUNK]))
    r = subprocess.run([exe, begin.hex(), (begin + bytes([L.FLAG_LONG])).hex()], capture_output=True, text=True)
    check("service: 500 kHz switch, idle drop-back, probation after setup, confirm sha, rollback at 60 s",
          r.returncode == 0, r.stdout.strip())
    check("service: a LONG session lets the node sleep, a fast one does not; LONG idle timeout",
          r.returncode == 0 and "all passed" in r.stdout, r.stdout.strip())

    print(f"\n{len(failures)} failed" if failures else "\nall passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
