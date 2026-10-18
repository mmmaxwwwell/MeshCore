"""Signed settings over LoRa: the real sender (lora_ota.py SettingsSender,
make_bundle) against the real node code (src/helpers/LoraOTASettings.cpp)
built for the host with a fake node (settings_sim.cpp). Called from
test_sim.py; check(name, cond, detail) records a result."""
import asyncio, hashlib, json, os, struct, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../.."))
import lora_ota as L
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BOARD = "test_board"
SELF = bytes(range(0x10, 0x30))   # the fake node's public key
OLD_RADIO = (910.525, 62.5, 7, 5)


def build(out, crypto, defines=()):
    ed = os.path.join(REPO, "lib/ed25519")
    subprocess.check_call(["c++", "-O2", "-Wall", "-Wno-unused-function", "-ffast-math", "-DLORA_OTA_HOST_TEST",
                           *[f"-D{d}" for d in defines],
                           "-I", os.path.join(REPO, "src/helpers"), "-I", ed, "-I", crypto,
                           os.path.join(HERE, "settings_sim.cpp"), os.path.join(REPO, "src/helpers/LoraOTASettings.cpp"),
                           *[os.path.join(crypto, f) for f in ("SHA256.cpp", "Hash.cpp", "Crypto.cpp")],
                           *[os.path.join(ed, f) for f in sorted(os.listdir(ed)) if f.endswith(".c")], "-o", out])


def radio_bytes(r):
    f, bw, sf, cr = r
    return struct.pack("<IIBB", round(f * 1000), round(bw * 1000), sf, cr)


class Node:
    """settings_sim over a pipe: requests (only heard on the node's radio), plus a clock"""

    def __init__(self, sim, pub, role="repeater", drop=0, seed=1, extra=()):
        self.p = subprocess.Popen([sim, "--pubkey", pub, "--board", BOARD, "--role", role, "--self", SELF.hex(),
                                   "--drop", str(drop), "--seed", str(seed), *extra],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def _frame(self, data):
        self.p.stdin.write(struct.pack("<H", len(data)) + data)
        self.p.stdin.flush()
        n = struct.unpack("<H", self.p.stdout.read(2))[0]
        return self.p.stdout.read(n)

    def control(self, op, args=b""):
        self.p.stdin.write(b"\xff\xff" + bytes([op]) + args)
        self.p.stdin.flush()
        n = struct.unpack("<H", self.p.stdout.read(2))[0]
        return self.p.stdout.read(n)

    async def request(self, payload, want_reply, timeout):
        assert 1 + 32 + len(payload) <= L.COMPANION_FRAME, f"{len(payload)}-byte request will not fit a companion frame"
        payload = payload + b"\0" * ((-(4 + len(payload))) % 16)   # AES blocks, as on the air
        body = self._frame(payload)
        return body or None

    async def sleep(self, secs):
        self.control(1, struct.pack("<I", int(secs * 1000)))

    def tick(self, secs):
        self.control(1, struct.pack("<I", int(secs * 1000)))

    def dump(self):
        return json.loads(self.control(2))

    def reboot(self):
        self.control(3)

    def fw_pending(self, on):
        self.control(5, bytes([on]))

    def close(self):
        self.p.stdin.close()
        self.p.wait()


class SimRadio:
    """the sending companion's radio, as SettingsSender drives it"""

    def __init__(self, node, follows=True):
        self.node, self.r, self.follows, self.history = node, OLD_RADIO, follows, []

    async def get(self):
        return self.r

    async def set(self, r):
        self.history.append(tuple(r))
        self.r = tuple(r)
        if self.follows:   # a companion that cannot follow (bad preset, out of range) stays deaf
            self.node.control(4, radio_bytes(r))
        else:
            self.node.control(4, radio_bytes((100.0, 7.8, 12, 8)))


def run_settings_tests(check, tmp, crypto):
    sim = os.path.join(tmp, "settings_sim")
    build(sim, crypto)
    key = Ed25519PrivateKey.generate()
    pub = L.pubkey_hex(key)
    node_t = (1, SELF[:8])
    v = [1000]

    def bundle(entries, target=node_t, version=None, k=key, check_keys=True, reboot=False):
        if version is None:
            v[0] += 1
            version = v[0]
        return L.make_bundle(entries, target, version, k, check=check_keys, reboot=reboot)

    def push(node, blob, radio=None, confirm=True):
        s = L.SettingsSender(node, blob, radio=radio, log=lambda *_: None, timeout=0, retries=8, sleep=node.sleep)
        try:
            return asyncio.run(s.run(confirm=confirm)), None
        except L.OtaError as e:
            return None, e

    def refused(blob, what, node=None, **kw):
        n = node or Node(sim, pub, **kw)
        ok, err = push(n, blob)
        d = n.dump()
        if node is None:
            n.close()
        return err is not None and what in str(err), f"{err}; {d}"

    # 1. good bundle, confirmed
    n = Node(sim, pub)
    ok, err = push(n, bundle([("flood.max.unscoped", "12"), ("tx", "20"), ("flood.advert.interval", "47")]))
    d = n.dump()
    check("settings: good bundle applies and is confirmed",
          ok and d["saved"]["flood.max.unscoped"] == 12 and d["saved"]["tx"] == 20 and
          d["saved"]["flood.advert.interval"] == 47 and d["tx_live"] == 20 and not d["pending"] and d["version"] == v[0],
          f"{err}; {d}")
    n.tick(120)
    d = n.dump()
    check("settings: a confirmed bundle stays", d["saved"]["flood.max.unscoped"] == 12 and d["saved"]["tx"] == 20, str(d))

    # 2. replay: the same bundle again, and an older one
    again = bundle([("flood.max.unscoped", "30")], version=v[0])
    ok_, why = refused(again, "not newer", node=n)
    check("settings: same version refused (replay)", ok_, why)
    ok_, why = refused(bundle([("flood.max.unscoped", "30")], version=5), "not newer", node=n)
    check("settings: older version refused", ok_, why)
    check("settings: refusals change nothing", n.dump()["saved"]["flood.max.unscoped"] == 12)
    n.close()

    # 3. no CONFIRM: back to the old values at 60 s
    n = Node(sim, pub)
    ok, err = push(n, bundle([("flood.max.unscoped", "12"), ("af", "2.5"), ("tx", "10")]), confirm=False)
    d = n.dump()
    applied = d["saved"]["flood.max.unscoped"] == 12 and d["saved"]["af"] == 2500 and d["pending"]
    n.tick(L.SET_CONFIRM_SECS - 3)   # (tx is a radio key: live from 1.5 s after the OK)
    early = n.dump()
    applied = applied and early["tx_live"] == 10
    n.tick(5)
    d = n.dump()
    check("settings: unconfirmed bundle applies, then reverts by itself at 60 s",
          applied and early["pending"] and d["saved"]["flood.max.unscoped"] == 64 and d["saved"]["af"] == 1000 and
          d["saved"]["tx"] == 22 and d["tx_live"] == 22 and not d["pending"], f"{err}; {early}; {d}")
    check("settings: a reverted bundle's version stays spent", d["version"] == v[0])
    n.close()

    # 4. radio change: the sender follows, confirms on the new settings, and goes back
    n = Node(sim, pub)
    radio = SimRadio(n)
    new = "910.525,250,11,5"
    ok, err = push(n, bundle([("radio", new), ("flood.max", "20")]), radio=radio)
    d = n.dump()
    check("settings: radio change confirmed on the new settings",
          ok and d["saved"]["radio"] == [910525, 250000, 11, 5] and d["live"] == [910525, 250000, 11, 5] and not d["pending"],
          f"{err}; {d}")
    check("settings: sender's companion back on its own radio afterwards",
          radio.r == OLD_RADIO and radio.history == [(910.525, 250.0, 11, 5), OLD_RADIO], str(radio.history))
    n.close()

    # 5. bad radio change: the sender cannot reach the node on it; the node comes back by itself
    n = Node(sim, pub)
    radio = SimRadio(n, follows=False)
    ok, err = push(n, bundle([("radio", "915.0,125,9,5")]), radio=radio)
    mid = n.dump()
    n.tick(L.SET_CONFIRM_SECS + 5)
    d = n.dump()
    n.control(4, radio_bytes(OLD_RADIO))   # what the sender's restore leaves it on
    st = L.set_status(asyncio.run(n.request(bytes([L.REQ_SET_CTRL, L.SET_OP_STATUS]), True, 0)))
    check("settings: unreachable after a radio change -> node reverts its radio by itself",
          ok is False and mid["live"] == [915000, 125000, 9, 5] and d["live"] == [910525, 62500, 7, 5] and
          d["saved"]["radio"] == [910525, 62500, 7, 5] and not d["pending"] and radio.r == OLD_RADIO,
          f"{err}; {mid}; {d}")
    check("settings: reachable again on the old radio, nothing pending", st is not None and st["pending"] == 0, str(st))
    n.close()

    # 6. a reboot during probation brings the old values back at boot
    n = Node(sim, pub)
    push(n, bundle([("flood.max.unscoped", "12"), ("radio", "915.0,125,9,5")]), confirm=False)
    n.tick(5)
    mid = n.dump()
    n.reboot()
    d = n.dump()
    check("settings: reboot before CONFIRM -> old values at boot",
          mid["saved"]["flood.max.unscoped"] == 12 and d["saved"]["flood.max.unscoped"] == 64 and
          d["live"] == [910525, 62500, 7, 5] and not d["pending"], f"{mid}; {d}")
    n.close()

    # 7. signatures
    other = Ed25519PrivateKey.generate()
    ok_, why = refused(bundle([("flood.max", "10")], k=other), "bad signature")
    check("settings: wrong signing key refused", ok_, why)
    blob = bytearray(bundle([("flood.max", "10")]))
    blob[-70] ^= 1   # inside the body, after signing
    ok_, why = refused(bytes(blob), "bad signature")
    check("settings: bundle altered after signing refused", ok_, why)

    # 8. a firmware-manifest signature is never a settings signature: sign
    # "MCOTA1"||board||size||sha with the real key and send the manifest's
    # bytes after the domain as a bundle body
    sha = hashlib.sha256(b"img").digest()
    manifest = L.manifest_message(BOARD, 0x1000, sha)
    forged = manifest[6:] + key.sign(manifest)
    ok_, why = refused(forged, "bad signature")
    check("settings: firmware-manifest signature not accepted as a bundle", ok_, why)
    body = L.bundle_body(v[0] + 1, node_t, [("flood.max", "10")])
    forged = body + key.sign(b"MCOTA1" + body)   # right body, firmware domain
    ok_, why = refused(forged, "bad signature")
    check("settings: a signature under the firmware domain is refused", ok_, why)

    # 9. whitelist
    for k, val in (("password", "hunter2"), ("prv.key", "00" * 64), ("guest.password", "x"), ("name", "Evil"),
                   ("lat", "1.0"), ("ota", "off")):
        try:
            L.make_bundle([(k, val)], node_t, 5000, key)
            sender_ok = False
        except L.OtaError:
            sender_ok = True
        ok_, why = refused(bundle([(k, val)], check_keys=False), "not on the whitelist")
        check(f"settings: non-whitelisted '{k}' refused (sender and node)", sender_ok and ok_, why)
    ok_, why = refused(bundle([("flood.max", "10"), ("password", "x")], check_keys=False), "not on the whitelist")
    check("settings: one bad key spoils the whole bundle", ok_, why)

    # 10. values, targets, roles
    for k, val in (("radio", "910.525,62.5,13,5"), ("radio", "910.5251,62.5,7,5"), ("radio", "3000,62.5,7,5"),
                   ("tx", "23"), ("flood.max", "65"), ("advert.interval", "30"), ("loop.detect", "max"),
                   ("regions", "bad name")):
        ok_, why = refused(bundle([(k, val)]), "out of range")
        check(f"settings: bad value {k}={val} refused", ok_, why)
    ok_, why = refused(bundle([("flood.max", "10")], target=(1, bytes(8))), "another node")
    check("settings: bundle for another node refused", ok_, why)
    ok_, why = refused(bundle([("flood.max", "10")], target=(2, b"other_board")), "another node")
    check("settings: bundle for another board refused", ok_, why)
    n = Node(sim, pub)
    ok, err = push(n, bundle([("flood.max", "10")], target=(2, BOARD.encode())))
    check("settings: board-tag target applies", ok and n.dump()["version"] == v[0], str(err))
    n.close()
    ok_, why = refused(bundle([("flood.max", "10")]), "no such setting", role="companion")
    check("settings: repeater-only key refused on a companion", ok_, why)
    n = Node(sim, pub, role="companion")
    ok, err = push(n, bundle([("tx", "14"), ("path.hash.mode", "1")]))
    d = n.dump()
    check("settings: companion takes its keys", ok and d["saved"]["tx"] == 14 and d["saved"]["path.hash.mode"] == 1, f"{err}; {d}")
    n.close()

    # 11. one thing at a time
    n = Node(sim, pub)
    n.fw_pending(1)
    ok_, why = refused(bundle([("flood.max", "10")]), "not confirmed", node=n)
    check("settings: refused while a new firmware image is unconfirmed", ok_, why)
    n.fw_pending(0)
    push(n, bundle([("flood.max", "10")]), confirm=False)
    ok_, why = refused(bundle([("flood.max", "11")]), "still on probation", node=n)
    check("settings: a second bundle waits for the first's confirm", ok_, why)
    st = L.set_status(asyncio.run(n.request(bytes([L.REQ_SET_CTRL, L.SET_OP_REVERT]), True, 0)))
    d = n.dump()
    check("settings: REVERT puts the old values back at once", st and st["was"] == 1 and d["saved"]["flood.max"] == 64 and
          not d["pending"], f"{st}; {d}")
    n.control(6)   # the probation record cannot be written
    ok_, why = refused(bundle([("flood.max", "12")]), "could not save", node=n)
    check("settings: no probation record, no change", ok_ and n.dump()["saved"]["flood.max"] == 64, why)
    n.close()

    # 12. regions, a multi-chunk bundle, packet loss
    n = Node(sim, pub, drop=20, seed=4)
    names = ",".join(["northeast", "east", "*"] + [f"r{i:02d}-" + "x" * 15 for i in range(10)])
    blob = bundle([("regions", names), ("flood.max.unscoped", "12"), ("loop.detect", "moderate")])
    ok, err = push(n, blob, confirm=False)
    d = n.dump()
    regs = set(d["saved"]["regions"].split(","))
    got = ok is False and {"ct", "northeast", "east", "*"} <= regs and d["saved"]["loop.detect"] == 2
    n.tick(L.SET_CONFIRM_SECS + 2)
    d = n.dump()
    check(f"settings: {len(blob)}-byte bundle with regions over 20% loss, then regions revert",
          got and d["saved"]["regions"] == "ct" and d["saved"]["loop.detect"] == 0, f"{err}; {d}")
    n.close()

    # 13. GET: what a companion's settings read as
    n = Node(sim, pub, role="companion")
    text, start = "", 0
    while start != 0xFF:
        r = asyncio.run(n.request(bytes([L.REQ_SET_CTRL, L.SET_OP_GET, start]), True, 0))
        text += r[2:].decode()
        start = r[1]
    check("settings: GET lists the current values", "radio=910.525,62.5,7,5\n" in text and "tx=22\n" in text and
          "af=1\n" in text and "flood.max" not in text, text)
    n.close()

    # 14. signed-only mode: which over-LoRa CLI commands it blocks
    blocked = ["set radio 915,125,9,5", "set tx 30", "set af 3", "set dutycycle 10", "set flood.max 3",
               "set flood.max.unscoped 1", "set advert.interval 60", "set repeat off", "set path.hash.mode 2",
               "region put ct", "region allowf *", "region denyf ct", "region remove ct", "region load",
               "region default ct", "region def ct", "tempradio 915,125,9,5,10"]
    free = ["set name x", "password x", "set guest.password x", "get radio", "region list allowed", "region get ct",
            "region", "ota status", "set lat 1", "reboot", "powersaving on"]
    exe = os.path.join(tmp, "unsigned_cmd")
    with open(exe + ".cpp", "w") as f:
        f.write('#include "LoraOTASettings.h"\n#include <stdio.h>\nint main(int c, char** v) {\n'
                '  for (int i = 1; i < c; i++) printf("%d", lora_ota_settings::isUnsignedSettingsCommand(v[i]));\n'
                '  return 0; }\n')
    ed = os.path.join(REPO, "lib/ed25519")
    subprocess.check_call(["c++", "-O1", "-w", "-DLORA_OTA_HOST_TEST", "-I", os.path.join(REPO, "src/helpers"), "-I", ed,
                           "-I", crypto, exe + ".cpp", os.path.join(REPO, "src/helpers/LoraOTASettings.cpp"),
                           *[os.path.join(crypto, f) for f in ("SHA256.cpp", "Hash.cpp", "Crypto.cpp")],
                           *[os.path.join(ed, f) for f in sorted(os.listdir(ed)) if f.endswith(".c")], "-o", exe])
    out = subprocess.run([exe, *blocked, *free], capture_output=True, text=True).stdout
    check("settings: signed-only mode blocks exactly the whitelisted settings' commands",
          out == "1" * len(blocked) + "0" * len(free), out)

    run_feature_tests(check, tmp, crypto, sim, key, pub, bundle, push, refused, v)


def run_feature_tests(check, tmp, crypto, sim, key, pub, bundle, push, refused, v):
    """our companion features (POSITION_REPORT, OVERLAY_MESH), client repeat, reboot-after-confirm, diff"""
    feat = os.path.join(tmp, "settings_sim_feat")
    build(feat, crypto, defines=("POSITION_REPORT", "OVERLAY_MESH"))

    def ctrl(n, op):
        return L.set_status(asyncio.run(n.request(bytes([L.REQ_SET_CTRL, op]), True, 0)))

    def get_all(n):
        text, start = "", 0
        while start != 0xFF:
            r = asyncio.run(n.request(bytes([L.REQ_SET_CTRL, L.SET_OP_GET, start]), True, 0))
            text += r[2:].decode()
            start = r[1]
        return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)

    # 15. feature keys: refused by a build without the features, on any role
    for k, val in (("posreport.interval", "5"), ("overlay", "off")):
        for role in ("companion", "repeater"):
            ok_, why = refused(bundle([(k, val)]), "not on the whitelist", role=role)
            check(f"settings: '{k}' refused by a {role} built without its feature", ok_, why)
    n = Node(sim, pub, role="companion")
    g = get_all(n)
    check("settings: GET of a featureless companion lists no feature keys",
          "posreport.interval" not in g and "overlay" not in g and g.get("repeat") == "off", str(g))
    n.close()
    # ... and a repeater built WITH them still refuses them (its role has no such setting)
    ok_, why = refused(bundle([("posreport.interval", "5")]), "no such setting", node=Node(feat, pub))
    check("settings: feature key refused by a repeater even in a feature build", ok_, why)

    # 16. posreport.interval: applies as #locset, confirmed; and reverts without a CONFIRM
    n = Node(feat, pub, role="companion")
    g = get_all(n)
    check("settings: feature build GET shows posreport.interval and overlay",
          g.get("posreport.interval") == "0" and g.get("overlay") == "on", str(g))
    ok, err = push(n, bundle([("posreport.interval", "15")]))
    d = n.dump()
    check("settings: posreport.interval applies and is confirmed", ok and d["posreport.interval"] == 15 and not d["pending"],
          f"{err}; {d}")
    ok, err = push(n, bundle([("posreport.interval", "1")]), confirm=False)
    mid = n.dump()
    n.tick(L.SET_CONFIRM_SECS + 2)
    d = n.dump()
    check("settings: posreport.interval reverts without a CONFIRM",
          mid["posreport.interval"] == 1 and mid["pending"] and d["posreport.interval"] == 15 and not d["pending"],
          f"{err}; {mid}; {d}")
    for bad in ("1441", "-1", "2.5", "x"):
        ok_, why = refused(bundle([("posreport.interval", bad)]), "out of range", node=n)
        check(f"settings: posreport.interval={bad} refused", ok_, why)
    n.close()

    # 17. overlay off: as #ovlset off (repeat goes off with it), node-side snapshot, revert, confirm
    n = Node(feat, pub, role="companion", extra=("--client-repeat",))
    ok, err = push(n, bundle([("overlay", "off")]), confirm=False)
    mid = n.dump()
    in_state = n.control(7, bytes([len(b"ourgroup")]) + b"ourgroup") == b"1"
    n.tick(L.SET_CONFIRM_SECS + 2)
    d = n.dump()
    check("settings: overlay off takes client repeat with it, both revert without a CONFIRM",
          mid["overlay"] == "" and mid["repeat"] == 0 and mid["overlay_snapshot"] == 1 and
          d["overlay"] == "#ourgroup" and d["repeat"] == 1 and d["overlay_snapshot"] == 0 and not d["pending"],
          f"{err}; {mid}; {d}")
    check("settings: the overlay name never goes into the state file (only the node's overlay snapshot)", not in_state)
    push(n, bundle([("overlay", "off")]), confirm=False)
    n.tick(5)
    n.reboot()
    d = n.dump()
    check("settings: reboot before CONFIRM brings the overlay back", d["overlay"] == "#ourgroup" and d["repeat"] == 1 and
          d["overlay_snapshot"] == 0, str(d))
    ok, err = push(n, bundle([("overlay", "off")]))
    d = n.dump()
    check("settings: overlay off confirmed: off for good, no copy of the region name left on the node",
          ok and d["overlay"] == "" and d["repeat"] == 0 and d["overlay_snapshot"] == 0, f"{err}; {d}")
    n.close()
    # 17b. overlay on: as "#ovlset on #<name> <r>" (owner, 2026-10-18: the name travels in the
    # signed bundle, inside the REQ's end-to-end encryption; the bundle file is kept like a key)
    n = Node(feat, pub, role="companion", extra=("--client-repeat",))
    ok, err = push(n, bundle([("overlay", "on #newgrp 0")]), confirm=False)
    mid = n.dump()
    in_state = n.control(7, bytes([len(b"newgrp")]) + b"newgrp") == b"1"
    n.tick(L.SET_CONFIRM_SECS + 2)
    d = n.dump()
    check("settings: overlay on #name 0 applies (repeat set from it) and reverts without a CONFIRM",
          mid["overlay"] == "#newgrp" and mid["repeat"] == 0 and mid["overlay_snapshot"] == 1 and
          d["overlay"] == "#ourgroup" and d["repeat"] == 1 and d["overlay_snapshot"] == 0 and not d["pending"],
          f"{err}; {mid}; {d}")
    check("settings: a bundle's overlay name never goes into the state file", not in_state)
    ok, err = push(n, bundle([("overlay", "on #newgrp 0")]))
    d = n.dump()
    check("settings: overlay on confirmed: new name kept, snapshot deleted",
          ok and d["overlay"] == "#newgrp" and d["repeat"] == 0 and d["overlay_snapshot"] == 0, f"{err}; {d}")
    n.close()
    for bad in ("on", "on #newgrp", "on newgrp 0", "on # 0", "on #a b 0", "on #newgrp 2", "on #" + "x" * 31 + " 0", "On #g 0"):
        ok_, why = refused_on(feat, pub, bundle([("overlay", bad)], check_keys=False), "out of range", push, role="companion")
        try:
            L.make_bundle([("overlay", bad)], (1, SELF[:8]), 1, key)
            sender_ok = False
        except L.OtaError:
            sender_ok = True
        check(f"settings: overlay={bad!r} refused by node and sender", ok_ and sender_ok, why)
    check("settings: the sender never prints the overlay name in full",
          "newgrp" not in str(L.shown("overlay", "on #newgrp 1")) and L.shown("posreport.interval", "5") == "5")
    ok_, why = refused_on(feat, pub, bundle([("overlay", "on #newgrp 0"), ("repeat", "on")]), "out of range", push,
                          role="companion", extra=("--client-repeat",))
    check("settings: overlay on #name 0 + repeat on in one bundle refused (contradiction)", ok_, why)
    ok_, why = refused_on(feat, pub, bundle([("overlay", "on #newgrp 1")]), "out of range", push, role="companion")
    check("settings: overlay on #name 1 refused off the client-repeat bands (as CMD_SET_RADIO_PARAMS)", ok_, why)
    ok_, why = refused_on(feat, pub, bundle([("overlay", "off"), ("repeat", "on")]), "out of range", push,
                          role="companion", extra=("--client-repeat",))
    check("settings: overlay off + repeat on in one bundle refused (contradiction)", ok_, why)

    # 18. client repeat on a companion: the allowed-band rule of CMD_SET_RADIO_PARAMS
    ok_, why = refused(bundle([("repeat", "on")]), "out of range", role="companion")
    check("settings: repeat on refused off the allowed bands (910.525)", ok_, why)
    n = Node(sim, pub, role="companion", extra=("--client-repeat",))
    ok_, why = refused(bundle([("radio", "910.525,62.5,7,5")]), "out of range", node=n)
    check("settings: a repeating companion cannot move off the allowed bands", ok_, why)
    ok, err = push(n, bundle([("repeat", "off")]))
    d = n.dump()
    check("settings: repeat off on a companion applies", ok and d["repeat"] == 0, f"{err}; {d}")
    ok, err = push(n, bundle([("repeat", "on")]), confirm=False)
    mid = n.dump()
    n.tick(L.SET_CONFIRM_SECS + 2)
    d = n.dump()
    check("settings: repeat on (918 MHz) applies, reverts without a CONFIRM",
          mid["repeat"] == 1 and d["repeat"] == 0 and not d["pending"], f"{err}; {mid}; {d}")
    n.close()

    # 19. reboot: once, only after the CONFIRM; never when the bundle reverts
    n = Node(feat, pub, role="companion")
    ok, err = push(n, bundle([("posreport.interval", "30")], reboot=True))
    right_after = n.dump()
    st = ctrl(n, L.SET_OP_STATUS)
    n.tick(L.SET_REBOOT_SECS - 1)
    before = n.dump()
    n.tick(2)
    d = n.dump()
    n.tick(30)
    later = n.dump()
    check("settings: reboot=1 reboots once, ~6 s after the CONFIRM; prefs survive",
          ok and right_after["reboots"] == 0 and right_after["reboot_due"] == 1 and st["reboot_due"] and
          before["reboots"] == 0 and d["reboots"] == 1 and later["reboots"] == 1 and
          later["posreport.interval"] == 30 and later["version"] == v[0] and not later["pending"],
          f"{err}; {right_after}; {before}; {d}; {later}")
    ok, err = push(n, bundle([("posreport.interval", "45")], reboot=True), confirm=False)
    st = ctrl(n, L.SET_OP_STATUS)
    n.tick(L.SET_CONFIRM_SECS + 30)
    d = n.dump()
    check("settings: reboot=1 without a CONFIRM: reverts, no reboot",
          st["reboot_asked"] and not st["reboot_due"] and d["reboots"] == 1 and d["posreport.interval"] == 30 and
          not d["pending"] and not d["reboot_due"], f"{err}; {st}; {d}")
    push(n, bundle([("posreport.interval", "45")], reboot=True), confirm=False)
    st = ctrl(n, L.SET_OP_REVERT)
    n.tick(30)
    d = n.dump()
    check("settings: reboot=1 then REVERT: no reboot", st["was"] and d["reboots"] == 1 and d["posreport.interval"] == 30,
          f"{st}; {d}")
    n.close()
    # a radio change + reboot: CONFIRM only once the node is on the new radio; the reboot keeps it
    n = Node(feat, pub, role="companion")
    radio = SimRadio(n)
    ok, err = push(n, bundle([("radio", "910.525,250,11,5")], reboot=True), radio=radio)
    n.tick(L.SET_REBOOT_SECS + 2)
    d = n.dump()
    check("settings: radio change + reboot: confirmed, rebooted once, comes up on the new radio",
          ok and d["reboots"] == 1 and d["live"] == [910525, 250000, 11, 5] and not d["pending"], f"{err}; {d}")
    n.close()
    # a reboot is not a bundle by itself, and only "1" asks for one
    body = L.bundle_body(v[0] + 100, (1, SELF[:8]), [("reboot", "1")])
    ok_, why = refused(body + key.sign(L.SET_DOMAIN + body), "does not parse", role="companion")
    check("settings: a reboot-only bundle refused", ok_, why)
    body = L.bundle_body(v[0] + 101, (1, SELF[:8]), [("tx", "10"), ("reboot", "yes")])
    ok_, why = refused(body + key.sign(L.SET_DOMAIN + body), "out of range", role="companion")
    check("settings: reboot=<not 1> refused", ok_, why)
    try:
        L.make_bundle([("reboot", "1")], (1, SELF[:8]), 1, key)
        sender_ok = False
    except L.OtaError:
        sender_ok = True
    check("settings: sender wants --reboot, not --set reboot=1", sender_ok)
    # the replay counter holds across the reboot it asked for
    n = Node(feat, pub, role="companion")
    blob = bundle([("posreport.interval", "5")], reboot=True)
    push(n, blob)
    n.tick(L.SET_REBOOT_SECS + 2)
    ok_, why = refused(blob, "not newer", node=n)
    check("settings: a reboot bundle cannot be replayed after the reboot", ok_ and n.dump()["reboots"] == 1, why)
    n.close()

    # 20. diff: only the changed keys
    cur = {"radio": "910.525,62.5,7,5", "tx": "22", "af": "1", "repeat": "off", "posreport.interval": "0",
           "overlay": "on", "regions": "ct,northeast", "rxdelay": "> 0.0"}
    want = [("radio", "910.525,62.50,7,5"), ("tx", "22"), ("af", "1.0"), ("repeat", "off"), ("posreport.interval", "10"),
            ("overlay", "off"), ("regions", "northeast,ct"), ("rxdelay", "0"), ("multi.acks", "1")]
    got = L.diff_entries(cur, want)
    check("settings: diff keeps only the changed (and unknown) keys",
          got == [("posreport.interval", "10"), ("overlay", "off"), ("multi.acks", "1")], str(got))
    n = Node(feat, pub, role="companion")
    g = get_all(n)
    want = [("tx", "22"), ("af", "1"), ("posreport.interval", "20"), ("radio.rxgain", "on")]
    changed = L.diff_entries(g, want)
    full = bundle(want)
    small = bundle(changed)
    ok, err = push(n, small)
    d = n.dump()
    check(f"settings: diff against the node's GET -> {len(small)}-byte bundle (all keys: {len(full)}), applies",
          changed == [("posreport.interval", "20")] and len(small) < len(full) and ok and d["posreport.interval"] == 20,
          f"{changed}; {err}; {d}")
    check("settings: diff of what the node already has is empty", L.diff_entries(get_all(n), want) == [])
    n.close()

    # 21. airtime of a settings push (slow mode's math)
    pk, air, t = L.settings_eta(len(small), L.Pacer(hops=0))
    pk3, air3, _ = L.settings_eta(len(small), L.Pacer(hops=3))
    check(f"settings: a {len(small)}-byte bundle is {pk} round trips, {air:.1f} s airtime direct, {air3:.1f} s at 3 hops",
          pk == 5 and 0 < 4 * air <= air3 < 5 * air, f"{pk} {air} {air3}")


def refused_on(sim, pub, blob, what, push, **kw):
    n = Node(sim, pub, **kw)
    ok, err = push(n, blob)
    d = n.dump()
    n.close()
    return err is not None and what in str(err), f"{err}; {d}"
