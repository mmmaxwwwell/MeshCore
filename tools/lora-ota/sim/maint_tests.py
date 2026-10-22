"""Maintenance over LoRa: the real sender (lora_ota.py MaintSender,
make_command, maint_do) against the real node code
(src/helpers/LoraOTAMaint.cpp) built for the host with a fake node
(maint_sim.cpp). Called from test_sim.py; check(name, cond, detail)
records a result."""
import asyncio, hashlib, json, os, struct, subprocess
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../.."))
import lora_ota as L
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BOARD = "test_board"
SELF = bytes(range(0x40, 0x60))   # the fake node's public key
# what the fake node holds that must never come back in any reply
SECRETS = [b"SECRET", b"secretgroup", hashlib.sha256(b"#secretgroup").digest()[:16], b"SECRET-PSK-BYTES"]


def build(out, crypto):
    ed = os.path.join(REPO, "lib/ed25519")
    subprocess.check_call(["c++", "-O2", "-Wall", "-Wno-unused-function", "-ffast-math", "-DLORA_OTA_HOST_TEST",
                           "-I", os.path.join(REPO, "src/helpers"), "-I", ed, "-I", crypto,
                           os.path.join(HERE, "maint_sim.cpp"), os.path.join(REPO, "src/helpers/LoraOTAMaint.cpp"),
                           *[os.path.join(crypto, f) for f in ("SHA256.cpp", "Hash.cpp", "Crypto.cpp")],
                           *[os.path.join(ed, f) for f in sorted(os.listdir(ed)) if f.endswith(".c")], "-o", out])


def contact_key(i):
    """maint_sim's generated contact i"""
    return hashlib.sha256(bytes([i & 0xFF, i >> 8, 0x5A, 0xA5])).digest()


class Node:
    """maint_sim over a pipe: requests, a clock, control ops; keeps every reply for the leak check"""

    def __init__(self, sim, pub, role="companion", contacts=40, drop=0, seed=1, extra=()):
        self.p = subprocess.Popen([sim, "--pubkey", pub, "--board", BOARD, "--role", role, "--self", SELF.hex(),
                                   "--contacts", str(contacts), "--drop", str(drop), "--seed", str(seed), *extra],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.replies, self.working = [], 0

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
        assert len(body) <= 4 + 128 + 5, f"{len(body)}-byte reply"   # what a REQ reply carries back
        if body:
            self.replies.append(bytes(body))
            if payload[0] == L.REQ_MNT_EXEC and body[0] == L.WORKING:
                self.working += 1
        return body or None

    async def sleep(self, secs):
        self.tick(secs)

    def tick(self, secs):
        self.control(1, struct.pack("<I", int(secs * 1000)))

    def dump(self):
        return json.loads(self.control(2))

    def power_cycle(self):
        self.control(3)

    def busy(self, b):
        self.control(5, bytes([b]))

    def requester(self, key):
        self.control(7, key if key else bytes(32))

    def put_file(self, fs, path):
        self.control(8 if fs == 1 else 9, bytes([len(path)]) + path.encode())

    def leaks(self):
        return [s for s in SECRETS for r in self.replies if s in r]

    def close(self):
        self.p.stdin.close()
        self.p.wait()


def run_maint_tests(check, tmp, crypto):
    sim = os.path.join(tmp, "maint_sim")
    build(sim, crypto)
    key = Ed25519PrivateKey.generate()
    pub = L.pubkey_hex(key)
    me = (1, SELF[:8])
    ctr = [1000]
    quiet = lambda *_: None

    def cmd(op, args=b"", target=me, counter=None, k=key, domain=None):
        if counter is None:
            ctr[0] += 1
            counter = ctr[0]
        if domain is None:
            return L.make_command(op, args, target, counter, k)
        body = struct.pack("<IBB", counter, target[0], len(target[1])) + target[1] + bytes([op]) + args
        return body + k.sign(domain + body)

    def sender(n):
        return L.MaintSender(n, log=quiet, timeout=0, retries=8, sleep=n.sleep)

    def run(n, blob):
        return asyncio.run(sender(n).run(blob))

    def read(n, what, *a, **kw):
        return asyncio.run(getattr(sender(n), what)(*a, **kw))

    def same(a, b):
        keys = ("contacts", "channels", "files", "identity", "counter", "reboots")
        return all(a[k] == b[k] for k in keys)

    # ------------------------------------------------------------ read-only
    n = Node(sim, pub)
    before = n.dump()
    st = read(n, "status")
    check("maint: STATUS (role, fw, board, contacts, favourites, channels, both filesystems)",
          st["role"] == "companion" and st["fw"] == "v1.18.0-maint-sim" and st["board"] == BOARD and
          st["contacts"] == 40 and st["contacts_max"] == 350 and st["favourites"] == 4 and st["channels"] == 3 and
          st["has_extrafs"] and st["fs"]["extrafs"] is not None and st["fs"]["primary"]["total_kb"] == 28 and
          st["batt_mv"] == 4012 and st["maint_counter"] == 0, str(st))
    f0, f1 = read(n, "files", 0), read(n, "files", 1)
    names0 = {e["name"]: e["size"] for e in f0}
    names1 = {e["name"]: e for e in f1}
    check("maint: file list, primary: names + sizes", names0.get("_main.id") == 64 and "prefs.json" in names0 and
          "ota_settings" in names0, str(f0))
    check("maint: file list, ExtraFS: files and a directory", "contacts3" in names1 and names1["contacts3"]["size"] == 40 * 152
          and names1.get("old", {}).get("dir") is True, str(f1))
    sub = read(n, "files", 1, "/old")
    check("maint: file list of a subdirectory", [e["name"] for e in sub] == ["junk.bin"], str(sub))
    try:
        read(n, "files", 1, "/nope")
        check("maint: file list of a missing directory refused", False)
    except L.OtaError as e:
        check("maint: file list of a missing directory refused", "not found" in str(e), str(e))
    for bad in ("/../x", "/a/../b"):
        r = asyncio.run(n.request(bytes([L.REQ_MNT_READ, L.MNT_RD_FILES, 0, 0, 0]) + bad.encode(), True, 0))
        check(f"maint: file list path {bad!r} refused", r[0] == L.BAD_ARG, r.hex())
    chs = read(n, "channels")
    check("maint: channels: index + name; a hashtag channel's name (its key) cut short",
          [(c["index"], c["name"], c["name_keyed"]) for c in chs] == [(0, "Public", False), (1, "#se", True), (2, "family", False)],
          str(chs))
    lst, total = read(n, "contacts")
    check("maint: contacts list: prefix, name, type, flags, last advert",
          total == 40 and len(lst) == 40 and lst[3]["prefix"] == contact_key(3)[:6].hex() and lst[3]["name"] == "node-003"
          and lst[3]["type"] == 4 and lst[10]["flags"] == 1 and lst[7]["last_advert"] == 1700000007, str(lst[:4]))
    rs, _ = read(n, "contacts", types=(1 << 2) | (1 << 4), nonfav=True)
    want = [i for i in range(40) if (1 + i % 4) in (2, 4) and i % 10]
    check("maint: contacts list filtered (repeaters + sensors, not favourites)",
          [c["prefix"] for c in rs] == [contact_key(i)[:6].hex() for i in want], str(rs))
    check("maint: read requests change nothing", same(before, n.dump()))
    check("maint: no reply carries a secret (keys, passwords, channel secrets, overlay name, file contents)",
          not n.leaks(), str(n.leaks()))
    n.close()

    # a real reply is decrypted in 16-byte AES blocks: zero padding at the end is not an entry
    class Padded:
        def __init__(self, replies): self.replies = list(replies)
        async def ask(self, payload, what, tries=None): return self.replies.pop(0)
    def pad(b): return b + bytes(-len(b) % 16 + 16)
    con = bytes([L.OK]) + struct.pack("<HH", 1, 0xFFFF) + bytes.fromhex("5cca79022ef9") + bytes([1, 1]) + struct.pack("<I", 7) + bytes([6]) + b"Ranger"
    chn = bytes([L.OK, 0xFF, 0, 0, 6]) + b"Public"
    fil = bytes([L.OK]) + struct.pack("<H", 0xFFFF) + bytes([0]) + struct.pack("<I", 9) + bytes([4]) + b"prefs"[:4]
    pc, _ = asyncio.run(L.MaintSender.contacts(Padded([pad(con)])))
    pch = asyncio.run(L.MaintSender.channels(Padded([pad(chn)])))
    pf = asyncio.run(L.MaintSender.files(Padded([pad(fil)])))
    check("maint: zero padding after the last entry is not read as contacts / channels / files",
          [c["name"] for c in pc] == ["Ranger"] and [c["name"] for c in pch] == ["Public"] and [f["name"] for f in pf] == ["pref"],
          f"{pc} {pch} {pf}")

    # paging at 350 contacts
    n = Node(sim, pub, contacts=350)
    replies0 = len(n.replies)
    lst, total = read(n, "contacts")
    pages = len(n.replies) - replies0
    d = n.dump()
    check(f"maint: 350 contacts page through completely ({pages} pages with names)",
          total == 350 and [c["prefix"] for c in lst] == [c[0][:12] for c in d["contacts"]] and
          [c["name"] for c in lst] == [c[3] for c in d["contacts"]], f"{total} {len(lst)}")
    r0 = len(n.replies)
    lst2, _ = read(n, "contacts", names=False)
    check(f"maint: without names: {len(n.replies) - r0} pages", len(lst2) == 350 and len(n.replies) - r0 <= pages / 2,
          f"{len(n.replies) - r0} vs {pages}")
    n.close()

    # ------------------------------------------------------------ every mutating op needs the owner's signature
    other = Ed25519PrivateKey.generate()
    newc = {"public_key": bytes(range(0x80, 0xA0)).hex(), "name": "newbie", "type": 2, "flags": 0,
            "out_path_len": 2, "out_path": "a1b2", "last_advert": 1234}
    ops = {
        "delete-contact": (L.MNT_OP_DELETE_CONTACTS, L.maint_args(L.MNT_OP_DELETE_CONTACTS, prefixes=[contact_key(3)[:8]])),
        "prune": (L.MNT_OP_PRUNE, L.maint_args(L.MNT_OP_PRUNE, types=L.parse_types("repeater,sensor"))),
        "favourite": (L.MNT_OP_FAVOURITE, L.maint_args(L.MNT_OP_FAVOURITE, prefix=contact_key(5)[:8])),
        "add-contact": (L.MNT_OP_ADD_CONTACT, L.maint_args(L.MNT_OP_ADD_CONTACT, contact=newc)),
        "format-extrafs": (L.MNT_OP_FORMAT_EXTRAFS, b""),
        "delete-file": (L.MNT_OP_DELETE_FILE, L.maint_args(L.MNT_OP_DELETE_FILE, path="/adv_blobs", fs=1)),
        "reboot": (L.MNT_OP_REBOOT, b""),
        "add-channel": (L.MNT_OP_SET_CHANNEL, L.maint_args(L.MNT_OP_SET_CHANNEL, index=3, name="#newtag")),
        "delete-channel": (L.MNT_OP_DELETE_CHANNEL, L.maint_args(L.MNT_OP_DELETE_CHANNEL, index=2)),
    }
    for name, (op, args) in ops.items():
        n = Node(sim, pub)
        before = n.dump()
        good = cmd(op, args)
        gctr = ctr[0]
        forged = good[:-64] + os.urandom(64)
        tampered = bytearray(good)
        tampered[len(good) - 65] ^= 1   # last byte of the body (the args, or the op)
        cases = [
            ("unsigned (random signature)", forged, "bad signature"),
            ("signed by another key", cmd(op, args, k=other), "bad signature"),
            ("altered after signing", bytes(tampered), "bad signature"),
            ("a settings-bundle signature", cmd(op, args, domain=L.SET_DOMAIN), "bad signature"),
            ("a firmware-manifest signature", cmd(op, args, domain=b"MCOTA1"), "bad signature"),
            ("for another node", cmd(op, args, target=(1, bytes(8))), "another node"),
            ("for another board", cmd(op, args, target=(2, b"other_board")), "another node"),
        ]
        bad = []
        for what, blob, want in cases:
            s, *_ = run(n, blob)
            if L.mnt_status(s).find(want) < 0:
                bad.append(f"{what}: {L.mnt_status(s)}")
        n.tick(10)
        unchanged = same(before, n.dump())
        check(f"maint: {name}: unsigned/foreign/altered/other-domain/other-target all refused, nothing changes",
              not bad and unchanged, f"{bad}; unchanged={unchanged}")
        s, c, rop, res = run(n, good)
        check(f"maint: {name}: the owner's command runs", s == L.OK and c == gctr and rop == op,
              f"{L.mnt_status(s)} {c} {rop}")
        n.tick(10)
        after = n.dump()
        s2, *_ = run(n, good)
        older = cmd(op, args, counter=gctr - 1)
        s3, *_ = run(n, older)
        n.tick(10)
        check(f"maint: {name}: replayed and older commands refused, change nothing",
              "replay" in L.mnt_status(s2) and "replay" in L.mnt_status(s3) and same(after, n.dump()),
              f"{L.mnt_status(s2)}; {L.mnt_status(s3)}")
        n.close()

    # a board-wide command
    n = Node(sim, pub)
    s, *_ = run(n, cmd(L.MNT_OP_FAVOURITE, L.maint_args(L.MNT_OP_FAVOURITE, prefix=contact_key(5)[:8]), target=(2, BOARD.encode())))
    check("maint: a command for this node's board runs", s == L.OK and n.dump()["contacts"][5][2] == 1, L.mnt_status(s))
    # the counter survives a power cycle: an old command stays refused
    n.power_cycle()
    s, *_ = run(n, cmd(L.MNT_OP_FAVOURITE, L.maint_args(L.MNT_OP_FAVOURITE, prefix=contact_key(6)[:8]), counter=ctr[0] - 1))
    check("maint: the counter survives a reboot (older command refused after it)", "replay" in L.mnt_status(s) and
          n.dump()["counter"] == ctr[0], L.mnt_status(s))
    # the counter cannot be saved: refused, nothing done
    before = n.dump()
    n.control(6)
    s, *_ = run(n, cmd(L.MNT_OP_DELETE_CONTACTS, L.maint_args(L.MNT_OP_DELETE_CONTACTS, prefixes=[contact_key(1)[:8]])))
    check("maint: counter not saved -> refused, nothing deleted", s == 23 and same(before, n.dump()), L.mnt_status(s))
    n.close()

    # ------------------------------------------------------------ delete contacts
    n = Node(sim, pub)
    fav, me_key = contact_key(20), contact_key(30)
    n.requester(me_key)
    s, c, op, res = run(n, cmd(L.MNT_OP_DELETE_CONTACTS, L.maint_args(
        L.MNT_OP_DELETE_CONTACTS, prefixes=[contact_key(1)[:8], contact_key(2)[:8], fav[:8], bytes(8), me_key[:8]])))
    r = L.mnt_result(op, s, res)
    keys = [c[0] for c in n.dump()["contacts"]]
    check("maint: delete contacts: two go; a favourite stays without --force; unknown counted",
          r.get("deleted") == 2 and r.get("not_found") == 1 and r.get("skipped") == 2 and fav.hex() in keys and
          contact_key(1).hex() not in keys and len(keys) == 38, str(r))
    s, c, op, res = run(n, cmd(L.MNT_OP_DELETE_CONTACTS, L.maint_args(
        L.MNT_OP_DELETE_CONTACTS, prefixes=[fav[:8], me_key[:8]], force=True)))
    r = L.mnt_result(op, s, res)
    keys = [c[0] for c in n.dump()["contacts"]]
    check("maint: --force deletes a favourite, never the requester's own contact",
          r.get("deleted") == 1 and r.get("skipped") == 1 and fav.hex() not in keys and me_key.hex() in keys, str(r))
    s, *_ = run(n, cmd(L.MNT_OP_FAVOURITE, L.maint_args(L.MNT_OP_FAVOURITE, prefix=me_key[:8], on=False)))
    check("maint: un-favouriting the requester is refused (it would cut off access)", s == L.PROTECTED, L.mnt_status(s))
    twin = dict(newc, public_key=(contact_key(4)[:6] + bytes(26)).hex(), name="twin")
    run(n, cmd(L.MNT_OP_ADD_CONTACT, L.maint_args(L.MNT_OP_ADD_CONTACT, contact=twin)))
    s, c, op, res = run(n, cmd(L.MNT_OP_DELETE_CONTACTS, L.maint_args(L.MNT_OP_DELETE_CONTACTS, prefixes=[contact_key(4)[:6]])))
    r = L.mnt_result(op, s, res)
    s2, *_ = run(n, cmd(L.MNT_OP_FAVOURITE, L.maint_args(L.MNT_OP_FAVOURITE, prefix=contact_key(4)[:6])))
    check("maint: a prefix that matches two contacts deletes neither (ambiguous)", r.get("ambiguous") == 1 and
          r.get("deleted") == 0 and s2 == L.AMBIGUOUS, f"{r} {L.mnt_status(s2)}")
    n.close()

    # ------------------------------------------------------------ prune
    n = Node(sim, pub, contacts=350)
    me_key = contact_key(10)   # a favourite chat contact
    n.requester(me_key)
    d0 = n.dump()
    s, c, op, res = run(n, cmd(L.MNT_OP_PRUNE, L.maint_args(L.MNT_OP_PRUNE, types=L.parse_types("repeater,sensor"))))
    r = L.mnt_result(op, s, res)
    d = n.dump()
    left = [(k, t, f) for k, t, f, _ in d["contacts"]]
    want = [(k, t, f) for k, t, f, _ in d0["contacts"] if t in (1, 3) or f & 1]
    gone = sum(1 for _, t, f, _ in d0["contacts"] if t in (2, 4) and not f & 1)
    check(f"maint: prune repeaters + sensors: {gone} strangers go; favourites, people and rooms stay",
          s == L.OK and left == want and r["deleted"] == gone and r["contacts_left"] == len(want) and
          r["kept_favourites"] == sum(1 for _, t, f, _ in d0["contacts"] if t in (2, 4) and f & 1), str(r))
    check(f"maint: prune of 350 does not block the loop (at most {d['max_removes_per_poll']} removals per pass, "
          f"{n.working} WORKING replies)", d["max_removes_per_poll"] <= 8 and n.working >= 1, str(d["max_removes_per_poll"]))
    check("maint: prune leaves the save to the app (one lazy write)", d["changed"] >= 1, str(d["changed"]))
    n.close()

    # ------------------------------------------------------------ favourite, add contact
    n = Node(sim, pub)
    s, *_ = run(n, cmd(L.MNT_OP_FAVOURITE, L.maint_args(L.MNT_OP_FAVOURITE, prefix=contact_key(7)[:8])))
    on = n.dump()["contacts"][7][2]
    s2, *_ = run(n, cmd(L.MNT_OP_FAVOURITE, L.maint_args(L.MNT_OP_FAVOURITE, prefix=contact_key(7)[:8], on=False)))
    off = n.dump()["contacts"][7][2]
    s3, *_ = run(n, cmd(L.MNT_OP_FAVOURITE, L.maint_args(L.MNT_OP_FAVOURITE, prefix=bytes(8))))
    check("maint: favourite on / off; an unknown contact is not found", s == L.OK and on == 1 and s2 == L.OK and off == 0 and
          s3 == L.NOT_FOUND, f"{s} {on} {s2} {off} {s3}")
    s, c, op, res = run(n, cmd(L.MNT_OP_ADD_CONTACT, L.maint_args(L.MNT_OP_ADD_CONTACT, contact=newc)))
    lst, total = read(n, "contacts")
    added = [x for x in lst if x["prefix"] == newc["public_key"][:12]]
    check("maint: add a contact from its public record", s == L.OK and res == b"\0" and total == 41 and added and
          added[0]["name"] == "newbie" and added[0]["type"] == 2 and added[0]["last_advert"] == 1234, f"{s} {res} {added}")
    s, c, op, res = run(n, cmd(L.MNT_OP_ADD_CONTACT, L.maint_args(L.MNT_OP_ADD_CONTACT, contact=dict(newc, name="renamed"))))
    lst, total = read(n, "contacts")
    check("maint: adding a known key updates it", s == L.OK and res == b"\1" and total == 41 and
          any(x["name"] == "renamed" for x in lst), f"{s} {res}")
    s, *_ = run(n, cmd(L.MNT_OP_ADD_CONTACT, L.maint_args(L.MNT_OP_ADD_CONTACT, contact=dict(newc, public_key=SELF.hex()))))
    check("maint: the node's own key is never added", s == L.PROTECTED, L.mnt_status(s))
    for bad, why in ((dict(newc, out_path_len=0xC1), "reserved path hash size"), (dict(newc, type=9), "type 9")):
        a = L.maint_args(L.MNT_OP_ADD_CONTACT, contact=dict(newc, type=2)) if why != "type 9" else None
        if why == "type 9":
            a = bytes.fromhex(newc["public_key"]) + bytes([9, 0, 0xFF]) + struct.pack("<I", 0) + b"x"
        else:
            a = bytes.fromhex(newc["public_key"]) + bytes([2, 0, 0xC1]) + struct.pack("<I", 0) + b"\0" + b"x"
        s, *_ = run(n, cmd(L.MNT_OP_ADD_CONTACT, a))
        check(f"maint: add contact with a malformed record ({why}) refused", s == 20, L.mnt_status(s))
    n.close()
    n = Node(sim, pub, extra=("--max", "40"))
    s, *_ = run(n, cmd(L.MNT_OP_ADD_CONTACT, L.maint_args(L.MNT_OP_ADD_CONTACT, contact=newc)))
    check("maint: add contact to a full table -> FULL", s == L.FULL and len(n.dump()["contacts"]) == 40, L.mnt_status(s))
    n.close()

    # ------------------------------------------------------------ format ExtraFS
    n = Node(sim, pub, contacts=350)
    d0 = n.dump()
    fmt = cmd(L.MNT_OP_FORMAT_EXTRAFS)
    fctr = ctr[0]
    n.busy(1)   # an unconfirmed firmware image: its rollback copy lives on the ExtraFS
    s, *_ = run(n, fmt)
    check("maint: format refused while a firmware image is unconfirmed (BUSY), counter not spent",
          s == L.BUSY and n.dump()["counter"] == 0 and same(d0, n.dump()), L.mnt_status(s))
    for b in (2, 4):
        n.busy(b)
        s, *_ = run(n, cmd(L.MNT_OP_FORMAT_EXTRAFS))
        check(f"maint: format refused while {'a transfer' if b == 2 else 'a settings bundle'} is in flight", s == L.BUSY,
              L.mnt_status(s))
    n.busy(0)
    s, c, op, res = run(n, fmt)   # the same signed command, now that nothing is in flight
    r = L.mnt_result(op, s, res)
    d = n.dump()
    files = {(f, p): size for f, p, size in d["files"]}
    files0 = {(f, p): size for f, p, size in d0["files"]}
    check("maint: format ExtraFS: same contacts and channels stored as before",
          s == L.OK and r["contacts_before"] == 350 and r["contacts_stored"] == 350 and r["channels_before"] == 3 and
          r["channels_stored"] == 3, str(r))
    check("maint: format ExtraFS: identity, prefs and the primary FS untouched",
          d["identity_ok"] == 1 and all(files.get(k) == v for k, v in files0.items() if k[0] == 0), str(d["files"]))
    check("maint: format ExtraFS: everything else on it is gone",
          (1, "/old/junk.bin") not in files and (1, "/ota-old.bin") not in files and (1, "/adv_blobs") not in files,
          str(d["files"]))
    n.power_cycle()
    d2 = n.dump()
    check("maint: format ExtraFS: after a power cycle the contacts and channels load back the same",
          d2["contacts"] == d0["contacts"] and d2["channels"] == d0["channels"] and d2["counter"] == fctr,
          f"{len(d2['contacts'])} {d2['channels']} {d2['counter']} {fctr}")
    n.close()
    n = Node(sim, pub, extra=("--no-fs2",))
    s, *_ = run(n, cmd(L.MNT_OP_FORMAT_EXTRAFS))
    check("maint: format on a node without an ExtraFS: not supported", s == 22 and n.dump()["identity_ok"] == 1,
          L.mnt_status(s))
    n.close()

    # ------------------------------------------------------------ delete file
    n = Node(sim, pub)
    n.put_file(1, "/old/deleteme")
    prot = [(0, "/_main.id"), (0, "/prefs.json"), (0, "/ota_maint"), (0, "/ota_settings"), (0, "/ota_set_overlay"),
            (0, "/overlay"), (0, "/identity/_main.id"), (0, "/x/../prefs.json"), (0, "/./prefs.json"),
            (0, "//prefs.json"), (1, "/contacts3"), (1, "/channels2"), (1, "/ota-old.bin"), (1, "/old/"), (0, "/s_contacts")]
    run(n, cmd(L.MNT_OP_REBOOT))   # (spends a counter, so /ota_maint exists)
    n.tick(10)
    before = n.dump()
    bad = []
    for fs, p in prot:
        s, *_ = run(n, cmd(L.MNT_OP_DELETE_FILE, bytes([fs]) + p.encode()))
        if s != L.PROTECTED:
            bad.append(f"{p}: {L.mnt_status(s)}")
    check("maint: protected files are never deleted (identity, prefs, counters, OTA rollback, tables, ACL)",
          not bad and before["files"] == n.dump()["files"], str(bad))
    s, *_ = run(n, cmd(L.MNT_OP_DELETE_FILE, L.maint_args(L.MNT_OP_DELETE_FILE, path="/old", fs=1)))
    s2, *_ = run(n, cmd(L.MNT_OP_DELETE_FILE, L.maint_args(L.MNT_OP_DELETE_FILE, path="/nothing", fs=1)))
    s3, *_ = run(n, cmd(L.MNT_OP_DELETE_FILE, L.maint_args(L.MNT_OP_DELETE_FILE, path="/old/deleteme", fs=1)))
    files = [p for f, p, _ in n.dump()["files"] if f == 1]
    check("maint: delete a file; a directory is refused, a missing file not found",
          s == L.PROTECTED and s2 == L.NOT_FOUND and s3 == L.OK and "/old/deleteme" not in files and "/old/junk.bin" in files,
          f"{s} {s2} {s3}")
    n.close()

    # ------------------------------------------------------------ reboot
    n = Node(sim, pub)
    n.busy(4)
    s, *_ = run(n, cmd(L.MNT_OP_REBOOT))
    n.busy(0)
    s2, *_ = run(n, cmd(L.MNT_OP_REBOOT))
    n.tick(L.MNT_REBOOT_SECS - 2)
    early = n.dump()["reboots"]
    n.tick(4)
    n.tick(30)
    check("maint: reboot refused while a settings bundle is on probation; else once, ~6 s after the reply",
          s == L.BUSY and s2 == L.OK and early == 0 and n.dump()["reboots"] == 1, f"{s} {s2} {early} {n.dump()['reboots']}")
    n.close()

    # ------------------------------------------------------------ channels: add (hashtag / own secret), delete
    n = Node(sim, pub)
    tag_secret = hashlib.sha256(b"#fieldops").digest()[:16]
    own = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    s, c, op, res = run(n, cmd(L.MNT_OP_SET_CHANNEL, L.maint_args(L.MNT_OP_SET_CHANNEL, index=3, name="#fieldops")))
    r = L.mnt_result(op, s, res)
    d = n.dump()
    check("maint: add a hashtag channel to an empty slot: secret = SHA-256(name)[0:16], as the apps derive it",
          s == L.OK and r == {"op": "add-channel", "status": "ok", "replaced": False, "hashtag": True} and
          d["channels"][3] == "#fieldops" and d["channel_secrets"][3] == (tag_secret + bytes(16)).hex(), f"{r} {d['channels']}")
    s, c, op, res = run(n, cmd(L.MNT_OP_SET_CHANNEL, L.maint_args(L.MNT_OP_SET_CHANNEL, index=4, name="crew", secret=own)))
    r = L.mnt_result(op, s, res)
    d = n.dump()
    check("maint: add a channel with its own 128-bit secret",
          s == L.OK and not r["replaced"] and not r["hashtag"] and d["channels"][4] == "crew" and
          d["channel_secrets"][4] == (own + bytes(16)).hex(), f"{r} {d['channels']}")
    s, c, op, res = run(n, cmd(L.MNT_OP_SET_CHANNEL, L.maint_args(L.MNT_OP_SET_CHANNEL, index=0, name="#public2")))
    r = L.mnt_result(op, s, res)
    check("maint: setting a configured slot replaces it (as CMD_SET_CHANNEL)", s == L.OK and r["replaced"] and
          n.dump()["channels"][0] == "#public2", str(r))
    chs = read(n, "channels")
    check("maint: the new channels list back; hashtag names cut (the name is the key)",
          [(c["index"], c["name"], c["name_keyed"]) for c in chs] ==
          [(0, "#pu", True), (1, "#se", True), (2, "family", False), (3, "#fi", True), (4, "crew", False)], str(chs))
    s, *_ = run(n, cmd(L.MNT_OP_DELETE_CHANNEL, L.maint_args(L.MNT_OP_DELETE_CHANNEL, index=2)))
    d = n.dump()
    s2, *_ = run(n, cmd(L.MNT_OP_DELETE_CHANNEL, L.maint_args(L.MNT_OP_DELETE_CHANNEL, index=2)))
    check("maint: delete a channel (empty name, zero secret, as the app); an empty slot is not found",
          s == L.OK and d["channels"][2] == "" and d["channel_secrets"][2] == "00" * 32 and s2 == L.NOT_FOUND,
          f"{L.mnt_status(s)} {L.mnt_status(s2)} {d['channels']}")
    n.power_cycle()
    d = n.dump()
    check("maint: channel changes are saved (same table after a power cycle)",
          d["channels"] == ["#public2", "#secretgroup", "", "#fieldops", "crew"] and
          d["channel_secrets"][4] == (own + bytes(16)).hex(), str(d["channels"]))
    c0 = n.dump()["counter"]
    s, *_ = run(n, cmd(L.MNT_OP_SET_CHANNEL, bytes([5, 3]) + b"#xy"))
    s2, *_ = run(n, cmd(L.MNT_OP_DELETE_CHANNEL, bytes([200])))
    check("maint: channel index past the node's slots refused, counter not spent",
          s == L.BAD_ARG and s2 == L.BAD_ARG and n.dump()["counter"] == c0, f"{L.mnt_status(s)} {L.mnt_status(s2)}")
    malformed = [("no secret, not a hashtag", bytes([3, 4]) + b"crew"), ("a lone '#'", bytes([3, 1]) + b"#"),
                 ("all-zero secret", bytes([3, 4]) + b"crew" + bytes(16)), ("empty name", bytes([3, 0]) + own),
                 ("control character", bytes([3, 4]) + b"cr\nw" + own), ("short secret", bytes([3, 4]) + b"crew" + own[:8]),
                 ("32-character name", bytes([3, 32]) + b"#" + b"x" * 31), ("delete with junk", bytes([3, 1]))]
    bad = []
    for what, a in malformed:
        op = L.MNT_OP_DELETE_CHANNEL if what.startswith("delete") else L.MNT_OP_SET_CHANNEL
        s, *_ = run(n, cmd(op, a))
        if s != 20:
            bad.append(f"{what}: {L.mnt_status(s)}")
    check("maint: malformed channel commands refused (does not parse), counter not spent",
          not bad and n.dump()["counter"] == c0, str(bad))
    leaks = [x for x in (own, tag_secret, b"fieldops", b"public2") for rr in n.replies if x in rr]
    check("maint: no reply carries a channel secret or a hashtag channel's full name", not leaks and not n.leaks(),
          f"{leaks} {n.leaks()}")
    for what, kw in (("no secret, not a hashtag", dict(index=3, name="crew")),
                     ("zero secret", dict(index=3, name="crew", secret=bytes(16))),
                     ("short secret", dict(index=3, name="crew", secret=bytes(8))),
                     ("long name", dict(index=3, name="#" + "x" * 31))):
        try:
            L.maint_args(L.MNT_OP_SET_CHANNEL, **kw)
            sender_ok = False
        except L.OtaError:
            sender_ok = True
        check(f"maint: sender refuses add-channel with {what}", sender_ok)
    n.close()

    # ------------------------------------------------------------ repeater
    n = Node(sim, pub, role="repeater")
    s, *_ = run(n, cmd(L.MNT_OP_SET_CHANNEL, L.maint_args(L.MNT_OP_SET_CHANNEL, index=0, name="#x1")))
    s2, *_ = run(n, cmd(L.MNT_OP_DELETE_CHANNEL, L.maint_args(L.MNT_OP_DELETE_CHANNEL, index=0)))
    check("maint: repeater: channel ops not supported, counter not spent", s == 22 and s2 == 22 and
          n.dump()["counter"] == 0, f"{L.mnt_status(s)} {L.mnt_status(s2)}")
    n.close()
    n = Node(sim, pub, role="repeater")
    st = read(n, "status")
    fl = read(n, "files", 0)
    s, *_ = run(n, cmd(L.MNT_OP_PRUNE, L.maint_args(L.MNT_OP_PRUNE, types=4)))
    c0 = n.dump()["counter"]
    s2, *_ = run(n, cmd(L.MNT_OP_DELETE_FILE, L.maint_args(L.MNT_OP_DELETE_FILE, path="/packet_log")))
    s3, *_ = run(n, cmd(L.MNT_OP_DELETE_FILE, L.maint_args(L.MNT_OP_DELETE_FILE, path="/s_contacts")))
    try:
        read(n, "contacts")
        lists = True
    except L.OtaError:
        lists = False
    check("maint: repeater: status + files; contact ops not supported (counter unspent); file delete with the ACL protected",
          st["role"] == "repeater" and st["contacts"] is None and not st["has_extrafs"] and
          any(e["name"] == "packet_log" for e in fl) and s == 22 and c0 == 0 and s2 == L.OK and s3 == L.PROTECTED and
          not lists and not n.leaks(), f"{st} {s} {c0} {s2} {s3}")
    n.close()

    # ------------------------------------------------------------ over a lossy link
    n = Node(sim, pub, contacts=350, drop=20, seed=4)
    d0 = n.dump()
    s, c, op, res = run(n, cmd(L.MNT_OP_PRUNE, L.maint_args(L.MNT_OP_PRUNE, types=L.parse_types("repeater"))))
    lst, total = read(n, "contacts", names=False)
    check("maint: prune + full listing over 20% packet loss", s == L.OK and total == len(n.dump()["contacts"]) == len(lst) and
          total == sum(1 for _, t, f, _ in d0["contacts"] if t != 2 or f & 1), f"{L.mnt_status(s)} {total}")
    n.close()

    # ------------------------------------------------------------ the CLI's own logic (maint_do) against the sim
    n = Node(sim, pub, contacts=60)
    keyfile = os.path.join(tmp, "maint.key")
    from cryptography.hazmat.primitives import serialization
    open(keyfile, "w").write(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                               serialization.NoEncryption()).hex())

    def cli(cmd_, **kw):
        a = SimpleNamespace(maint_cmd=cmd_, key=keyfile, bundle_target=None, json=True, **kw)
        return asyncio.run(L.maint_do(a, sender(n), "sim", SELF))

    d0 = n.dump()
    dry, _, err = cli("prune", types="repeater,sensor", dry_run=True)
    check("maint CLI: prune --dry-run lists the non-favourite repeaters + sensors, signs and changes nothing",
          err is None and len(dry["would_delete"]) == sum(1 for _, t, f, _ in d0["contacts"] if t in (2, 4) and not f & 1)
          and same(d0, n.dump()), str(err))
    out, _, err = cli("prune", types="repeater,sensor", dry_run=False)
    check("maint CLI: prune deletes what the dry run listed", err is None and out["deleted"] == len(dry["would_delete"]),
          f"{err} {out}")
    out, _, err = cli("delete-contact", contact=["node-002"], force=False)
    check("maint CLI: delete-contact by name", err is None and out["deleted"] == 1, f"{err} {out}")
    out, _, err = cli("favourite", contact=contact_key(6)[:6].hex(), off=False)
    check("maint CLI: favourite by key prefix", err is None and
          [c[2] for c in n.dump()["contacts"] if c[0] == contact_key(6).hex()] == [1], f"{err} {out}")
    out, _, err = cli("format-extrafs")
    check("maint CLI: format-extrafs reports the node after it", err is None and out["after"]["contacts"] == out["contacts_stored"],
          f"{err} {out}")
    jf = os.path.join(tmp, "c.json")
    json.dump({"public_key": "ab" * 32, "adv_name": "fromlib", "type": 1, "flags": 0, "out_path_len": -1, "out_path": "",
               "last_advert": 5}, open(jf, "w"))
    out, _, err = cli("add-contact", from_json=jf)
    check("maint CLI: add-contact from a meshcore-lib style JSON", err is None and out["result"] == "added", f"{err} {out}")
    out, _, err = cli("delete-file", path="ExtraFS/adv_blobs", fs=None)
    check("maint CLI: delete-file ExtraFS/<name> on a freshly formatted ExtraFS: not found", err and "not found" in err,
          str(err))
    import contextlib, io
    secret_hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    out, pr, err = cli("add-channel", index=3, name="ops", secret=secret_hex)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        pr()
    shown_all = buf.getvalue() + json.dumps(out)
    check("maint CLI: add-channel with a secret: added; the secret is printed (and in --json) only cut",
          err is None and out["status"] == "ok" and out["channel"]["secret"] == "a1b2…" and
          secret_hex not in shown_all and secret_hex[:8] not in shown_all and
          n.dump()["channel_secrets"][3] == secret_hex + "00" * 16, f"{err} {shown_all}")
    out, pr, err = cli("add-channel", index=4, name="#nightwatch", secret=None)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        pr()
    shown_all = buf.getvalue() + json.dumps(out)
    check("maint CLI: add-channel #hashtag: its name (the key) printed only cut",
          err is None and out["hashtag"] and "nightwatch" not in shown_all and
          n.dump()["channels"][4] == "#nightwatch", f"{err} {shown_all}")
    out, _, err = cli("delete-channel", index=3)
    check("maint CLI: delete-channel", err is None and out["status"] == "ok" and n.dump()["channels"][3] == "", f"{err} {out}")
    st, _, err = cli("status")
    check("maint CLI: each command used a fresh counter (time-based, above the node's)", st["maint_counter"] >= ctr[0],
          str(st["maint_counter"]))
    check("maint CLI: nothing secret in any reply", not n.leaks(), str(n.leaks()))
    n.close()
    check("maint: parse_types", L.parse_types("repeater,sensor") == 0b10100 and L.parse_types("repeaters, 1") == 0b110)
