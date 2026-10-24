# Find Hub (native Fast Pair + FHN) on the nRF52840 companion

**Status 2026-10-24: implemented (phases 1-5), proven on Rover against a
seeker emulator; not yet tried with a real Android phone.** Results, measured
costs and the phone test plan are in sections 6-8 at the end; sections 1-5
are the plan as approved.

Goal: an L1 BLE companion that pairs with Fast Pair from an Android phone, shows
up in the Find Hub app, rings from it, and gets crowd location reports, with no
off-device provisioning or periodic re-registration.

Branch `companion-v1.18.0-findhub` (worktree `~/git/MeshCore-findhub`), on top
of patched v1.18.0 (`3528165a`). Test board: Rover (Wio Tracker L1, USB serial
`A9A322B36B9C145A`). Full-flash backup taken 2026-10-24:
`~/scratch/l1-backups/rover-A9A322B36B9C145A-before-findhub-20261024.UF2`
(sha256 `02a5a745…`). Restore = copy that UF2 onto the bootloader drive.

## 1. What exists today

### BLE stack (Adafruit nRF52 core, S140 7.3.0, Bluefruit)

**Companion (`SerialBLEInterface`)**
- `Bluefruit.begin()` with 1 peripheral link (2 with the Find Hub flag),
  `BANDWIDTH_MAX`, tx +4 dBm.
- Name `MeshCore-<name>`. PPCP 15-30 ms, latency 4, 2 s timeout, also pushed
  with `conn_param_update` once secured.
- Services:
  - BLE UART (NUS): the companion protocol, `SECMODE_ENC_WITH_MITM`.
  - BLE DFU: same security.
- Security:
  - MITM on, a static PIN (`setPIN`), IO caps display-only, so pairing is
    passkey entry with a fixed passkey.
  - Bonds are kept by Bluefruit (`/adafruit/bond_prph` on InternalFS).
  - The companion role starts only in `onSecured`; an unsecured link gets
    nothing.
- Advertising:
  - One set: flags, tx power and the NUS UUID; name in the scan response.
  - 20-152.5 ms, fast timeout 30 s, restart on disconnect, 10 s watchdog.
  - Stops while a client is connected (one link).
- Address: the factory static random address. It never changes, and the app
  reconnects to it.

**Repeater / room server (`NRF52Board`)**
- No BLE at runtime. Bluefruit is started only by `startOTAUpdate()`
  (DFU-only advertising, 1 link).
- Find Hub on a repeater would mean running the SoftDevice permanently (RAM
  and power), so it is **out of scope**. This plan covers the companion only.

### Find Hub work already on this branch (3 commits)

- `helpers/findhub/FindHubCrypto`:
  - EID: AES-ECB-256 seed, r mod n, secp160r1 via micro-ecc.
  - Hashed flags, derived keys, one-time auth (HMAC-SHA256),
    AES-128-ECB (rweather Crypto).
- `helpers/findhub/FindHubBeacon` (portable; platform through an interface):
  - The Beacon Actions protocol: beacon params, provisioning state, set/clear
    EIK, ring, ring state, UTP on/off.
  - Frame type 0x40/0x41, rotation with a random 1-204 s delay.
  - The ring state machine.
  - Read EIK (0x04) always answers "no user consent".
- `helpers/nrf52/FindHubService`:
  - GATT service 0xFE2C with only the Beacon Actions characteristic.
    Requests are queued from the BLE task and handled on the main loop.
  - State on InternalFS.
  - Daily GPS time sync.
- `SerialBLEInterface` (`FINDHUB_BEACON`):
  - 2 peripheral links.
  - The companion advert (1.2 s) and the FHN frame (0.8 s) take turns; with a
    client connected, only the FHN frame goes out.
- Provisioning happens today over the companion link (`CMD_FINDHUB 0xA0`,
  from homelab's `meshcore-findhub` CLI):
  - the EIK is minted off-device;
  - the beacon clock is `unix_now - pair_date`, so it needs a valid wall
    clock (GPS);
  - Google never learns about the tag. That is why it is not in Find Hub.
- Tests: `pio test -e native_findhub` passes 12/12 today (vectors from a
  Python reference and the ring flow), run with
  `nix shell nixpkgs#platformio nixpkgs#gcc`.

### Gaps against the request

| Gap | Phase |
|---|---|
| No Fast Pair Provider: Model ID, Key-based Pairing, Passkey, Account Key characteristics, account key store | 1 |
| No discoverable or not-discoverable Fast Pair advertising | 2 |
| Read EIK with user consent (0x04) not implemented | 3 |
| Beacon clock tied to wall time / pair_date instead of the device's own persisted counter | 3-4 |
| No address rotation: the FHN frame goes out on the companion's static address | 4 |
| Scheduler knows only 2 frame kinds and keeps FHN connectable | 5 |
| Flag is `FINDHUB_BEACON`; the request asks for `WITH_FINDHUB` | 1 |

### Flash / RAM (Wio Tracker L1, measured 2026-10-24)

| Env | Flash used / app region | RAM |
|---|---|---|
| `WioTrackerL1_companion_radio_ble` (baseline) | 405,044 / 708,608 (57.2%) | 148,576 / 235,520 |
| `..._ble_findhub` (today) | 427,364 (+22,320) | 149,560 (+984) |
| `WioTrackerL1_repeater` | 376,852 / 811,008 | 35,428 |

Headroom with today's Find Hub code: **281 KB flash, 86 KB RAM**. The
companion's app region is smaller than the repeater's because of the
InternalFS reservation.

## 2. Decisions (defaults; change any before I start)

- **D1, crypto backend: CC310 on the device, micro-ecc + rweather in the
  native tests.**
  - The core already links `Adafruit_nRFCrypto` / `libnrf_cc310_0.9.13`
    (`USE_CC310_HW_CRYPTO`). Its headers expose ECDH on
    `CRYS_ECPKI_DomainID_secp256r1` and `..._secp160r1`, plus AES (`ssi_aes`)
    and SHA/HMAC.
  - The EID's r·G is computed as ECDH(r, G): the x coordinate is the EID.
  - Why: a software P-256 ECDH on a 64 MHz M4 blocks the main loop for about
    100-200 ms, which is LoRa RX/TX time. CC310 is hardware and constant time.
  - Native tests keep micro-ecc as the reference.
  - A debug build runs a power-on self-test of the CC310 path against the
    same vectors. The header's comments swap r1 and k1, so the domain ID must
    be proven on the device, not assumed.
  - Fallback if CC310 secp160r1 misbehaves: micro-ecc (already in the image).
    I'll report the flash cost of each path.
- **D2, no BLE bonding for Fast Pair** (the spec allows it for locator tags
  that don't bond, and NCS's `locator_tag` builds with
  `CONFIG_BT_FAST_PAIR_REQ_PAIRING=n`).
  - Key-based Pairing → Account Key write → Beacon Actions provisioning, all
    on an unencrypted link authenticated by Fast Pair's own crypto.
  - This avoids a conflict with the companion's security, which is global in
    Bluefruit: the companion needs a static passkey with display-only IO, and
    Fast Pair BLE pairing needs numeric comparison (DisplayYesNo, LESC).
  - The Passkey characteristic is still implemented and tested, per the
    request. If Find Hub insists on bonding on the phone, phase 1 adds a
    per-connection `SEC_PARAMS_REQUEST` override; that may need a patch to
    the forked Bluefruit core.
- **D3, Fast Pair provisioning replaces the companion-link provisioning.**
  - `CMD_FINDHUB` keeps status/ring/clear and loses `provision`, so only the
    owner's phone can set the EIK.
  - homelab's `meshcore-findhub provision` is retired once this works.
- **D4, beacon clock = the device's own counter** (seconds since
  provisioning), persisted every 1 h (the spec asks for at least daily) and at
  every write.
  - A reboot resumes from the last saved value.
  - When the RTC holds a GPS-set time, the counter stored with a Unix anchor
    also covers time spent powered off.
  - GPS becomes an improvement, no longer a requirement.
- **D5, pairing mode trigger:** first boot with no account key, plus a user
  button **triple-click**, opens 10 min of discoverable advertising.
  - The same press opens the 5-minute "user consent" window for Read EIK.
  - Long press stays power-off.
- **D6, debug model:** Nordic's `locator_tag` debug Model ID and anti-spoofing
  key, copied from NCS's docs/sample at implementation time.
  - Phones show them only with "Include debug results".
  - Both are build flags (`FINDHUB_MODEL_ID`, `FINDHUB_ANTISPOOF_KEY_B64`),
    so a registered model swaps in without code changes.
  - Note: homelab's trackers plan records that enrolment with a borrowed model
    key was deliberately not built. This request overrides that, for debug
    use.
- **D7, flag:** `FINDHUB_BEACON` is renamed to `WITH_FINDHUB`, and the env
  stays `WioTrackerL1_companion_radio_ble_findhub`.
- **D8, base:** stay on patched v1.18.0. Rebasing onto `lora-ota-1.18`
  (Rover's current firmware, `b9f506ff`) is a separate step once this works.

## 3. Phases

Each phase ends with a build of the L1 env, the flash/RAM delta against the
baseline table above, the native tests green, and a commit.

**1. Fast Pair GATT service** (`helpers/findhub/FastPair.{h,cpp}` portable +
`FindHubService` glue)
- Characteristics on 0xFE2C: Model ID (FE2C1233), Key-based Pairing
  (FE2C1234), Passkey (FE2C1235), Account Key (FE2C1236), plus the existing
  Beacon Actions (FE2C1238).
- Key-based Pairing (KBP):
  - Decrypt a 16-byte request with an account key, or with the
    64-byte-pubkey form: ECDH P-256 with the anti-spoofing key → AES key =
    SHA-256(shared)[0:16].
  - Check type and provider address (or salt).
  - Respond with AES-128-ECB of {0x01, our address, salt}.
- Rules:
  - 10-attempt failure lockout (spec).
  - KBP state times out after 10 s.
  - The Account Key write is accepted only on a link with a valid KBP key.
  - Keys must start with 0x04.
- Account key store: 5 keys, LRU, `/findhub/akeys` on InternalFS. The first
  key is the owner account key, used by FHN recovery/ring auth.
- Per the spec, if no EIK arrives within 5 min of the first account key, the
  account keys are wiped.
- Tests (native, before any flashing): every Fast Pair spec appendix vector
  that applies (AES-ECB, ECDH, KBP request decrypt/response, passkey,
  account key filter, HMAC), plus a full seeker↔provider KBP walk.

**2. Fast Pair advertising**
- Discoverable: service data 0xFE2C + the 3-byte Model ID, plus tx power.
  Sent only in pairing mode (D5), and never while FHN-provisioned (spec).
- Not-discoverable: the account key filter (salted Bloom filter, battery
  bits).
  - Advertised once an account key exists, so owner phones recognise the tag.
  - It uses its own rotating random address, independent of the FHN address
    (the spec requires the FP address to keep rotating even in UTP mode).

**3. Beacon Actions, completed**
- Read EIK with user consent (0x04): owner key auth, EIK encrypted as the
  spec says, only inside the D5 consent window, otherwise ATT 0x82.
- Provisioning over GATT becomes the only path (D3), with the clock moved to
  D4.
- Auth is checked against the spec's one-time-key rules, and the nonce is
  single-use per read (already tested; extended to recovery keys).

**4. FHN advertising**
- EID and hashed flags are already done.
- New: the FHN frame gets its own random non-resolvable address, set with
  `sd_ble_gap_addr_set` while advertising is stopped (the scheduler stops it
  between slots anyway). It rotates together with the EID, including the
  1-204 s random delay.
- In UTP mode the FHN address stays fixed.
- The companion slot switches back to the static identity address, so the
  app's bond and reconnects stay unchanged.
- Risk: whether S140 7.3 accepts an address change while a link is up. This
  gets verified on Rover first. If it refuses, the FHN frame keeps its last
  rotated address until the link drops, and the plan reports it.
- FHN tx power is at least 0 dBm; the board uses +4.

**5. Coexistence scheduler**
- `AdvScheduler` with slots for companion, FP (discoverable or
  not-discoverable) and FHN.
- FHN goes out at least every 2 s. Proposed cycle 2 s: FHN 0.7 / companion
  0.9 / FP 0.4. Pairing mode gives FP and companion the rest.
- Each slot sets its own address, payload and connectability:
  - FHN frames are **non-connectable** (`ADV_NONCONN_IND`) whenever any link
    is up, and connectable otherwise, so the owner's phone can connect to
    ring.
  - FP not-discoverable frames are connectable.
- The scheduler runs from `loop()`, cost a few µs per switch. The LoRa ISR
  path is untouched, and crypto runs at most once per 1024 s (EID) or per
  phone request.

## 4. On-device test plan (Rover)

1. Flash with `pio run -e WioTrackerL1_companion_radio_ble_findhub -t upload`
   (UF2). Check over USB serial that the self-test passes and that the
   companion app still connects and messages (protocol unchanged).
2. Phone:
   - Settings → Google → Devices & sharing → Devices → "Include debug
     results" on.
   - Find Hub app installed, Bluetooth and location on.
3. Pairing: triple-click Rover → the half-sheet "Locator tag" (debug) appears
   → Connect → accept Find Hub. Then check:
   - the USB log shows KBP ok → account key → EIK set;
   - companion status shows provisioned and the counter.
4. Find Hub app: the device is listed. "Play sound" rings Rover, and
   stop/timeout work. Status shows the GATT op log.
5. Crowd report: leave the owner's phone at home and walk Rover past another
   Android phone (a different Google account, Bluetooth on, Find Hub network
   on default "high-traffic areas" or "all areas"). A location then appears
   in Find Hub. A busy public place helps; reports can take 15-60 min.
6. Reboot persistence: power-cycle Rover and check that the counter resumes
   and that the phone still sees the device (no re-pair).
7. Restore: copy the backup UF2 from the top of this file onto Rover's
   bootloader drive, then check Rover's version and favourites over LoRa.

## 5. Open risks

- Find Hub may refuse a debug model for crowd reports (only the owner's
  phone sees it). If so, a registered Model ID (Google Nearby console,
  owner-only) is the fix, and D6 makes that a build flag.
- Fast Pair on a link without bonding (D2) is what `locator_tag` does. If the
  Play Services build on the test phone demands bonding, phase 1 grows the
  per-connection security override.
- CC310 secp160r1 domain correctness (D1) is caught by the self-test before
  anything goes on air.

## 6. What was built (and where it differs from the plan)

Commits on `companion-v1.18.0-findhub`: `4d97ff8f` (portable core + tests),
`9508870b` (nRF52 glue, scheduler, UI), `5e0d947a` (fixes from the first
on-device run).

- `helpers/findhub/FastPair`: Key-based Pairing (initial pairing with the
  anti-spoofing key, later ones with an account key), Passkey, Account Key,
  5-key LRU list that keeps the owner key, 10-failure lockout for 5 min,
  replayed-request check, discoverable / not-discoverable payloads.
- `helpers/findhub/FindHubBeacon`: Beacon Actions against the account-key
  list; owner = the first key ever written; first Set EIK without a hash; Read
  EIK (0x04) with the recovery key, only inside the consent window; Clear EIK
  is a factory reset (spec, locator tags).
- `helpers/findhub/FindHub`: the locator-tag policy and the frame/address plan
  (section 3, phases 2 and 4).
- `nrf52/FindHubService`: GATT (0xFE2C: Model ID, KBP, Passkey, Account Key,
  Beacon Actions; DIS Firmware Revision gated as the spec asks), InternalFS
  (`/fh_ak`, `/fh_eik`, `/fh_clk`, `/fh_boot`), the beacon clock, the boot EC
  self-test.
- `nrf52/SerialBLEInterface`: the advertising scheduler (companion 900 ms on
  the identity address, Fast Pair 600 ms and FHN 500 ms on the tag address).
- Companion `CMD_FINDHUB`: status (new layout), 0x05 pair, 0x03 clear, 0x04
  ring; 0x02 provision removed (D3).
- UI: a "Find Hub" home page (owner, mid-implementation): Enter registers
  (pairing mode, 10 min) or cancels; when registered, Enter twice removes it
  (factory reset). This replaces D5's triple-click, which the L1 already uses
  for the buzzer. Removing on the device stops the beacon and wipes its keys;
  the entry in the owner's Find Hub app goes away only when removed there.
- Clock (D4): a counter from the first boot, saved hourly and at provisioning.
  GPS time sync is gone. After a reboot the clock resumes from the last save
  (measured on Rover: 131 s behind after a reboot 130 s after the last save),
  and the tag sends not-discoverable Fast Pair frames until the owner's phone
  reads the beacon parameters, which is how Android re-synchronises
  (throttled by the phone to once a day).
- Addresses: random static addresses (`sd_ble_gap_addr_set`), not NRPAs. The
  SoftDevice only takes private addresses through its privacy mode, which
  would move the companion's address too. An address that changes with every
  EID is just as unlinkable on air.
- Existing bonds are unaffected: Bluefruit never distributes an identity key
  (`keys_own.p_id_key = NULL`), so a phone keeps the address it bonded on: the
  companion advert's, which stays the factory identity address.

Known gaps:
- Passkey characteristic: implemented and tested in the portable layer, but
  the bonding flow cannot run on Bluefruit (it answers numeric comparison
  inside its own event handler, and the companion's IO capabilities are
  display-only). Only the no-bonding flow works, which is what locator tags
  (and the Nordic debug model, "Data-Only connection") use.
- DULT accessory non-owner service, precision finding, personalized name: not
  implemented. DULT is required for certification, not for the debug model.
- "Bluetooth off" in the UI turns the Find Hub beacon off too (one radio switch).
- While any phone is connected (the companion app included) FHN frames are
  non-connectable, as asked: the Find Hub app cannot ring the tag then.
  The companion command (`ring --companion`) still works.

## 7. Measured (Wio Tracker L1, nRF52840)

| Build | Flash | RAM |
|---|---|---|
| `WioTrackerL1_companion_radio_ble` | 405,044 | 148,576 |
| `..._findhub` (CryptoCell EC) | 428,380 (+23,336) | 154,344 (+5,768) |
| `..._findhub_swec` (micro-ecc EC) | 438,804 (+33,760) | 150,904 (+2,328) |

The CryptoCell build is 10-12 KB smaller (micro-ecc's P-256 and secp160r1
tables go) and keeps the CPU free: Key-based Pairing answers in 84 ms over the
air, including the ECDH. Its RAM cost is CC310's static work buffers. Headroom
left: about 280 KB flash, 81 KB RAM.

Tests: `pio test -e native_findhub`, 39 cases. They include every applicable
case of Google's "Cryptographic Test Cases" (SHA-256, AES-128, ECDH, the AES
key from ECDH, the account key filter with and without battery data, AES-CTR
+ HMAC additional data) and a full Seeker<->Provider walk on the spec's
Alice/Bob keys.

On Rover, using a seeker emulator on enceladus (bleak; the debug model's
anti-spoofing key; homelab `fhn.py` for EIDs):
- the boot self-test passes on the CryptoCell;
- the discoverable frame (Model ID `4a436b`, TX power) is on air, and Model ID
  and Firmware Revision read back;
- the KBP response is valid; the account key is accepted; beacon parameters
  come back encrypted with it; the owner flag is set; Set EIK is accepted;
- the FHN frame on air resolves to the EIK (frame type 0x40, hashed flags =
  battery normal);
- ring: started, then stopped (timeout), both notifications authenticated;
- Read EIK: ATT 0x82 without consent; the right EIK inside the consent window;
- after a reboot: still provisioned, the clock resumes, the not-discoverable
  frame carries the right account key filter, and a clock read ends it;
- the companion protocol still works (meshcore-cli `infos`, contacts,
  channels), and LoRa adverts keep arriving.

## 8. Test with an Android phone

Prerequisites (owner):
- The Google account on the phone must be on Google's FHN allowlist for debug
  models: Nordic's README says FHN provisioning of the debug model fails
  otherwise. Request it through the device proposal form linked from the FHN
  spec. The Fast Pair half-sheet itself shows without it.
- Settings → Google → Devices & sharing → Devices → "Include debug results" on.
- Find Hub app installed; Bluetooth and location on.

Steps:
1. Flash: `pio run -e WioTrackerL1_companion_radio_ble_findhub`, then copy
   `firmware.uf2` (from `bin/uf2conv/uf2conv.py -f 0xADA52840 -c firmware.hex`)
   onto the bootloader drive.
2. On the tracker: home pages → "Find Hub" → Enter ("pairing: open phone").
   Or `nix run .#meshcore-findhub -- pair --address <ble>` from enceladus.
3. Phone near the tracker: the half-sheet "NCS locator tag" (debug) appears →
   Connect → accept the Find Hub terms. The tracker page goes "adding to Find
   Hub.." then "registered"; `meshcore-findhub status` shows provisioned, 1
   account key and `key-based pairing 1 ok`.
4. Find Hub app: the device is listed. "Play sound": the tracker rings until
   stopped, the timeout runs out, or any key is pressed.
5. Crowd report: leave the owner's phone behind, carry the tracker past other
   Android phones (Find Hub network on, "high-traffic areas" or "all areas"),
   ideally in a busy place. A location shows up in Find Hub, often after
   15-60 min.
6. Power-cycle the tracker: it comes back "registered", and the owner's phone
   re-syncs its clock the next time it is near (the status shows "waiting for
   the owner's phone" until then).
7. Remove: in the Find Hub app (removes it from the account), then on the
   tracker Enter twice on the Find Hub page (or `meshcore-findhub clear`).
