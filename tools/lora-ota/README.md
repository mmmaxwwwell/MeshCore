# Firmware over LoRa (ESP32 and nRF52, repeaters and companions)

Sends a signed firmware image to a repeater over the LoRa link itself, through
any companion radio, with automatic rollback. Design and decisions:
`~/git/homelab/docs/build-notes/meshcore-lora-ota-plan.md`.

## How it works

1. The sender talks to the target through any companion radio (USB or BLE).
   - **Repeater target:** the sender logs in as admin.
   - **Companion target:** no login. A companion takes OTA requests only
     from radios it has **favourited**.
2. REQ_RADIO moves the target to a private fast channel (default 919.0 MHz,
   500 kHz, SF5); the sending companion follows. The target drops back to
   its own settings by itself after 90 s without OTA traffic, so a dead
   laptop can't strand it.
3. BEGIN carries size, SHA-256, an ed25519 signature and the chunk size.
   The target checks the signature against the key compiled into it
   (`LORA_OTA_PUBKEY`) and its own board tag (`LORA_OTA_BOARD`), then
   prepares its staging area.
4. DATA chunks stream without per-chunk acks. 136 bytes is the most a stock
   companion's 176-byte command frame carries; the target caps chunks at
   156. STATUS returns a bitmap of what's missing, and the sender resends
   only that. A broken link can resume: a new push of the same image
   continues the same session.
5. FINISH: the target reads the image back and checks the hash and the
   LoRa-OTA marker, answers "checksum good, rebooting", and installs it 6 s
   later.
6. The new image boots on probation. The sender sends CONFIRM until the
   REBOOTED target answers (its uptime tells new from old). **No CONFIRM
   within 60 s of boot, or a crash or hang before one: back to the old
   image.**

Per chip:
- **ESP32:** staged in the spare OTA partition. The bootloader's own
  rollback does the rest.
- **nRF52840 with a QSPI LittleFS** (Wio Tracker L1 companions etc.):
  - **Staging:** in a file on that filesystem.
  - **Install:** back up the running image to a second file, then a RAM
    routine copies the new one into the app region. It marks the app invalid
    while it copies, so a power cut lands in the bootloader's DFU mode
    instead of half an image. It verifies the copy, falls back to the backup
    if the copy won't verify, and starts the hardware watchdog.
  - **Rollback:** the probation logic reinstalls the backup.
  - **Not covered:** an image that dies on every boot before the OTA service
    starts.
  - Which boards: `~/git/homelab/docs/build-notes/meshcore-lora-ota-plan.md` L8.

Every request is a REQ datagram encrypted and MAC'd with the shared secret of
an admin (repeater) or a favourite (companion), so nobody else can run a
session. The signature means an admin password alone cannot install
code: you also need the signing key.

## Use

Envs: `Heltec_v3_companion_radio_usb_lora_ota` (Rhea),
`WioTrackerL1_companion_radio_ble_posreport_lora_ota` (Wayfarer),
`heltec_v4_repeater_lora_ota`, `Heltec_v3_repeater_lora_ota`.

```sh
P='nix shell --impure --expr "with import <nixpkgs> {}; [ (python3.withPackages (p: [ p.cryptography ])) ]" -c python3'
$P tools/lora-ota/lora_ota.py keygen     # once; key at ~/.config/meshcore/ota-signing.key
$P tools/lora-ota/lora_ota.py pubkey     # goes in -D LORA_OTA_PUBKEY of the *_lora_ota envs

# ESP32: sign the app-only firmware.bin (never the merged USB image)
pio run -e Heltec_v3_companion_radio_usb_lora_ota
$P tools/lora-ota/lora_ota.py sign .pio/build/Heltec_v3_companion_radio_usb_lora_ota/firmware.bin --board heltec_v3_companion_usb
# nRF52: sign the raw app region, made from the hex
arm-none-eabi-objcopy -I ihex -O binary .pio/build/<env>/firmware.hex wayfarer.bin
$P tools/lora-ota/lora_ota.py sign wayfarer.bin --board wio_l1_companion_ble

# push runs with the meshcore lib (homelab's pinned python-meshcore; no cryptography needed)
lora_ota.py push --companion E2:7D:69:21:47:AA --target Rhea rhea.bin                 # companion target
lora_ota.py push --companion /dev/serial/by-id/... --target Wayfarer wayfarer.bin     # e.g. on titan, Rhea as sender
lora_ota.py push --companion ... --target Quartz --password-file <admin pw> quartz.bin  # repeater target

# delta: send only what changed since the image the target runs now (keep the .bin you flashed!)
lora_ota.py push --companion ... --target Rhea --delta-from rhea-previous.bin rhea.bin
lora_ota.py delta rhea-previous.bin rhea.bin -o rhea.patch   # just make one, to see its size
```

Notes:
- **Companion targets** take OTA requests only from radios they have
  favourited. **Repeater targets** need the admin password.
- Rhea is owned by titan's `meshcore-gateway`. To send *from* Rhea, run the
  tool on titan with the gateway and both its sockets stopped. When Rhea
  *receives*, the gateway can stay up; it reconnects after the reboot.
- `--fast freq,bw,sf,cr` picks the transfer channel (default `919.0,500,5,5`,
  inside US 902–928 and clear of the MeshCore and Meshtastic presets).
  `--slow` stays on the mesh settings, works across hops and is paced to a
  small share of the shared channel: see "Slow mode" below.
- The sender keeps the companion's own settings: radio, tuning, and the
  client-repeat flag. Note that `set_radio` without that flag turns repeat
  off and saves it. Ctrl-C restores them too.
- An interrupted push can be re-run: it finds the target on the transfer
  channel if it is still there, and resumes the same session within 5 min
  (a `--slow` session: 6 h, and its chunks survive even after that).
- `confirm [--wait 150]` keeps sending CONFIRM, which is how you confirm a
  first LoRa-OTA build installed by WiFi OTA.
- Measured (2026-10-18), Wayfarer ↔ Rhea across the house:
  - Rhea ESP32 image (664 KB), sent from Wayfarer over BLE: about 310 s at
    2.1 KiB/s. The BLE round trip per frame is the limit.
  - Wayfarer nRF52 image (422 KB), sent from Rhea over USB: about 125 s at
    4.4 KiB/s.
  - Install plus reboot adds about 10 s (ESP32) or about 40 s (nRF52: backup
    plus copy).

Repeater CLI (admin): `ota status`, `ota confirm`, `ota rollback` (only while
pending).

### Delta updates (`--delta-from`)

Between two of our own builds most of the image is unchanged, so `push
--delta-from BASE.bin` sends a patch that rebuilds the new image from the one
the target runs (`delta.py`, stdlib only; format in its docstring):

- **Patch:** bsdiff's matching (code that moved keeps its alignment; where an
  address changed, a sparse byte diff), then raw deflate with a 2 KiB window.
- **Target:** BEGIN carries the base's sha256[0:8] (what CONFIRM reports for
  the running image). The target compares it with its running image before
  any DATA, and refuses a mismatch with `BASE_MISMATCH` (13).
  - The sender then sends the whole image instead. It does the same for
    firmware without delta support (`BAD_ARG`) or without room for the
    patch (`TOO_BIG`).
  - The sender doesn't probe with CONFIRM first: CONFIRM would also confirm
    a pending image.
- **Staging:** the DATA chunks are the patch. The existing bitmap, STATUS
  and resume logic is unchanged. The patch is staged:
  - ESP32: at the end of the spare OTA partition.
  - nRF52 LittleFS: in `/ota-patch.bin`, at most ~250 KB.
  - nRF52 raw slots: in the backup slot, which install rewrites afterwards.
- **FINISH:** the target decodes the patch into the normal staging area, a
  32 KB slice per main-loop pass, answering WORKING meanwhile.
  `verifyImage()` then checks the result against the **signed** size and
  sha256, plus the marker.
  - The signature always covers the final image, so a patch is never
    trusted. A corrupt or malicious one decodes to garbage, which fails the
    hash and never activates (`hash mismatch`; the sender resends once,
    then gives up).
  - Everything after verify (install, probation, rollback) is the same as
    for a full image.
- **Decoder** (`src/helpers/LoraOTADelta.cpp`): about 3.6 KB of RAM,
  allocated once at boot, with no big stack frames. It reads the patch once,
  front to back, and writes the image strictly in order.
  - ESP32 reads the base with `esp_partition_read` on the running partition.
  - nRF52 reads it straight from internal flash at `APP_START`.
- **Keep the exact `.bin` each radio runs.** The base must be byte-identical
  to what is flashed.
  - ESP32: the app-only `firmware.bin`. The base sha is the hash esptool
    appends to it.
  - nRF52: the objcopy'd app region.

Measured (2026-10-18, two builds of the same env from the same tree):

| Env | Change | Image | Patch |
|---|---|---|---|
| Heltec_v3_companion_radio_usb_lora_ota (ESP32-S3) | `FIRMWARE_BUILD_DATE` "x" -> "y" | 664,432 B | 110 B (1 chunk) |
| Heltec_v3_companion_radio_usb_lora_ota | +5-line CLI command (`uptime`) | 664,560 B | 23,255 B (3.5%) |
| WioTrackerL1_companion_radio_ble_posreport_lora_ota (nRF52) | `FIRMWARE_BUILD_DATE` | 421,640 B | 40 B (1 chunk) |
| WioTrackerL1_companion_radio_ble_posreport_lora_ota | +5-line CLI command | 421,784 B | 4,828 B (1.1%) |

A code change shifts everything linked after it, so every pointer into the
moved code changes: that, not the new code, is most of a code-change patch.

**Delta and slow mode together** (slow mode is the next section): `push --slow --delta-from BASE` sets both
BEGIN flags.
- Slow mode's ETA counts the patch, not the image.
- Its persisted bitmap then names patch chunks. The session record also
  holds the patch size and the base sha, so a reboot resumes only the same
  delta against the same base, never a full push of that image.
- After a reboot, the target re-opens the staged patch without erasing it
  (`patchReattach`), and erases the image area again for the decode.
- On ESP32, the patch area ends below slow mode's 4 KB session sector.
- On nRF52 raw slots, the patch is in the backup slot, and the session
  sector sits after the state sector, so they don't overlap.

## Slow mode: over the shared mesh, a little at a time

`push --slow` sends the update through the normal mesh, on the normal radio
settings, through repeaters, over hours to days, using only a small share of
the channel's airtime: a polite neighbour on the shared CT Mesh channel. Every
packet is an ordinary encrypted MeshCore REQ datagram, as in the fast mode.

```sh
lora_ota.py eta wayfarer.bin                      # how long, at 0.5/1/2/5 % (add --hops N)
lora_ota.py push --slow --companion ... --target Wayfarer wayfarer.bin            # 2 % of airtime
lora_ota.py push --slow --duty 1 ...              # a share of airtime, relays included
lora_ota.py push --slow --pace 60 ...             # or: one packet per 60 s
lora_ota.py push --slow --resume ...              # after Ctrl-C, a laptop sleep, a day later
```

- **Pacing.** Every transmission is paced, not just DATA: STATUS polls,
  BEGIN/FINISH re-asks and retries too. After each packet the sender waits
  `airtime / duty`, where airtime counts the packet, the target's reply (a
  STATUS reply is about as long as a DATA) and **every relay's re-send**
  (hops + 1 transmissions). ±25 % jitter on every gap, so it never runs in
  lock step with someone else's periodic traffic. Default 2 %.
- **Route.** It uses the contact's learned path (`out_path_len`), so a
  packet costs hops + 1 transmissions. With no path it floods: every
  repeater in reach re-sends every packet. The sender warns and paces as if
  10 transmissions per packet. Better: message the target first so the path
  is learned, or say `--hops N`.
- **Rounds.** DATA goes out in rounds of 256 chunks, each followed by a
  STATUS of just the 1024-chunk windows it touched. The acked bitmap goes to
  the state file after every poll.
- **State file** (`~/.local/state/meshcore-lora-ota/<target>-<sha>.json`,
  or `--state`): target, image SHA-256, session, chunk size, acked bitmap,
  pacing. `--resume` continues from it. If the target still has that
  session, windows already acked in full are not polled again. If not
  (dropped, rebooted), the sender polls everything once. Deleted after a
  good FINISH.
- **LONG sessions on the target.** BEGIN carries a flags byte. LONG (`0x02`)
  raises the idle timeout from 5 min to 6 h for that session only. It also
  keeps the receive bitmap in flash, saved every 16 new chunks or 5 min after
  the first unsaved one, from the main loop (never the receive path). If the
  session is dropped anyway (6 h of silence, or a reboot), the next BEGIN of
  the **same** image (same size, chunk size and SHA-256) checks the
  signature as always, then takes the saved chunks back instead of erasing.
  The sender does that by itself on a `bad session` reply. A reboot costs at
  most the ~16 unsaved chunks, plus whatever of the current round went to
  the dead session.
  - Why it is safe: the record is saved only after its chunks are written;
    the staging area is NOR flash (bits only go 1 -> 0), so rewriting an
    unsaved chunk with the same bytes is harmless; any BEGIN that erases
    the staging area clears the record first; FINISH still re-hashes the
    whole image against the signed SHA-256.
  - Where: ESP32, the last 4 KB sector of the staging OTA partition (images
    may use all but that sector). nRF52 raw slots, its own 4 KB sector after
    the probation STATE sector (never that one). nRF52 LittleFS, the file
    `/ota-session`. On NOR the bitmap is stored inverted, so a save only
    clears bits: no erase per save, and a save cut by a power loss is an
    older but still correct record.
  - An older target ignores the flag (its BEGIN reply has no flags byte).
    The sender then warns: 5-min idle timeout, and a reboot restarts the
    transfer.
- **The node keeps its job.** A LONG session never touches the radio
  settings (no REQ_RADIO) and the node keeps relaying. Between packets it is
  not "pending work", so ESP32 light sleep (repeater `powersaving on`) and
  nRF52 sleep carry on. A packet wakes the node, and the 6 h timeout runs on
  `millis()`, which keeps counting through light sleep.
- **After FINISH** nothing changes: the node reboots into the new image, and
  CONFIRM must land within 60 s of boot or it rolls back. Over several hops,
  watch that round trip. The CONFIRM loop is not paced: it is a minute or
  two of small packets.

### Airtime and ETA

Time on air per Semtech AN1200.13: explicit header, CRC on, preamble 16
(MeshCore's), US preset SF7 / 62.5 kHz / CR 4/5. A DATA is 143 bytes of
payload (7 + 136-byte chunk), plus the 4-byte tag, AES-padded to 160, plus
header, path length, path, hashes and MAC: 166 bytes direct, **549 ms on
air**. A STATUS is 130 ms out and 508 ms back.

`slow_eta` without losses (add your loss rate on top). Duty counts relays:
2 hops = 3 transmissions per packet.

| Image | Chunks | DATA airtime | 1 % | 2 % | 5 % | 2 hops, 2 % | 2 hops, 5 % |
|---|---|---|---|---|---|---|---|
| nRF52 companion (Wayfarer), 422 KiB | 3178 | 29 min | 49 h | 24 h | 10 h | 75 h | 30 h |
| ESP32 companion (Rhea), 664 KiB | 5000 | 46 min | 77 h | 38 h | 15 h | 117 h | 47 h |
| ESP32 repeater (Heltec V3), 1.1 MiB | 8611 | 79 min | 132 h | 66 h | 26 h | 202 h | 81 h |

`--pace 60` on the nRF52 image: about 53 h.

### Protocol (REQ payload, little endian; replies after the 4-byte tag)

| Type | Request | Reply |
|---|---|---|
| `0x60` BEGIN | size u32, sha256[32], sig[64], chunk u8 [, flags u8 [, base sha256[0:8], patch size u32]] | WORKING (12) while it checks the signature and stages; then status, session u32, chunk u8, chunks u16, accepted flags u8 |
| `0x61` DATA | session u32, index u16, bytes | none |
| `0x62` STATUS | session u32, from u16 | status, received u16, first_missing u16, bitmap[128] |
| `0x63` FINISH | session u32 | WORKING while it re-hashes; then status (OK: reboots in 6 s) |
| `0x64` ABORT | session u32 | status |
| `0x65` CONFIRM | none | status, was_pending u8, uptime_s u32, running sha256[0:8] |
| `0x66` RADIO | freq kHz u32, bw Hz u32, sf, cr, idle s u16 | status; applies 1.5 s later, reverts after `idle` s without OTA traffic |

BEGIN's size/sha/sig always describe the NEW image. Flags (offset 101;
absent = 0; both may be set):
- `0x01` DELTA: DATA carries a patch of `patch size` bytes (offsets
  102-113) against the running image named by `base sha256[0:8]`. `chunks`
  then counts patch chunks. Status 13 BASE_MISMATCH means the target runs
  another image.
- `0x02` LONG: slow mode, above.

The reply's flags byte echoes the flags the target accepted. An older target
sends no such byte, which reads as 0. Status codes 16-23 belong to signed
settings, 24-28 to maintenance (0x6A-0x6C, "Maintenance" below).

The running sha is what the chip reports. On ESP32 that's the hash esptool
appends to the image; on nRF52 it's the SHA-256 of the app image.

### Found on real radios (each now covered by a host test)

- Requests arrive **zero-padded to 16 bytes** (AES blocks), so DATA must not
  demand an exact length.
- A **stock companion frame is 176 bytes**, so the sender uses 136-byte
  chunks.
- On nRF52 the loop task has a **4 KB stack**. The signature check, staging
  and the full-image hash run in `poll()` from the main loop, never inside the
  receive path (Wayfarer hung).
- **nRF52 QSPI DMA** needs word-aligned RAM buffers, flash addresses and
  lengths. It can't read internal flash either, so the backup is copied
  through RAM. littlefs v1 hands aligned page writes straight to the device.
- **Float range checks drift on nRF52:** 500000 Hz / 1000 > 500. Check
  integers.
- **ESP32 probation** arms the watchdog on the first loop pass, not in
  `setup()`: companion setup takes ~20 s, and a 5 s watchdog reset there makes
  the bootloader roll back.
- **CONFIRM names the running image.** After a rollback the old image answers
  too, with a short uptime.

## Signed settings

The same key that signs firmware also signs **settings bundles**: a short
list of node settings that the owner pushes to a repeater or companion over
LoRa. The node checks the signature, applies the bundle **on probation**, and
puts the old values back by itself unless a CONFIRM arrives in time.
Source: `src/helpers/LoraOTASettings.{h,cpp}`. Every `*_lora_ota` build has it.

### Trust

- **Signature.** ed25519 with the compiled-in `LORA_OTA_PUBKEY`, over
  `"MCSET1" || body`. Firmware manifests sign `"MCOTA1" || ...`, so a
  firmware signature never verifies as a settings bundle and the reverse.
  The node checks the signature before it reads anything else in the body.
- **Who can send it.** The same as firmware: an admin for a repeater, a
  favourite for a companion. The admin password alone changes nothing this
  way: the bundle must also carry the owner's signature.
- **Target.** A bundle names one node (public key prefix, at least 6 bytes)
  or one board tag (`LORA_OTA_BOARD`, e.g. every `heltec_v4_repeater_headless`).
  Anything else is refused.
- **Replay.** Each bundle has a version (`make` uses the unix time). The node
  records the version as it applies a bundle and refuses anything not newer.
  A bundle that reverted has spent its version: make a new one to retry.
- **Whitelist.** Only these keys. Values are range-checked on the node, and
  one bad entry refuses the whole bundle.

| Key | Value | Roles |
|---|---|---|
| `radio` | `freq,bw,sf,cr` (MHz, kHz; 3 decimals at most) | both |
| `tx` | dBm, -9 up to the board's build maximum (`MAX_LORA_TX_POWER`, else `LORA_TX_POWER`) | both |
| `af` | 0-9 | both |
| `rxdelay` | 0-20 | both |
| `txdelay`, `direct.txdelay` | 0-2 | both |
| `multi.acks` | 0-1 | both |
| `path.hash.mode` | 0-2 | both |
| `int.thresh` | 0-255 | both |
| `agc.reset.interval` | seconds, 0-1020, multiple of 4 | both |
| `radio.rxgain` | on/off | both |
| `flood.max`, `flood.max.unscoped`, `flood.max.advert` | 0-64 | repeater |
| `advert.interval` | minutes: 0 (off) or 60-240, even | repeater |
| `flood.advert.interval` | hours: 0 (off) or 3-168 | repeater |
| `loop.detect` | off/minimal/moderate/strict | repeater |
| `repeat` | on/off. Companion: client repeat, as `CMD_SET_RADIO_PARAMS` sets it: on only on the client-repeat bands (`ALLOWED_REPEAT_FREQ_RANGE`) | both |
| `regions` | `ct,northeast,east,*`: each region exists (under `*`) with flood allowed. Additive: nothing is removed or denied | repeater |
| `posreport.interval` | minutes 0-1440, 0 = off. As `#locset <min>`: saved to `/posrep`, next report in 5 s | companion, `POSITION_REPORT` builds |
| `overlay` | `off` or `on #<name> <0\|1>`, as `#ovlset`. `off` clears the name and **client repeat goes off with it**; `on` sets the name and client repeat to the last field (the bundle's mask includes `repeat`, so a revert restores both) | companion, `OVERLAY_MESH` builds |

The two feature keys are on the whitelist **only in builds that compile the
feature in**: elsewhere they are `not on the whitelist`, like any unknown key
(and a repeater refuses them as `no such setting` in any build).
`overlay=on #<name> <r>` carries the overlay's region name, and **the name IS
the overlay's key** (the transport key is SHA-256 of it). Owner decision
(2026-10-18): allowed anyway, so a radio out in the field can be moved to a
new overlay group without anyone touching it. What protects the name:
- Over the air it travels only inside the REQ datagrams, which are encrypted
  end to end with the sender/target shared secret (as `#ovlset` DMs are).
- The bundle FILE is signed, not encrypted: `settings make` writes it 0600
  and says so. Keep it like a key and delete it after the push.
- The sender prints only the first characters of the name.
- On the node the name goes only into the overlay config (as `#ovlset`):
  never into the settings state file. The verify buffers are wiped after
  every APPLY.

While an overlay bundle is on probation the node keeps a copy of its own
overlay config in `/ota_set_overlay` to revert from; the copy is deleted as
soon as the bundle is confirmed or reverted. A bundle whose `repeat` entry
disagrees with the overlay's (`off` = repeat off, `on ... r` = r) contradicts
itself and is refused, and `on ... 1` off the client-repeat bands is refused
like `CMD_SET_RADIO_PARAMS` would refuse it.

Never on the list: passwords (admin, guest), the private key, the signing
key, name, location, owner info, bridge settings, power saving, Wi-Fi, BLE
PIN, contacts and telemetry policy, the position
report destination, and anything about OTA itself. A companion refuses
repeater keys (`this node has no such setting`); with client repeat on
(already, or from the same bundle), it also refuses a `radio` outside the
client-repeat bands.

**Reboot request.** A bundle may carry the control entry `reboot=1`
(`make`/`diff --reboot`). It is not a setting: it changes nothing by itself,
a bundle with nothing else is refused, and any value but `1` is refused. The
node reboots **once, 6 s after the bundle's CONFIRM** (time for the reply to
go out), with the confirmed settings saved. It never reboots instead of a
CONFIRM: a bundle that reverts (no CONFIRM, REVERT, or a reboot/power cut
during probation) does not reboot the node, and the request is held in RAM
only. The version is spent like any other, so the bundle cannot be replayed
after the reboot. A node without this firmware refuses `reboot` as not on
the whitelist, so it never silently skips one.

### Probation

1. The bundle arrives in DATA chunks; APPLY names its SHA-256. The node
   checks signature, target, version and every value from its main loop
   (APPLY answers WORKING meanwhile).
2. It first saves a **probation record**: the old values of every key the
   bundle changes (regions: a copy of the region table). Then it applies and
   saves the new values.
3. Radio keys (`radio`, `tx`, `radio.rxgain`) reach the radio **1.5 s after
   the OK reply** goes out (10 s after the apply at the latest), so the
   reply leaves on the old settings.
4. **No CONFIRM within 60 s of the change** (from the radio switch for radio
   keys): the old values come back, radio included. CONFIRM is refused
   until the radio has switched, so a CONFIRM proves the sender reaches the
   node on the new settings.
5. A **reboot or power cut** before CONFIRM: the old values come back at
   boot.
6. One thing at a time: no bundle while a new firmware image is unconfirmed,
   no firmware BEGIN while a bundle is on probation (or its reboot is due),
   and no second bundle until the first is confirmed or reverted.
7. `reboot=1`: after the CONFIRM, the node reboots once, 6 s later.

The sender handles the radio case: after APPLY it moves its own companion to
the bundle's radio settings (direct path, no repeaters in between), sends
CONFIRM there, and **always** puts the companion back on its own settings,
also on failure or Ctrl-C. If the node can't be reached on the new settings,
the sender gives up, goes back, and the node reverts within 60 s by itself.
A radio change therefore needs the node within direct range of the sending
companion.

### Use

```sh
# make (offline, signs with ~/.config/meshcore/ota-signing.key)
lora_ota.py settings make --target ce6ce5eab221 --set radio=910.525,62.5,7,5 \
    --set flood.max.unscoped=12 --set flood.advert.interval=47 --set regions=ct,northeast,east,* -o quartz.mcset
lora_ota.py settings make --target board:heltec_v4_repeater_headless --set tx=20 -o v4-tx.mcset
lora_ota.py settings make --target 534b6eee0f09 --set posreport.interval=10 --set overlay=off --reboot -o wayfarer.mcset

# diff: read the node's values (as show does), sign a bundle of ONLY the keys that differ
lora_ota.py settings diff --companion ... --target Wayfarer --set posreport.interval=10 --set repeat=off \
    --set tx=22 -o wayfarer.mcset          # prints current -> wanted per key; no bundle if nothing differs
lora_ota.py settings eta wayfarer.mcset [--hops 3 | --flood]   # round trips and channel airtime

# push: shows current -> new, uploads, applies, follows a radio change, confirms
lora_ota.py settings push --companion ... --target Quartz --password-file <admin pw> quartz.mcset
lora_ota.py settings push --companion ... --target Wayfarer wayfarer.mcset          # companion: favourite

lora_ota.py settings show    --companion ... --target T [--password-file F]
lora_ota.py settings status|confirm|revert --companion ... --target T [--password-file F]
```

Reading the current values:
- **Repeater:** the sender reads them with the admin CLI (`get radio`,
  `get flood.max`, `region list allowed`, ...), which works on any firmware.
- **Companion:** a companion has no CLI over LoRa. A signed-settings
  firmware answers `GET` (CTRL op 3) with every key it supports, which is
  what `settings show` and `push` print. On older firmware only the
  companion's own app (or USB) shows them.

`diff` compares values the way the node holds them (`1` = `1.0`,
`62.5` = `62.50`, regions in any order); a key it cannot read counts as
changed. The bundle targets the node's 8-byte key prefix unless
`--bundle-target` says otherwise. Smaller bundles mean fewer DATA packets.

Repeater CLI (admin): `ota settings` (version, pending, seconds left),
`ota settings confirm`, `ota settings revert`.

### Over the mesh: how long a bundle takes

A settings push is not paced like a `--slow` firmware push: it is a handful
of request/reply round trips on the mesh preset: STATUS, one DATA per 137
bytes, APPLY (WORKING, then the result) and CONFIRM. The sender reuses slow
mode's airtime math (`settings eta`, also printed by `make` and `diff`; US
preset SF7 / 62.5 kHz, both directions, every relay counted):

| Bundle | Round trips | Airtime direct | 3 hops | flood (10 tx) |
|---|---|---|---|---|
| ~100 B (one or two keys) | 5 | 1.7 s | 7.1 s | 17 s |
| ~160 B (a few keys + reboot) | 6 | 2.2 s | 9.2 s | 22 s |
| ~350 B (regions list) | 7 | 3.0 s | 12.5 s | 30 s |
| 512 B (the maximum) | 8 | 3.7 s | 15.5 s | 37 s |

The wall time is those round trips: seconds direct, tens of seconds over a
few hops, plus the reply retries on loss. A typical bundle is done well
inside the 60 s probation window. Held to slow mode's default 2% of the
channel it would take ~1.5-3 min direct; the push does not wait like that,
since a bundle is only a few packets.

### Protocol (REQ payload, little endian; replies after the 4-byte tag)

| Type | Request | Reply |
|---|---|---|
| `0x67` SET_DATA | total u16, offset u16, n u8, bytes | status, have u16 (contiguous bytes held) |
| `0x68` SET_APPLY | total u16, sha256(bundle)[0:8] | WORKING (12) while it checks; then status, version u32, secs_left u16 |
| `0x69` SET_CTRL | op u8: 0 STATUS, 1 CONFIRM, 2 REVERT | status, pending u8 (2 = radio switch still to come), was u8, version u32, pending_version u32, secs_left u16, flags u8 (bit 0: the pending bundle asks for a reboot, bit 1: the reboot is due; older firmware stops before flags) |
| `0x69` SET_CTRL | op 3 GET, start u8 | status, next u8 (0xFF = end), `key=value\n` text |

Bundle: `body || sig[64]`, at most 512 bytes; body = version u32, target kind
u8 (1 = public key prefix, 2 = board tag), target length u8, target, count u8,
then per entry key length u8, key, value length u8, value (ASCII, as the CLI
takes it). The entry `reboot` = `1` is the reboot request (counts toward the
24 entries; at most once). The format is otherwise unchanged: a bundle
without `reboot` reads the same on old and new firmware.

Status codes 16+: 16 version not newer, 17 another node/board, 18 not on the
whitelist, 19 value out of range, 20 does not parse, 21 another bundle on
probation, 22 no such setting on this role, 23 could not save. Reused: 3 bad
signature, 6 incomplete, 7 hash mismatch, 10 unconfirmed firmware image, 12
working.

### Signed-only mode (build flag, off by default)

`-D LORA_OTA_SETTINGS_SIGNED_ONLY` on a repeater build refuses, **over
LoRa only**, the admin CLI commands that change a whitelisted setting
without a signature. USB serial and the ethernet CLI (both `sender_timestamp`
0) stay open: they are the recovery path. Blocked:

- `set radio`, `set freq` (already serial-only), `set tx`, `set af`,
  `set dutycycle` (it sets `af`), `set rxdelay`, `set txdelay`,
  `set direct.txdelay`, `set multi.acks`, `set path.hash.mode`,
  `set int.thresh`, `set agc.reset.interval`, `set radio.rxgain`
- `set flood.max`, `set flood.max.unscoped`, `set flood.max.advert`,
  `set advert.interval`, `set flood.advert.interval`, `set loop.detect`,
  `set repeat`
- `tempradio`
- `region load`, `region save`, `region allowf`, `region denyf`,
  `region home <name>`, `region default <name>`, `region put`,
  `region remove`, `region def`

Everything else (passwords, name, location, `get ...`, `region list`,
`ota ...`, `reboot`, ...) is unchanged. Companions take settings from their
own app over BLE/USB, never over LoRa, so the flag only matters on
repeaters. Whether to turn it on is the owner's call.

### Tests

`test_sim.py` also builds `LoraOTASettings.cpp` for the host behind a fake
node (`sim/settings_sim.cpp`: prefs and their saved copy, state file,
region table, a radio that only hears a sender on the same settings) and
drives it with the real sender (`sim/settings_tests.py`): apply + confirm,
revert without confirm, a radio change the sender follows, a radio change
it cannot follow (the node comes back by itself), reboot during probation,
replay and old versions, a foreign key, a tampered bundle, a firmware
manifest's signature passed off as a bundle, non-whitelisted and
out-of-range values, other node/board, role limits, one bundle at a time,
REVERT, a failed probation record, a multi-chunk bundle with regions over
20% loss, GET, and the signed-only command list.

It builds the fake node twice, without and with `-DPOSITION_REPORT
-DOVERLAY_MESH`: the feature keys are refused by the first (both roles) and
by a repeater in the second; `posreport.interval` and `overlay=off` apply,
revert without a CONFIRM and across a reboot, `overlay=off` takes client
repeat with it and leaves no copy of the region name once confirmed,
`overlay=on` is refused; client `repeat` keeps to the allowed bands;
`reboot=1` reboots exactly once ~6 s after the CONFIRM (also with a radio
change) and never after a revert, REVERT or replay; `diff` keeps only the
changed keys, and the bundle it makes applies.

## Maintenance

All maintenance of a node over LoRa, through any companion, over any number
of hops: read its state, and change it with commands the owner signs.
Source: `src/helpers/LoraOTAMaint.{h,cpp}` (platform-neutral) and
`LoraOTAMaintFs.h` (the apps' filesystem half). Every `*_lora_ota` build has
it: companions fully, repeaters and room servers the parts that apply to
them.

### Security model

- **Who can ask.** Requests are REQ datagrams, encrypted end to end with the
  sender/target shared secret, like OTA and settings. A companion answers
  only radios it has **favourited**; a repeater or room server only a
  logged-in **admin**.
- **Read-only requests** (`MNT_READ`) change nothing, and that gate is all
  they need. They return public data only:
  - status: firmware version, uptime, battery, storage, counts, what is in
    flight;
  - file lists: **names and sizes**, never contents;
  - contacts: key prefix, name, type, flags, last advert;
  - channels: index and name.
  Never returned: the private key, passwords, channel secrets, the overlay
  name, the contents of any file. A **hashtag channel**'s secret is
  SHA-256 of its name, so its name IS its key: it is listed with only its
  first 3 characters and a flag saying so.
- **Everything that changes or deletes anything is a signed command:**
  - **Signature:** ed25519 with the compiled-in `LORA_OTA_PUBKEY` (the
    firmware and settings key) over `"MCMNT1" || body`. Firmware signs
    `"MCOTA1"` and settings `"MCSET1"`, so no signature passes for another
    kind. The node checks the signature before it reads anything else in the
    body. There is no way to change the key at runtime.
  - **Target:** the command names one node (public key prefix, at least 6
    bytes) or one board tag (`LORA_OTA_BOARD`). Anything else is refused.
  - **Replay:** a counter (the sender uses the unix time, or the node's last
    + 1 if that is higher). The node refuses anything not newer and saves
    the counter in `/ota_maint` on its **primary** filesystem **before** the
    command runs, so a command never runs twice, even across a power cut. A
    refusal that changed nothing (BUSY, NOT_SUPPORTED, a malformed command)
    does not spend the counter.
  - No signature, another key, a body altered after signing, another node,
    an old counter: refused, nothing changes.
- **Guard rails on top of the signature:**
  - The requester's own contact is never deleted or un-favourited (that
    would cut off the radio asking). The node's own key is never added as a
    contact.
  - Format and reboot wait (BUSY) while a firmware image is unconfirmed,
    a firmware transfer is in progress, or a settings bundle is on
    probation: the firmware's rollback copy and staging files live on the
    ExtraFS of an nRF52 companion.
  - Protected files are never deleted: identity (`*.id`, `/identity/...`),
    prefs (`prefs.json`, `new_prefs`, `com_prefs`), both replay counters and
    the settings probation copies (`ota_settings`, `ota_set_*`,
    `ota_maint`), firmware rollback and staging (`ota-state`, `ota-old.bin`,
    `ota-new.bin`, `ota-session`, `ota-patch.bin`), `overlay`, `posrep`,
    the contact and channel tables (`contacts3`, `channels2`), and the
    repeater/room ACL and regions (`s_contacts`, `regions2`). Paths with `.`
    or `..` components and directories are refused too.
  - Work that touches many contacts or flash runs from the main loop, a
    slice per pass (prune: 8 contacts), never in the receive path; EXEC
    answers WORKING meanwhile. Buffers are static (nRF52 loop stack: 4 KB).

### Operations

| Op | Signed | Companion | Repeater / room |
|---|---|---|---|
| `status` | no | yes | yes |
| `files [--fs 0\|1] [DIR]` | no | both filesystems | primary |
| `contacts [--types T] [--non-favourites] [--no-names]` | no | yes | (none) |
| `channels` | no | yes | (none) |
| `delete-contact PREFIX\|NAME... [--force]` | yes | yes | |
| `prune --types repeater,sensor [--dry-run]` | yes | yes | |
| `favourite PREFIX\|NAME [--off]` | yes | yes | |
| `add-contact --from-json F` | yes | yes | |
| `format-extrafs` | yes | nRF52 with an ExtraFS | |
| `delete-file [--fs 0\|1] PATH` | yes | yes | yes |
| `reboot` | yes | yes | yes |

- **delete-contact:** by key prefix (12+ hex digits) or by a name that is
  unique on the node. Favourites stay unless `--force`. A prefix that
  matches two contacts deletes neither. Reports deleted / not found /
  ambiguous / skipped.
- **prune:** deletes every contact of the given types that is **not a
  favourite**: the fleet's "no strangers' repeaters" policy is
  `prune --types repeater,sensor`. People and rooms stay unless named.
  `--dry-run` lists what would go (a read, nothing signed). The contacts
  file is then written by the companion's usual lazy save (5 s).
- **favourite:** sets or clears the favourite flag.
- **add-contact:** a full public record: `public_key`, `name` (1-31 bytes),
  `type` (1 chat, 2 repeater, 3 room, 4 sensor), `flags`, `out_path_len`
  (-1 = flood), `out_path` (hex), `last_advert`. The meshcore lib's contact
  form (`adv_name`, ...) is read too. A known key is updated. A full table
  answers FULL.
- **format-extrafs:** for the nRF52 companions whose contacts and channels
  live on the QSPI ExtraFS. The companion holds both in RAM, so: format the
  secondary FS only, save contacts and channels back from RAM, then count
  what the files hold and compare with RAM (STORE_ERROR if they differ).
  Identity, prefs, the overlay and both replay counters live on the primary
  FS and are not touched. Advert blobs and leftover OTA files on the ExtraFS
  are gone afterwards. The sender prints the node's status after it.
- **delete-file:** `/name` on the primary FS, `ExtraFS/name` (or `--fs 1`)
  on the secondary one. Files only, never the protected ones.
- **reboot:** 6 s after the reply. Contacts not saved yet are saved first.

```sh
lora_ota.py maint status --companion ... --target Wayfarer
lora_ota.py maint contacts --companion ... --target Wayfarer --types repeater,sensor --non-favourites
lora_ota.py maint prune --companion ... --target Wayfarer --types repeater,sensor --dry-run
lora_ota.py maint prune --companion ... --target Wayfarer --types repeater,sensor
lora_ota.py maint format-extrafs --companion ... --target Wayfarer
lora_ota.py maint files --companion ... --target Quartz --password-file <admin pw>
lora_ota.py --key other.key maint reboot --companion ... --target Quartz --password-file <admin pw>
lora_ota.py maint status --json ...        # every op: --json for machines
```

- The signing key is `~/.config/meshcore/ota-signing.key` (`--key` to use
  another). A command is made and signed on the fly for the node's 8-byte
  key prefix (`--bundle-target board:TAG` for a board-wide one).
- Over hops it rides the contact's path like any REQ: no fast channel, a
  command is one DATA plus a few EXEC round trips. A full contact listing
  of 350 contacts is ~70 round trips with names, ~35 without
  (`--no-names`); `prune --dry-run` asks only for the matching ones.
- `ota maint` on the node's CLI prints the last command's counter.

### Protocol (REQ payload, little endian; replies after the 4-byte tag)

| Type | Request | Reply |
|---|---|---|
| `0x6A` MNT_READ | op u8, args | status, data (op 0-3 below) |
| `0x6B` MNT_DATA | total u16, offset u16, n u8, bytes | status, have u16 (contiguous bytes held) |
| `0x6C` MNT_EXEC | total u16, sha256(command)[0:8] | WORKING (12) while it checks and runs; then status, counter u32, op u8, result |

MNT_READ ops (replies at most 128 bytes; a page ends where the next entry
would not fit):
- `0` STATUS -> role u8 (0 companion, 1 repeater, 2 room), flags u8 (1 image
  unconfirmed, 2 OTA transfer, 4 settings on probation, 8 command running,
  16 reboot due, 32 has ExtraFS), uptime u32, battery mV u16, primary
  used/total KB u32 u32, ExtraFS used/total KB u32 u32 (0xFFFFFFFF none),
  contacts u16 (0xFFFF none), max u16, favourites u16, channels u8 (0xFF
  none), settings version u32, last maintenance counter u32, fw len u8 +
  fw, board len u8 + board.
- `1` FILES: fs u8, start u16, dir (to the end; default `/`) -> next u16
  (0xFFFF end), entries: kind u8 (1 = dir), size u32, len u8, name.
- `2` CONTACTS: start u16, types u8 (bit per ADV type, 0 = all), flags u8
  (1 not favourites only, 2 no names) -> total u16, next u16 (0xFFFF end),
  entries: key prefix[6], type u8, flags u8, last advert u32 [, len u8,
  name].
- `3` CHANNELS: start u8 -> next u8 (0xFF end), entries: index u8, kind u8
  (1 = name-keyed: name cut to 3 characters), len u8, name.

A signed command is `body || sig[64]`, at most 256 bytes; body = counter
u32, target kind u8 (1 = key prefix, 2 = board tag), target len u8, target,
op u8, args:

| Op | Args | Result |
|---|---|---|
| `0x10` DELETE_CONTACTS | flags u8 (1 = also favourites), prefix len u8 (6-32), n u8, n prefixes | deleted, not found, ambiguous, skipped (u8 each) |
| `0x11` PRUNE | types u8 (bit per ADV type 1-7) | deleted u16, favourites kept u16, contacts left u16 |
| `0x12` FAVOURITE | on u8, prefix len u8, prefix | - |
| `0x13` ADD_CONTACT | key[32], type u8, flags u8, out_path_len u8, last advert u32, path bytes, name | 0 added / 1 updated |
| `0x14` FORMAT_EXTRAFS | - | contacts before u16, stored u16, channels before u8, stored u8 |
| `0x15` DELETE_FILE | fs u8, path | - |
| `0x16` REBOOT | - | - |

Status codes 24+: 24 not found, 25 protected (a protected file, the node
itself, or your own contact), 26 contact table full, 27 busy (an image,
transfer or settings bundle in flight), 28 prefix matches more than one
contact. Reused: 3 bad signature, 6 incomplete, 7 hash mismatch, 11 bad
argument, 12 working, 16 counter not newer (replay), 17 another node/board,
20 does not parse, 22 not on this node, 23 could not save. While a command
runs, an OTA BEGIN is refused with 10 (one thing at a time).

### Tests

`test_sim.py` builds `LoraOTAMaint.cpp` behind a fake companion or repeater
(`sim/maint_sim.cpp`: two filesystems as path -> bytes, the contact and
channel tables and their files, an identity and prefs full of secret
markers) and drives it with the real sender (`sim/maint_tests.py`):
- every mutating op refused unsigned, signed by another key, altered after
  signing, signed as a settings bundle or a firmware manifest, for another
  node or board, replayed, or older, each changing nothing; the owner's
  command runs; the counter survives a power cycle; a counter that cannot be
  saved refuses the command;
- no reply ever holds a secret marker, a channel secret or a hashtag name;
  read requests change nothing; bad paths are refused;
- 350 contacts page through completely, with and without names;
- delete (favourites, `--force`, the requester, ambiguous prefixes), prune
  of 350 (favourites, people and rooms stay; at most 8 removals per loop
  pass; WORKING meanwhile), favourite, add / update / full / own key,
  malformed records;
- format: refused while an image / transfer / settings bundle is in flight
  without spending the counter, then the same command runs; same contacts
  and channels stored, identity and primary FS untouched, everything else
  gone, the same tables after a power cycle; not supported without ExtraFS;
- delete-file against every protected name and traversal trick; reboot
  once, 6 s after the reply, refused while settings are on probation;
- a repeater; 20% packet loss; and the CLI's own logic (`maint_do`: dry
  run, by name, a contact from the meshcore lib's JSON, fresh counters).
`service_test.cpp` also runs maintenance through `LoraOTAService`.

## The first LoRa-OTA image

A node gets its first LoRa-OTA build some other way: USB, or WiFi OTA
(`start ota`). After a WiFi OTA that image also boots unconfirmed: run
`lora_ota.py confirm` as the upload finishes. It must land within 60 s of boot
or the image rolls back.

## Test

```sh
nix shell --impure --expr 'with import <nixpkgs> {}; [ (python3.withPackages (p: [ p.cryptography ])) gcc ]' \
    -c python3 tools/lora-ota/sim/test_sim.py
```

This builds `src/helpers/LoraOTA.cpp` for the host behind a pipe that loses
packets, with a RAM flash that behaves like NOR. It then runs the real sender
through: clean transfer, 20% loss, a bad flash write, a foreign key, the wrong
board, no marker, an unconfirmed running image, too big, an image altered
after signing, resume after a dropped link, the confirm timing (only an
answer from the rebooted image counts, and a rollback is reported), plus the
nRF52 littlefs staging and the service layer under `-ffast-math`.

Slow mode, on a virtual clock that passes on the target too:
- a paced transfer at 15 % loss: the airtime share it asked for, no two
  packets too close, STATUS paced too, and the ETA within reach;
- resume from the sender's state file after the sender dies;
- a 5 h silence keeps a LONG session; a 7 h one drops it, and BEGIN again
  takes the saved chunks back;
- a target reboot mid-transfer resumes from the persisted bitmap, and
  without a session store it restarts and still finishes;
- a fast session still drops after 5 min;
- in the service: a LONG session does not count as pending work (the node
  sleeps) while a fast one does, it survives 10 min of silence, and it
  drops after 6 h.

Delta updates are tested the same way, against a simulated running image:
- delta transfer, 20% loss, and a bad flash write in the patch;
- a wrong base is refused before any DATA, and `push` falls back to the
  whole image (also for firmware without delta support, or no room);
- a corrupt patch, and one that decodes to a different image, never
  activate;
- a malformed patch is refused;
- resume mid-delta.

The firmware decoder is also built alone (`sim/delta_test.cpp`, `-ffast-math`,
with ASan and UBSan where the compiler has them). It is run with odd step
budgets and 300 fuzzed patches per pair. Set `LORA_OTA_DELTA_PAIRS` to a
directory of real builds (`<env>-x.bin`, `<env>-y.bin`, `<env>-code.bin`) to
run those pairs through the decoder and the whole protocol too. Delta and
LONG together: a target reboot mid-patch resumes from the persisted patch
bitmap, and a full push of the same image ignores a delta's record.

Requests are padded and size-checked like a real companion's. It needs
`.pio/libdeps` (build any env once) for the rweather Crypto sources.
