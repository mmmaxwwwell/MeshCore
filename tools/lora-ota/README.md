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
```

Notes:
- **Companion targets** take OTA requests only from radios they have
  favourited. **Repeater targets** need the admin password.
- Rhea is owned by titan's `meshcore-gateway`. To send *from* Rhea, run the
  tool on titan with the gateway and both its sockets stopped. When Rhea
  *receives*, the gateway can stay up; it reconnects after the reboot.
- `--fast freq,bw,sf,cr` picks the transfer channel (default `919.0,500,5,5`,
  inside US 902–928 and clear of the MeshCore and Meshtastic presets).
  `--slow` stays on the mesh settings and works across hops, but takes about
  80 min of the shared channel for an ESP32 image.
- The sender keeps the companion's own settings: radio, tuning, and the
  client-repeat flag. Note that `set_radio` without that flag turns repeat
  off and saves it. Ctrl-C restores them too.
- An interrupted push can be re-run: it finds the target on the transfer
  channel if it is still there, and resumes the same session within 5 min.
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

### Protocol (REQ payload, little endian; replies after the 4-byte tag)

| Type | Request | Reply |
|---|---|---|
| `0x60` BEGIN | size u32, sha256[32], sig[64], chunk u8 | WORKING (12) while it checks the signature and stages; then status, session u32, chunk u8, chunks u16 |
| `0x61` DATA | session u32, index u16, bytes | none |
| `0x62` STATUS | session u32, from u16 | status, received u16, first_missing u16, bitmap[128] |
| `0x63` FINISH | session u32 | WORKING while it re-hashes; then status (OK: reboots in 6 s) |
| `0x64` ABORT | session u32 | status |
| `0x65` CONFIRM | none | status, was_pending u8, uptime_s u32, running sha256[0:8] |
| `0x66` RADIO | freq kHz u32, bw Hz u32, sf, cr, idle s u16 | status; applies 1.5 s later, reverts after `idle` s without OTA traffic |

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
| `repeat` | on/off | repeater |
| `regions` | `ct,northeast,east,*`: each region exists (under `*`) with flood allowed. Additive: nothing is removed or denied | repeater |

Never on the list: passwords (admin, guest), the private key, the signing
key, name, location, owner info, bridge settings, power saving, Wi-Fi, BLE
PIN, contacts and telemetry policy, and anything about OTA itself. A
companion refuses repeater keys (`this node has no such setting`); with
client repeat on, it also refuses a `radio` outside the client-repeat bands.

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
   no firmware BEGIN while a bundle is on probation, and no second bundle
   until the first is confirmed or reverted.

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

Repeater CLI (admin): `ota settings` (version, pending, seconds left),
`ota settings confirm`, `ota settings revert`.

### Protocol (REQ payload, little endian; replies after the 4-byte tag)

| Type | Request | Reply |
|---|---|---|
| `0x67` SET_DATA | total u16, offset u16, n u8, bytes | status, have u16 (contiguous bytes held) |
| `0x68` SET_APPLY | total u16, sha256(bundle)[0:8] | WORKING (12) while it checks; then status, version u32, secs_left u16 |
| `0x69` SET_CTRL | op u8: 0 STATUS, 1 CONFIRM, 2 REVERT | status, pending u8 (2 = radio switch still to come), was u8, version u32, pending_version u32, secs_left u16 |
| `0x69` SET_CTRL | op 3 GET, start u8 | status, next u8 (0xFF = end), `key=value\n` text |

Bundle: `body || sig[64]`, at most 512 bytes; body = version u32, target kind
u8 (1 = public key prefix, 2 = board tag), target length u8, target, count u8,
then per entry key length u8, key, value length u8, value (ASCII, as the CLI
takes it).

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
Requests are padded and size-checked like a real companion's. It needs
`.pio/libdeps` (build any env once) for the rweather Crypto sources.
