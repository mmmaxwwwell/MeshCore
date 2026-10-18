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
| `0x60` BEGIN | size u32, sha256[32], sig[64], chunk u8, [flags u8] | WORKING (12) while it checks the signature and stages; then status, session u32, chunk u8, chunks u16, accepted flags u8 |
| `0x61` DATA | session u32, index u16, bytes | none |
| `0x62` STATUS | session u32, from u16 | status, received u16, first_missing u16, bitmap[128] |
| `0x63` FINISH | session u32 | WORKING while it re-hashes; then status (OK: reboots in 6 s) |
| `0x64` ABORT | session u32 | status |
| `0x65` CONFIRM | none | status, was_pending u8, uptime_s u32, running sha256[0:8] |
| `0x66` RADIO | freq kHz u32, bw Hz u32, sf, cr, idle s u16 | status; applies 1.5 s later, reverts after `idle` s without OTA traffic |

BEGIN flags (offset 101): `0x02` LONG (slow mode, above). `0x01` is
reserved for delta images. The reply's flags byte echoes the flags the
target accepted; an older target sends no such byte, which reads as 0.

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
Requests are padded and size-checked like a real companion's. It needs
`.pio/libdeps` (build any env once) for the rweather Crypto sources.
