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
