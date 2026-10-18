# Firmware over LoRa (ESP32 repeaters)

Sends a signed firmware image to a repeater over the LoRa link itself, through
any companion radio, with automatic rollback. Design and decisions:
`~/git/homelab/docs/build-notes/meshcore-lora-ota-plan.md`.

## How it works

1. The sender logs in to the repeater as admin through a companion (USB or BLE)
   and checks `ota status` (board tag, not pending).
2. `tempradio 919.0 500 5 5 <mins>` moves the repeater to a private fast
   channel. The companion follows. The repeater falls back to its own settings
   by itself when the timer ends, so a dead laptop can't strand it.
3. BEGIN carries size, SHA-256 and an ed25519 signature. The repeater checks
   the signature against the key compiled into it (`LORA_OTA_PUBKEY`) and
   its own board tag (`LORA_OTA_BOARD`), then erases its spare OTA partition.
4. 156-byte DATA chunks stream without per-chunk acks. STATUS returns a bitmap
   of what's missing, and the sender resends only that. A broken link can
   resume: a new push of the same image continues the same session.
5. When the node has every chunk it says so. On FINISH it reads the image
   back and checks the SHA-256 and the LoRa-OTA marker. If those pass, it sets
   the image as the boot image, answers "checksum good, rebooting" and reboots
   6 s later.
6. The new image boots on probation. The sender switches the companion back
   to the mesh settings and sends CONFIRM (a binary request; no new login,
   since the node keeps its admin list in flash) until the REBOOTED node
   answers. Uptime in the reply tells the new image from the old one. **No
   CONFIRM within 60 s of boot, or a crash or hang before one: the bootloader
   goes back to the old image.**

Every request is an admin REQ datagram (encrypted, MAC'd), so only an admin
can run a session. The signature means an admin password alone cannot install
code: you also need the signing key.

## Use

```sh
S='nix shell --impure --expr "with import <nixpkgs> {}; [ (python3.withPackages (p: [ p.cryptography ])) ]" -c'
python3 tools/lora-ota/lora_ota.py keygen     # once; key at ~/.config/meshcore/ota-signing.key
python3 tools/lora-ota/lora_ota.py pubkey     # goes in -D LORA_OTA_PUBKEY of the *_lora_ota envs

pio run -e heltec_v4_repeater_lora_ota
python3 tools/lora-ota/lora_ota.py sign .pio/build/heltec_v4_repeater_lora_ota/firmware.bin --board heltec_v4_repeater

# push needs the meshcore lib too (homelab: the pinned pkgs/python-meshcore)
python3 tools/lora-ota/lora_ota.py push --companion E2:7D:69:21:47:AA --target Quartz \
    --password-file ~/.config/meshcore/quartz-admin-password \
    .pio/build/heltec_v4_repeater_lora_ota/firmware.bin
```

Notes:
- Sign the app-only `firmware.bin`, never the merged USB image.
- `--fast freq,bw,sf,cr` picks the transfer channel (default `919.0,500,5,5`,
  inside US 902–928 and clear of the MeshCore and Meshtastic presets).
- `--slow` stays on the mesh settings and works across hops, but takes about
  80 min of the shared channel for an ESP32 image.
- `status` sends `ota status`. `confirm [--wait 70]` keeps sending CONFIRM, which is how you
  confirm a first LoRa-OTA build installed by WiFi OTA (no password needed: it uses the
  earlier login).

Repeater CLI (admin): `ota status`, `ota confirm`, `ota rollback` (only while
pending).

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
after signing, resume after a dropped link, and the confirm timing (only an
answer from the rebooted image counts). It needs `.pio/libdeps` (build
any env once) for the rweather Crypto sources.
