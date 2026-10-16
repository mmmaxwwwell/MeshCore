# L1 companion emulation (Renode + Android emulator)

Runs the **real** MeshCore companion firmware with the **real** S140 7.3.0 SoftDevice
on an emulated nRF52840 (Renode), and the **stock MeshCore Android app** in the Android
emulator, joined over emulated BLE. Nothing in the firmware is faked except what a
board would supply: the build is `WioTrackerL1_companion_radio_ble_5k_emu`.

```
 MeshCore app ── Android BT stack ── netsim ──► hcishim.py ──► PTY ──► Zephyr hci_uart
 (emulator)                          (grpc, localhost)                (Renode node "ctrl")
                                                                            │ emulated air
                                                       S140 + MeshCore firmware (node "nodeN")
```

Proven 2026-10-16: pairing with PIN, companion protocol, and a **5000-contact sync**
(app shows "Search 5000 Contacts"; ~27 contacts/s, ~3 min).

## Use

```bash
emu/run.sh render                 # once (and after editing src/): templates -> local/
emu/run.sh build-renode           # once: pinned Renode + patch (skip if local/emu/renode-src exists)
pio run -e WioTrackerL1_companion_radio_ble_5k_emu
emu/run.sh air node1              # foreground; background it. More nodes: air node1 node2
emu/run.sh android                # HCI shim + Android emulator (headless), waits for BT ON
emu/run.sh connect node1          # app: Connect -> node -> PIN pairing
```

Per node, under `local/emu/`: `<n>-cdc.log` (everything the firmware prints on USB
serial), `<n>-ficr.bin` (synthetic, from the name: stable BLE address), `<n>-qspi.img`
(external flash, autosaved; delete to start blank). Internal flash starts blank, so the
firmware mints a fresh identity on first boot. The `_emu` build seeds 5000 synthetic
contacts into an empty store (`EMU_SEED_CONTACTS`), ~2 min of device time.

Speed: about real time for one node. The app's timeouts are real time, so a slow host
shows up as GATT/SMP timeouts.

## Inputs (not in git: `local/` is ignored)

- `local/emu/s140_7.3.0_mbr_sd.hex`: MBR + S140 7.3.0 (from the Adafruit nRF52
  bootloader's `pca10100` release hex, FWID 0x0123).
- `local/emu/zephyr-hci-uart.elf`: Zephyr `samples/bluetooth/hci_uart` for
  `nrf52840dk/nrf52840` (UART1 = HCI, 1 Mbaud).
- `local/android/meshcore.apk`: the app (author's release, v1.50.0 tested).
- `local/android/avd/mc.avd`: `avdmanager create avd -n mc -k
  "system-images;android-35;default;x86_64" -d pixel_6` with the env from
  `local/android/env.sh` (AOSP image, no Google Play; SDK from `src/android/sdk.nix`).

Never put a real radio's dumps (internal flash with its private key, its FICR) in
here; a real identity on the emulated air is a clone of that radio.

## What had to be modelled or fixed in Renode (`src/emu/renode-nrf52-ble.patch`)

| Piece | Why |
|---|---|
| PPI tasks synchronous | deferred task writes made TIMER0 CAPTURE0 (radio DISABLED) land after the SoftDevice read it: SD assert at 0x187CE |
| CCM (+AAR) model | link encryption; MeshCore's characteristics need an encrypted MITM link |
| Radio device-address match (DAB/DAP/DEVMATCH) | Zephyr's initiator filters on the accept list with it; Android connects with the accept list |
| Radio: stale RX frames dropped | a frame that arrived while not listening was delivered at a later RX start, on any channel: Zephyr answered a 65 ms old ADV_IND with a CONNECT_IND |
| Radio timing per MODE (2M/coded) | 1M timing was hard-coded |
| QSPI + P25Q16H model | external flash (littlefs contact store), image backed |
| SX1262 model (SPIM3, NSS/RESET/DIO1) | RadioLib init, TX, RX, CAD; every SX1262 in one Renode shares one LoRa "air" |
| SAADC model | `analogRead` (battery) spun forever on a missing peripheral |
| USBD ready, VBUS, RTC tick timer, TIMER SHUTDOWN, comparing-timer clamp | earlier boot blockers |

Firmware-side stand-ins, all done by the emulator (`mcnode.sh`), not the firmware:
CC310 ECDH/keygen hooks (`cc310_hooks.py`, real P-256 on the host), USB CDC output
captured by hooking `Adafruit_USBD_CDC::write`, and tickless idle replaced by
`wfi; bx lr` (a Python hook there ran on every idle pass: 12x slower than real time).

## Android side (`src/emu/host/hcishim.py`)

The Zephyr controller is LE-only; Android's stack aborts on a controller without
BR/EDR answers (READ_LOCAL_NAME, READ_LOCAL_EXTENDED_FEATURES, READ_BUFFER_SIZE, SSP
bit). The shim answers those locally (never forwarding them: a 244-byte
WRITE_EXTENDED_INQUIRY_RESPONSE once wedged the controller's UART parser) and passes
all LE traffic through. Bumble's netsim server binds localhost only.

Every emulated node with the same FICR has the same address: `connect` clears
Android's bonds first (`adb root`, AOSP userdebug image).
