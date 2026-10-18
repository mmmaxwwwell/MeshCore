#!/usr/bin/env python3
"""Legacy Nordic BLE DFU (SDK 11, what the Adafruit nRF52 bootloader speaks) over BlueZ via bleak.

For an nRF52 MeshCore node told `start ota` (the app then advertises the DFU
service; this tool makes it reboot into the bootloader's BLE DFU mode and
sends the image there). Package = the build's DFU zip (firmware.zip from
`pio run`): manifest.json + application .bin + .dat init packet.

  ble_dfu.py <ble-address> <firmware.zip> [--bootloader]   (BlueZ default adapter)

The bootloader checks the init packet (device type, SoftDevice requirement)
before it takes the image. A failed or unactivated transfer leaves the node in
the bootloader's DFU mode, advertising "AdaDFU" (no USB there): rerun with
--bootloader to retry.
"""
import argparse, asyncio, json, struct, sys, zipfile

from bleak import BleakClient, BleakScanner

SVC = "00001530-1212-efde-1523-785feabcd123"
CP = "00001531-1212-efde-1523-785feabcd123"
PKT = "00001532-1212-efde-1523-785feabcd123"

OP_START, OP_INIT, OP_RECV, OP_VALIDATE, OP_ACTIVATE, OP_PRN, OP_RESP, OP_PRN_NOTIF = 1, 2, 3, 4, 5, 8, 0x10, 0x11
IMG_APP = 0x04
PRN = 10          # packets between receipt notifications
CHUNK = 20        # legacy DFU packet size


def load(path):
    z = zipfile.ZipFile(path)
    app = json.loads(z.read("manifest.json"))["manifest"]["application"]
    return z.read(app["bin_file"]), z.read(app["dat_file"])


class Dfu:
    def __init__(self, client):
        self.c = client
        self.q = asyncio.Queue()

    async def start(self):
        await self.c.start_notify(CP, lambda _, d: self.q.put_nowait(bytes(d)))

    async def cp(self, data, response=True):
        await self.c.write_gatt_char(CP, bytes(data), response=response)

    async def expect(self, op, timeout=60):
        while True:
            d = await asyncio.wait_for(self.q.get(), timeout)
            if d[0] == OP_RESP and d[1] == op:
                if d[2] != 1:
                    raise SystemExit(f"DFU op {op} failed: status {d[2]}")
                return
            if d[0] == OP_PRN_NOTIF:
                continue
            print(f"  (notification {d.hex()})")

    async def receipt(self, timeout=30):
        while True:
            d = await asyncio.wait_for(self.q.get(), timeout)
            if d[0] == OP_PRN_NOTIF:
                return struct.unpack_from("<I", d, 1)[0]
            if d[0] == OP_RESP:
                raise SystemExit(f"unexpected response during transfer: {d.hex()}")


async def find(addr, name_hint=None, timeout=30):
    dev = await BleakScanner.find_device_by_address(addr, timeout=timeout)
    if dev is None and name_hint:
        dev = await BleakScanner.find_device_by_name(name_hint, timeout=timeout)
    return dev


def addr_plus_one(addr):
    n = int(addr.replace(":", ""), 16) + 1
    h = f"{n & 0xFFFFFFFFFFFF:012X}"
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("address")
    ap.add_argument("package")
    ap.add_argument("--bootloader", action="store_true",
                    help="the node is already in the bootloader's DFU mode (advertises AdaDFU)")
    a = ap.parse_args()
    image, init = load(a.package)
    print(f"image {len(image)} bytes, init packet {len(init)} bytes")

    if not a.bootloader:
        await to_bootloader(a.address)
    await send(a.address, image, init)


async def to_bootloader(address):
    dev = await find(address)
    if dev is None:
        raise SystemExit(f"{address} not advertising (did `start ota` run?)")
    async with BleakClient(dev, timeout=30) as c:
        names = {ch.uuid for s in c.services for ch in s.characteristics}
        print(f"connected to {address}: {'DFU service' if CP in names else 'NO DFU service'}")
        if CP not in names:
            raise SystemExit("no legacy DFU control point")
        # In the app (buttonless), START tells it to reboot into the bootloader's OTA mode.
        in_bootloader = PKT in names and any(s.uuid == SVC and len(s.characteristics) >= 3 for s in c.services)
        d = Dfu(c)
        await d.start()
        try:
            await d.cp([OP_START, IMG_APP])
        except Exception as e:   # the app resets on this write; a lost reply is normal
            print(f"  (start write: {e.__class__.__name__})")
        try:
            await asyncio.wait_for(d.q.get(), 3)
        except asyncio.TimeoutError:
            pass
        if not in_bootloader:
            print("app is rebooting into the bootloader")

    await asyncio.sleep(3)


async def send(address, image, init):
    # the bootloader advertises on the same address (Adafruit) or address+1 (Nordic stock)
    dev = await find(address, timeout=20) or await find(addr_plus_one(address), "AdaDFU", timeout=20)
    if dev is None:
        raise SystemExit("bootloader not found after the reboot")
    print(f"bootloader at {dev.address} ({dev.name})")
    async with BleakClient(dev, timeout=30) as c:
        d = Dfu(c)
        await d.start()
        await d.cp([OP_START, IMG_APP])
        await c.write_gatt_char(PKT, struct.pack("<III", 0, 0, len(image)), response=False)
        print("start: waiting for the bootloader to prepare (erase) ...")
        await d.expect(OP_START, timeout=120)

        await d.cp([OP_INIT, 0x00])
        await c.write_gatt_char(PKT, init, response=False)
        await d.cp([OP_INIT, 0x01])
        await d.expect(OP_INIT)
        print("init packet accepted")

        await d.cp([OP_PRN, PRN & 0xFF, PRN >> 8])
        await d.cp([OP_RECV])
        sent = 0
        t0 = asyncio.get_running_loop().time()
        n = 0
        while sent < len(image):
            part = image[sent:sent + CHUNK]
            await c.write_gatt_char(PKT, part, response=False)
            sent += len(part)
            n += 1
            if n % PRN == 0 and sent < len(image):
                got = await d.receipt()
                if got != sent:
                    raise SystemExit(f"bootloader has {got} bytes, sent {sent}")
                if n % (PRN * 200) == 0:
                    dt = asyncio.get_running_loop().time() - t0
                    print(f"  {sent}/{len(image)} bytes, {sent / dt / 1024:.1f} KiB/s", flush=True)
        await d.expect(OP_RECV, timeout=60)
        print(f"image received in {asyncio.get_running_loop().time() - t0:.0f} s")
        await d.cp([OP_VALIDATE])
        await d.expect(OP_VALIDATE, timeout=60)
        print("image validated; activating")
        try:   # the control point takes acknowledged writes only; the bootloader resets on this one
            await d.cp([OP_ACTIVATE], response=True)
        except Exception as e:
            print(f"  (activate write: {e.__class__.__name__}, normal when it resets at once)")
    print("done: the node boots the new image")


if __name__ == "__main__":
    asyncio.run(main())
