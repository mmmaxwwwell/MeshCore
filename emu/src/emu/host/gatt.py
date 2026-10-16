import asyncio, os, sys
from bumble.device import Device, Peer
from bumble.transport import open_transport
from bumble.hci import Address
from bumble.pairing import PairingConfig, PairingDelegate

NUS_RX = '6E400002-B5A3-F393-E0A9-E50E24DCCA9E'
NUS_TX = '6E400003-B5A3-F393-E0A9-E50E24DCCA9E'

class Kbd(PairingDelegate):
    def __init__(self): super().__init__(io_capability=PairingDelegate.IoCapability.KEYBOARD_INPUT_ONLY)
    async def get_number(self): print('passkey requested -> 123456', flush=True); return 123456

async def main(transport, target, pair):
    async with await open_transport(transport) as (src, snk):
        dev = Device.with_hci('bumble', Address('F0:F1:F2:F3:F4:F5'), src, snk)
        dev.pairing_config_factory = lambda conn: PairingConfig(sc=True, mitm=True, bonding=True, delegate=Kbd())
        await dev.power_on()
        print('connecting', flush=True)
        conn = await asyncio.wait_for(dev.connect(Address(target, Address.RANDOM_DEVICE_ADDRESS)), 60)
        print('connected', conn, flush=True)
        if os.environ.get('PHY2M'):
            from bumble.hci import HCI_LE_2M_PHY
            await conn.set_phy(tx_phys=[HCI_LE_2M_PHY], rx_phys=[HCI_LE_2M_PHY])
            await asyncio.sleep(3)
            print('phy:', await conn.get_phy(), flush=True)
        peer = Peer(conn)
        await asyncio.wait_for(peer.discover_services(), 60)
        for s in peer.services:
            await s.discover_characteristics()
            print('service', s.uuid, flush=True)
            for c in s.characteristics: print('   char', c.uuid, c.properties, flush=True)
        if pair:
            print('pairing', flush=True)
            await asyncio.wait_for(conn.pair(), 120)
            print('paired, encrypted=', conn.is_encrypted, flush=True)
            rx = peer.get_characteristics_by_uuid(NUS_RX)[0]; tx = peer.get_characteristics_by_uuid(NUS_TX)[0]
            got = asyncio.get_running_loop().create_future()
            await tx.subscribe(lambda v: got.done() or got.set_result(bytes(v)))
            await rx.write_value(b'hello-emu', with_response=False)
            print('echo:', await asyncio.wait_for(got, 60), flush=True)
        await conn.disconnect()

asyncio.run(main(sys.argv[1], sys.argv[2], len(sys.argv) > 3))
