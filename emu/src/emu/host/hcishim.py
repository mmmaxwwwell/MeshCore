# HCI shim: Android emulator (netsim, controller mode) <-> LE-only Zephyr
# controller (Renode PTY). Android's stack assumes a dual-mode controller and
# restarts when BR/EDR commands come back UNKNOWN_HCI_COMMAND; this rewrites
# those Command Status rejections into a successful Command Complete with
# plausible return parameters. Everything else passes through untouched.
#
# usage: hcishim.py <android-netsim transport> <controller transport>
import asyncio, logging, struct, sys, time
logging.basicConfig(level=logging.WARNING)
logging.getLogger('bumble.transport.android_netsim').setLevel(logging.DEBUG)
from bumble.transport import open_transport

NAME = b'EmuCtrl'.ljust(248, b'\0')
RET = {  # opcode -> return parameters after the status byte
    0x0C14: NAME,                        # READ_LOCAL_NAME
    0x0C23: b'\x0c\x02\x5a',             # READ_CLASS_OF_DEVICE
    0x0C19: b'\x00',                     # READ_SCAN_ENABLE
    0x0C17: struct.pack('<H', 0x2000),   # READ_PAGE_TIMEOUT
    0x0C45: b'\x00',                     # READ_INQUIRY_MODE
    0x0C55: b'\x01',                     # READ_SIMPLE_PAIRING_MODE
    0x0C58: b'\x00',                     # READ_INQUIRY_RESPONSE_TX_POWER_LEVEL
    0x0C6C: b'\x01\x00',                 # READ_LE_HOST_SUPPORT
    0x080E: struct.pack('<H', 0),        # READ_DEFAULT_LINK_POLICY_SETTINGS
    0x0C38: b'\x00',                     # READ_NUMBER_OF_SUPPORTED_IAC
    0x0C39: b'\x01\x33\x8b\x9e',         # READ_CURRENT_IAC_LAP
    0x0C1B: struct.pack('<HH', 0x800, 0x12),  # READ_PAGE_SCAN_ACTIVITY
    0x0C1D: struct.pack('<HH', 0x1000, 0x12), # READ_INQUIRY_SCAN_ACTIVITY
    0x0C0D: struct.pack('<HH', 0, 0),    # READ_STORED_LINK_KEY
    0x0C66: b'\x00',                     # READ_DEFAULT_ERRONEOUS_DATA_REPORTING
    0x1005: struct.pack('<HBHH', 251, 0, 8, 0),  # READ_BUFFER_SIZE (ACL len, SCO len, ACL num, SCO num)
    0x0C2D: b'\x00\x00\x00',             # READ_TRANSMIT_POWER_LEVEL (handle, level)
    0x0C79: b'\x01',                     # READ_SECURE_CONNECTIONS_HOST_SUPPORT
}

LAST_PARAMS = {}         # opcode -> parameters of the last command sent
LMP_PAGE0 = [bytes(8)]   # filled from the controller's READ_LOCAL_SUPPORTED_FEATURES

def ret_for(opcode):
    if opcode == 0x1004:  # READ_LOCAL_EXTENDED_FEATURES: page, max page, 8 feature bytes
        page = LAST_PARAMS.get(opcode, b'\0')[:1] or b'\0'
        feats = LMP_PAGE0[0] if page[0] == 0 else (b'\x03' + bytes(7) if page[0] == 1 else bytes(8))
        return page + b'\x01' + feats
    return RET.get(opcode, b'')

def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)

# BR/EDR-only commands Zephyr's LE-only controller rejects: answered here and
# never forwarded (a 244-byte WRITE_EXTENDED_INQUIRY_RESPONSE once wedged the
# controller's UART HCI parser).
LOCAL = set(RET) | {0x0C6D, 0x0C14, 0x1004, 0x1005, 0x0C56, 0xFD53, 0x080F, 0x0C24,
                    0x0C18, 0x0C13, 0x0C26, 0x0C1E, 0x0C1A, 0x0C1C, 0x0C52, 0x0C7A,
                    0x0C45, 0x0C43, 0x0C33, 0x0C0A, 0x0C16}
HOST_SINK = [None]

def local_complete(opcode):
    params = b'\x01' + struct.pack('<H', opcode) + b'\x00' + ret_for(opcode)
    return bytes([0x04, 0x0E, len(params)]) + params

class Pipe:
    def __init__(self, name, out, rewrite):
        self.name, self.out, self.rewrite = name, out, rewrite
    def on_packet(self, pkt):
        pkt = bytes(pkt)
        if self.rewrite:
            pkt = self.rewrite(pkt)
            if pkt is None:
                return
        self.out.on_packet(pkt)

def to_host(pkt):
    # H4 event: 04 code len ...
    if len(pkt) >= 7 and pkt[0] == 0x04 and pkt[1] == 0x0F and pkt[3] == 0x01:
        ncmd = pkt[4]
        opcode = pkt[5] | pkt[6] << 8
        ret = ret_for(opcode)
        params = bytes([ncmd]) + struct.pack('<H', opcode) + b'\x00' + ret
        log(f'fake complete for unknown opcode 0x{opcode:04X} ({len(ret)} ret bytes)')
        return bytes([0x04, 0x0E, len(params)]) + params
    if len(pkt) >= 15 and pkt[0] == 0x04 and pkt[1] == 0x0E and (pkt[4] | pkt[5] << 8) == 0x1003 and pkt[6] == 0:
        # claim Secure Simple Pairing (byte 6 bit 3): Android's stack refuses
        # a controller without it, even though only LE is ever used here
        f = bytearray(pkt[7:15]); f[6] |= 0x08
        LMP_PAGE0[0] = bytes(f)
        log('controller LMP features page 0 (SSP added):', LMP_PAGE0[0].hex())
        pkt = pkt[:7] + LMP_PAGE0[0] + pkt[15:]
    if len(pkt) >= 7 and pkt[0] == 0x04 and pkt[1] == 0x0E and pkt[6] != 0:
        opcode = pkt[4] | pkt[5] << 8
        log(f'controller error 0x{pkt[6]:02X} for opcode 0x{opcode:04X}')
    return pkt

def to_ctrl(pkt):
    if pkt[0] == 0x01 and len(pkt) >= 3:
        opcode = pkt[1] | pkt[2] << 8
        LAST_PARAMS[opcode] = pkt[4:]
        log(f'cmd 0x{opcode:04X} {pkt[4:20].hex()}')
        if opcode in LOCAL:
            log(f'local complete for 0x{opcode:04X}')
            HOST_SINK[0].on_packet(local_complete(opcode))
            return None
    return pkt

async def main(host_spec, ctrl_spec):
    async with await open_transport(ctrl_spec) as (csrc, csnk):
        async with await open_transport(host_spec) as (hsrc, hsnk):
            HOST_SINK[0] = hsnk
            hsrc.set_packet_sink(Pipe('h2c', csnk, to_ctrl))
            csrc.set_packet_sink(Pipe('c2h', hsnk, to_host))
            log('bridging', host_spec, '<->', ctrl_spec)
            await asyncio.Event().wait()

asyncio.run(main(sys.argv[1], sys.argv[2]))
