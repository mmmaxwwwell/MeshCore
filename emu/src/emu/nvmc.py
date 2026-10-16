# nRF52840 NVMC, minimal: always READY, CONFIG stored, page/all erase fill flash with 0xFF.
# (Writes to flash itself land directly in Renode's mapped flash memory.)
try:
    regs
except NameError:
    regs = {}
    from System import Array, Byte
    from Antmicro.Renode.Core import EmulationManager
    def _bus():
        return list(EmulationManager.Instance.CurrentEmulation.Machines)[0].SystemBus
    def _erase(addr, length):
        _bus().WriteBytes(Array[Byte]([0xFF] * length), addr)
if request.IsRead:
    off = request.Offset
    request.Value = 1 if off in (0x400, 0x408) else regs.get(off, 0)
elif request.IsWrite:
    off = request.Offset
    regs[off] = request.Value
    if off in (0x508, 0x510):            # ERASEPAGE / ERASEPCR0: address of the page
        _erase(request.Value & ~0xFFF, 0x1000)
    elif off == 0x50C and request.Value == 1:   # ERASEALL
        _erase(0, 0x100000)
