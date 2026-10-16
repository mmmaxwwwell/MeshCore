# nRF52840 MWU (Memory Watch Unit), minimal: a register file where REGIONEN (0x510)
# follows REGIONENSET (0x514, write-1-to-set) and REGIONENCLR (0x518, write-1-to-clear),
# and the SET/CLR registers read back REGIONEN, as on the chip. No watch events are raised.
try:
    regs
except NameError:
    regs = {}
if request.IsRead:
    off = request.Offset
    request.Value = regs.get(0x510, 0) if off in (0x510, 0x514, 0x518) else regs.get(off, 0)
elif request.IsWrite:
    off = request.Offset
    if off == 0x514:
        regs[0x510] = regs.get(0x510, 0) | request.Value
    elif off == 0x518:
        regs[0x510] = regs.get(0x510, 0) & ~request.Value & 0xFFFFFFFF
    else:
        regs[off] = request.Value
