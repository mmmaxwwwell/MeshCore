/*
 * Based on nrf54l15_linker_script_no_vpr.ld from lolren's nrf54-arduino-core 1.0.20, with the memory
 * map moved around andyshinn's nRF54_Bootloader (xiao_nrf54l15). The bootloader owns 0x0-0x8000, its
 * settings page at 0x14F000 and the s145 SoftDevice from 0x15A800, and keeps its DFU handoff in RAM
 * at 0x2003FF80-0x20040000 (above this script's RAM, which ends at 0x2003FE00).
 *
 * App:                     0x008000-0x080000  (480 KB)
 * LoRa OTA staging slot:   0x080000-0x0F8000  (480 KB, LoraOTANrf54.cpp)
 * LoRa OTA patch slot:     0x0F8000-0x116000  (120 KB)
 * LoRa OTA state, session: 0x116000-0x118000
 * InternalFS:              0x118000-0x147000  (188 KB, LFS_RRAM_BASE/SIZE in the variant)
 * Core persistence pages:  0x147000-0x14A000  (moved down from 0x17A000, inside the SoftDevice)
 *
 * Every L15 env uses this map, with or without LoRa OTA, so an update never moves InternalFS.
 *
 * Licensed under the Apache License 2.0
 */

ENTRY(Reset_Handler)

MEMORY
{
    FLASH (rx)       : ORIGIN = 0x00008000, LENGTH = 0x78000
    FLASH_ZIGBEE (r) : ORIGIN = 0x00147000, LENGTH = 0x1000
    FLASH_BOND_DB (r) : ORIGIN = 0x00148000, LENGTH = 0x1000
    FLASH_BOND (r)   : ORIGIN = 0x00149000, LENGTH = 0x1000
    RAM (rwx)        : ORIGIN = 0x20000000, LENGTH = 0x3FE00
}

/* The app region and the end of the image (code + rodata + the .data load image), for LoRa OTA. */
PROVIDE(__app_region_start = ORIGIN(FLASH));
PROVIDE(__app_region_end = ORIGIN(FLASH) + LENGTH(FLASH));

/* Stack size. Heap is not given a fixed size; it fills all RAM between
 * the end of static sections (.bss, .noinit) and the bottom of the stack. */
__stack_size__ = 4K;

/* Only nRF54L15-compiled objects may satisfy this link. */
PROVIDE(__nrf54_core_target_nrf54l15 = 0x4C313500);

/* Section Definitions */
SECTIONS
{
    /*
     * The startup code goes into FLASH
     */
    .isr_vector :
    {
        . = ALIGN(4);
        KEEP(*(.isr_vector))     /* Startup code */
        . = ALIGN(4);
    } >FLASH

    /*
     * The program code and other data goes into FLASH
     */
    .text :
    {
        . = ALIGN(4);
        *(.text)                 /* .text sections (code) */
        *(.text*)                /* .text* sections (code) */
        *(.glue_7)               /* glue arm to thumb code */
        *(.glue_7t)              /* glue thumb to arm code */
        *(.eh_frame)             /* exception handling */

        KEEP (*(.init))
        KEEP (*(.fini))

        . = ALIGN(4);
        _etext = .;              /* End of code section */
    } >FLASH

    /*
     * C/C++ runtime constructor/destructor tables.
     * __libc_init_array() consumes these symbols at startup.
     */
    .preinit_array :
    {
        . = ALIGN(4);
        PROVIDE_HIDDEN(__preinit_array_start = .);
        KEEP(*(.preinit_array))
        KEEP(*(.preinit_array*))
        PROVIDE_HIDDEN(__preinit_array_end = .);
        . = ALIGN(4);
    } >FLASH

    .init_array :
    {
        . = ALIGN(4);
        PROVIDE_HIDDEN(__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        PROVIDE_HIDDEN(__init_array_end = .);
        . = ALIGN(4);
    } >FLASH

    .fini_array :
    {
        . = ALIGN(4);
        PROVIDE_HIDDEN(__fini_array_start = .);
        KEEP(*(SORT(.fini_array.*)))
        KEEP(*(.fini_array))
        PROVIDE_HIDDEN(__fini_array_end = .);
        . = ALIGN(4);
    } >FLASH

    /*
     * Read-only data (constants, strings, etc.)
     */
    .rodata :
    {
        . = ALIGN(4);
        KEEP(*(.gnu.linkonce.r.nrf54_core_target_guard.*))
        *(.rodata)               /* .rodata sections (constants, strings, etc.) */
        *(.rodata*)              /* .rodata* sections */
        . = ALIGN(4);
    } >FLASH

    .zigbee_storage ORIGIN(FLASH_ZIGBEE) (NOLOAD) :
    {
        . = ALIGN(16);
        _szigbee_storage = .;
        KEEP(*(.zigbee_storage))
        KEEP(*(.zigbee_storage*))
        . = ALIGN(16);
        _ezigbee_storage = .;
    } >FLASH_ZIGBEE
    ASSERT(SIZEOF(.zigbee_storage) <= 0x1000,
           "Zigbee persistence exceeds its dedicated 4 KB page")

    .bond_db_storage ORIGIN(FLASH_BOND_DB) (NOLOAD) :
    {
        . = ALIGN(16);
        _sbond_db_storage = .;
        KEEP(*(.bond_db_storage))
        . = ALIGN(16);
        _ebond_db_storage = .;
    } >FLASH_BOND_DB
    ASSERT(SIZEOF(.bond_db_storage) <= 0x1000,
           "BLE multibond database exceeds its dedicated 4 KB page")

    /*
     * Reserved non-volatile storage area for bond persistence.
     * This region is excluded from normal code/data placement.
     */
    .bond_storage ORIGIN(FLASH_BOND) (NOLOAD) :
    {
        . = ALIGN(4);
        _sbond_storage = .;
        KEEP(*(.bond_base_storage))
        . = ALIGN(4);
    } >FLASH_BOND
    ASSERT(SIZEOF(.bond_storage) <= 0x50,
           "BLE base bond storage exceeds its stable 80-byte slot")

    .bond_cccd_storage ORIGIN(FLASH_BOND) + 0x50 (NOLOAD) :
    {
        . = ALIGN(4);
        KEEP(*(.bond_cccd_storage))
        . = ALIGN(4);
        _ebond_storage = .;
    } >FLASH_BOND
    ASSERT(SIZEOF(.bond_cccd_storage) <= 0x8C,
           "BLE CCCD storage exceeds its stable 140-byte slot")

    /*
     * Reserved non-volatile storage area for user Preferences key/value data.
     * Shares the dedicated FLASH_BOND page with bond storage.
     */
    .prefs_storage ORIGIN(FLASH_BOND) + 0xDC (NOLOAD) :
    {
        . = ALIGN(4);
        _sprefs_storage = .;
        KEEP(*(.prefs_storage))
        KEEP(*(.prefs_storage*))
        . = ALIGN(4);
        _eprefs_storage = .;
    } >FLASH_BOND
    ASSERT(SIZEOF(.prefs_storage) <= 0xAE0,
           "Preferences storage exceeds its stable 2784-byte slot")

    /*
     * Reserved non-volatile storage area for EEPROM emulation.
     * Shares the dedicated FLASH_BOND page with bond/prefs storage.
     */
    .eeprom_storage ORIGIN(FLASH_BOND) + 0xBBC (NOLOAD) :
    {
        . = ALIGN(4);
        _seeprom_storage = .;
        KEEP(*(.eeprom_storage))
        KEEP(*(.eeprom_storage*))
        . = ALIGN(4);
        _eeeprom_storage = .;
    } >FLASH_BOND
    ASSERT(SIZEOF(.eeprom_storage) <= 0x40C,
           "EEPROM storage exceeds its stable 1036-byte slot")

    .bond_signing_storage ORIGIN(FLASH_BOND) + 0xFC8 (NOLOAD) :
    {
        . = ALIGN(4);
        _sbond_signing_storage = .;
        KEEP(*(.bond_signing_storage))
        KEEP(*(.bond_signing_storage*))
        . = ALIGN(4);
        _ebond_signing_storage = .;
    } >FLASH_BOND
    ASSERT(SIZEOF(.bond_signing_storage) <= 0x38,
           "BLE signing extension exceeds the stable 56-byte slot")

    /*
     * ARM sections
     */
    .ARM.extab :
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } >FLASH

    .ARM :
    {
        __exidx_start = .;
        *(.ARM.exidx*)
        __exidx_end = .;
    } >FLASH

    /*
     * Initialized data sections into RAM, load from FLASH
     */
    .data :
    {
        . = ALIGN(4);
        _sdata = .;              /* Start of data section in RAM */
        *(.data)                 /* .data sections */
        *(.data*)                /* .data* sections */

        . = ALIGN(4);
        _edata = .;              /* End of data section in RAM */
    } >RAM AT>FLASH

    _sidata = LOADADDR(.data);   /* Start of data section in FLASH */
    PROVIDE(__app_image_end = _sidata + (_edata - _sdata));   /* LoRa OTA: last byte of the image + 1 */

    /*
     * Uninitialized data section into RAM
     */
    .bss :
    {
        . = ALIGN(4);
        _sbss = .;               /* Start of bss section */
        __bss_start__ = _sbss;
        *(.bss)
        *(.bss*)
        *(COMMON)

        . = ALIGN(4);
        _ebss = .;               /* End of bss section */
        __bss_end__ = _ebss;
    } >RAM

    /*
     * Non-initialized RAM section retained across reset paths where RAM power
     * is maintained. Startup code does not touch this section.
     */
    .noinit (NOLOAD) :
    {
        . = ALIGN(4);
        _snoinit = .;
        *(.noinit)
        *(.noinit*)
        . = ALIGN(4);
        _enoinit = .;
    } >RAM

    /*
     * Heap: grows upward from end of static sections to the bottom of the stack.
     * Stack: the startup code sets SP to __stack_start__ (top of RAM); the
     * linker symbol __stack_end__ marks the lowest safe stack address.
     */
    ._user_heap_stack :
    {
        . = ALIGN(8);
        PROVIDE ( __heap_start__ = . );
        PROVIDE ( end = . );
        PROVIDE ( _end = . );
        . = ORIGIN(RAM) + LENGTH(RAM) - __stack_size__;
        PROVIDE ( __heap_end__ = . );
        . = ALIGN(8);
    } >RAM
    /*
     * Symbols for startup code
     */
    __stack_start__ = ORIGIN(RAM) + LENGTH(RAM);
    __stack_end__ = __stack_start__ - __stack_size__;


    . = ALIGN(4);
}
