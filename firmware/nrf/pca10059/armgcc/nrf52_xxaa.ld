/* Linker script to configure memory regions. */

SEARCH_DIR(.)
GROUP(-lgcc -lc -lnosys)

MEMORY
{
  FLASH (rx) : ORIGIN = 0x00001000, LENGTH = 0xF7000
  RAM (rwx) :  ORIGIN = 0x20000008, LENGTH = 0x10000
}


INCLUDE "nrf_common.ld"
