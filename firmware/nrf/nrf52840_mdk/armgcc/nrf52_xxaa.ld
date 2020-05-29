/* Linker script to configure memory regions. */

SEARCH_DIR(.)
GROUP(-lgcc -lc -lnosys)

MEMORY
{
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 0x100000
  RAM (rwx) :  ORIGIN = 0x20000008, LENGTH = 0x3FFF8
}


INCLUDE "nrf_common.ld"
