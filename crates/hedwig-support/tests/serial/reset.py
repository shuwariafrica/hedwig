"""esptool's reset into the bootloader through pyserial, as esp-pylib 1.1.5 writes it.

`set_rts` writes DTR again after every RTS change (`serial_reset.py:111-123`), and
`classic_bootloader_reset` is the sequence below (`serial_reset.py:296-329`); esptool uses it,
and only it, over RFC 2217 (`esptool/loader.py:843-853`). Prints what the board then said.
"""
import sys
import time

import serial

port = serial.serial_for_url(sys.argv[1], baudrate=115200, timeout=1)


def set_rts(state):
    port.rts = state
    port.dtr = port.dtr


port.dtr = False
set_rts(True)
time.sleep(0.1)
port.dtr = True
set_rts(False)
time.sleep(0.05)
port.dtr = False
time.sleep(0.5)
print(port.read(port.in_waiting or 1).decode(errors="replace").strip())
port.close()
