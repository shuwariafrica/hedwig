"""The remote's side of the serial suite: pyserial's own RFC 2217 client at the URL given."""
import sys
import time

import serial

port = serial.serial_for_url(sys.argv[1], baudrate=115200, timeout=3)
sent = b"hedwig\xff\xfeserial\xff"
port.write(sent)
print("echo", port.read(len(sent)) == sent)
port.baudrate = 921600
print("baud", port.baudrate)
for rts in (True, False):
    port.rts = rts
    time.sleep(0.3)
    print("rts", rts, "cts", port.cts)
for dtr in (True, False):
    port.dtr = dtr
    time.sleep(0.3)
    print("dtr", dtr, "dsr", port.dsr)
port.close()
print("closed")
