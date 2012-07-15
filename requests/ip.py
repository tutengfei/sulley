from sulley import *

def crc16(data):
    crc = 0
    # Sum of 16 bit packets
    for i in range(len(data)):
        if i%2 == 0:
            crc += ord(data[i]) << 8
        else:
            crc += ord(data[i])


    crc = ((crc & 0xff0000) >> 16) + (crc & 0x00ffff)
    crc = crc ^ 0xffff

    strcrc = chr(crc >> 8) + chr(crc & 0xff)

    return strcrc

s_initialize("ip1")
# Ethernet
#s_binary("0xff ff ff ff ff ff", name="eth dst")
s_binary("0x00 80 ee 2a b3 21", name="eth dst")
s_binary("0x00 80 03 04 05 06", name="eth src")
s_binary("0x08 00", name="eth proto")

#IP
if s_block_start("ipfield1"):
    # 4 => IP version / 5 => Header length
    # FIXME : To be improved with 4 bits fields
    s_byte("\x45", name="version", fuzzable=True)
    # Same thing here, this Byte include the ECN flag
    s_byte("\x00", name="DSF", fuzzable=True)
    s_sizer('ipfield1', length=2, inclusive=True, fuzzable=True, name="size")
    s_word('\x42\x42', name="id")
    # FIXme : same here, need bit fields
    s_word('\x00\x00', name="flags")
    s_byte("\x40", name="TTL")
    s_byte("\x00", name="protocol")
    s_checksum("ipfield1", algorithm=crc16, length=2, name="chksum")
    #s_dword("\x0a\x01\x01\x01", name="ipsrc")
    s_dword("\x0a\x03\x4b\x0c", name="ipsrc")
    s_dword("\x0a\x03\x21\x01", name="ipdst")
s_block_end("ipfield1")

