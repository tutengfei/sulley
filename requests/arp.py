from sulley import *

s_initialize("arp")
s_binary("0xff ff ff ff ff ff")
s_binary("0x01 02 03 04 05 06")
s_binary("0x08 06")

s_binary("0x00 01") #/* Hardware Type -> here Ethernet (1)*/
s_binary("0x08 00") #/* Protocol Type -> here IP (8) */
s_binary("0x06") #/* Hardware size -> here MAC (48Bit /6Byte) */
s_binary("0x04") #/* Protocol Size -> here IP (32Bit /4Byte) */
s_binary("0x00 01") #/* Opcode (1->request, 2->reply) */
s_binary("0x01 02 03 04 05 06") #/* MAC-Src */
s_binary("0xc0 a8 5f b5") #/* IP-Src */
s_binary("0x00 00 00 00 00 00") #/* MAC-Dst */
s_binary("0xc0 a8 5f b6") #/* IP-Dst */
s_random(0x0000, 1, 5)


s_initialize("arp2")
s_binary("0xff ff ff ff ff ff")
s_binary("0x01 02 03 04 05 06")
s_binary("0x08 06")

#s_block_start("arp", alt_mutate=True)
s_block_start("arp")
s_word(0x0001, endian='>') #/* Hardware Type -> here Ethernet (1)*/
s_word(0x0800, endian='>') #/* Protocol Type -> here IP (8) */
s_byte(0x06) #/* Hardware size -> here MAC (48Bit /6Byte) */
s_byte(0x04) #/* Protocol Size -> here IP (32Bit /4Byte) */
s_word(0x0001, endian='>') #/* Opcode (1->request, 2->reply) */
s_word(0x0102, endian='>')
s_word(0x0304, endian='>')
s_word(0x0506, endian='>') #/* MAC-Src */
s_word(0xc0a8, endian='>')
s_word(0x5fb5, endian='>') #/* IP-Src */
s_word(0x0000, endian='>')
s_word(0x0000, endian='>')
s_word(0x0000, endian='>') #/* MAC-Dst */
s_word(0xc0a8, endian='>')
s_word(0x5fb6, endian='>') #/* IP-Dst */
s_random(0x0000, 1, 5)
s_block_end("arp")


s_initialize("arp3")
# Destination address
s_binary("0xff ff ff ff ff ff")
#Source address
s_binary("0x01 02 03 04 05 06")
# Type : ARP
s_binary("0x08 06")

# ARP Packet
s_word("\x00\x01", fuzzable=True) #/* Hardware Type -> here Ethernet (1)*/
s_word("\x08\x00", fuzzable=False) #/* Protocol Type -> here IP (8) */
s_byte("\x06", fuzzable=False) #/* Hardware size -> here MAC (48Bit /6Byte) */
s_byte("\x04", fuzzable=False) #/* Protocol Size -> here IP (32Bit /4Byte) */
s_word("\x00\x01", fuzzable=False) #/* Opcode (1->request, 2->reply) */

# MAC Src Address
s_dword("\x01\x02\x03\x04", fuzzable=True)
s_word("\x05\x06", fuzzable=True) #/* MAC-Src */
s_dword("\x0a\x01\x01\x01", fuzzable=False) #/* IP-Src */
s_binary("0x00 00 00 00 00 00") #/* MAC-Dst */
s_dword("\x0a\x01\x01\x02", fuzzable=False) #/* IP-Dst */
s_random(0x0000, 1, 5, fuzzable=False)



