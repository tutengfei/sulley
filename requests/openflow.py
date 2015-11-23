from sulley import *

s_initialize("openflow")
s_static("\x01")
s_static("\x10")
s_sizer("openflow_length", length=2, name="length", endian=">", fuzzable=False)
if s_block_start("openflow_length"):
    s_dword(0xfffffffc)
    s_dword(0x00000000)
s_block_end()