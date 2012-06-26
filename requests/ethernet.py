from sulley import *

s_initialize("ethernet")
# Dest address
s_dword("\xff\xff\xff\xff", fuzzable = True)
# Source address
s_dword("\xff\xff\xff\xff", fuzzable = True)
# Type
s_word("\x08\x06", fuzzable = True)
# Data
s_random(0x0000, 1, 5)


