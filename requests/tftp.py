from sulley import *


s_initialize("tftp_standard")
s_group("opcode", values=["\x00\x01","\x00\x02","\x00\x03","\x00\x04","\x00\x05"])
if s_block_start("filerequest", group="opcode"):
    # filename
    s_string("foo bar")
            # terminator
    s_static("\x00")
            # transfertype
    s_group("transfertype", values=["netascii","octet","mail","abcdabcd"])
    s_block_end("filerequest")

s_initialize("tftp_random")
if s_block_start("randompacket"):
    #op code
    s_short("\x00\x01")
    # string
    s_string("foobar")
    s_delim("\x00")
    s_string("octet")
    s_delim("\x00")
    s_block_end("randompacket")

# TODO : encoder

s_initialize("tftp_read_octet")
if s_block_start("read_rrq"):
    s_static("\x00\x01")
    s_string("uname.txt")
    s_static("\x00")
    s_static("octet")
    s_static("\x00")
    s_block_end("read_rrq")

s_initialize("tftp_read_octet_blksize")
if s_block_start("read_rrq"):
    s_static("\x00\x01")
    s_string("uname.txt")
    s_static("\x00")
    s_static("octet")
    s_static("\x00")
    s_string("blksize")
    s_static("\x00")
    s_double(754, format="ascii")
    s_static("\x00")
    s_block_end("read_rrq")

s_initialize("tftp_read_octet_options")
if s_block_start("read_rrq_opt"):
    s_static("\x00\x01")
    s_string("uname.txt")
    s_static("\x00")
    s_static("octet")
    s_static("\x00")
    s_static("blksize")
    s_static("\x00")
    s_double(10000, format="ascii")
    s_static("\x00")
    s_static("timeout")
    s_static("\x00")
    s_short(1, format="ascii")
    s_static("\x00")
    s_static("tsize")
    s_static("\x00")
    s_short(10000, format="ascii")
    s_static("\x00")
    s_string("test")
    s_static("\x00")
    s_string("foo bar")
    s_static("\x00")
    s_block_end("read_rrq_opt")


s_initialize("tftp_ack")
s_static("\x00\x04")
s_short(0, format="ascii")


s_initialize("tftp_write_request")
if s_block_start("write_rrq"):
    s_static("\x00\x02")
    s_string("foo bar")
    s_static("\x00")
    s_static("octet")
    s_static("\x00")
    s_block_end("write_rrq")




#if s_block_start("transtype", group="transfertype"):
    #s_string(" ")
    #s_static("\x00")
    #s_block_end()
