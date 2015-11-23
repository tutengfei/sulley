from sulley import *
from requests import openflow
import socket

def bind(target):
    s = socket.socket(socket.AF_INET, socket.socket_STREAM)
    s.connect(target)

def do_fuzz():
	sess = sessions.session(session_filename="openflow.log")
	target = sessions.target("127.0.0.1", 6653)
	sess.add_target(target)
	sess.connect(s_get("openflow"))
	sess.fuzz()
	print "done fuzzing......"

if __name__ == "__main__":
	do_fuzz()