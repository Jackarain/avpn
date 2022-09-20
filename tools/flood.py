#!/usr/bin/env python

import sys
import time
import humanize
import socket

dst_ip = "10.0.0.1"
dst_port = 5005
msg_len = 1422

if len(sys.argv) == 2 and sys.argv[1].find("help") != -1:
	print(""" Usage:""")
	print("""   flood.py [dest_ip(10.0.0.1)] [len(1422)] [port(5005)]""")
	exit()

if len(sys.argv) >= 2:
	dst_ip = sys.argv[1]
	if len(sys.argv) > 2:
		dst_port = int(sys.argv[2])
		if len(sys.argv) >= 3:
			dst_port = int(sys.argv[3])

msg = [0 for i in range(msg_len)]
ar = bytes(msg)
size = len(ar)

print("UDP target IP: %s" % dst_ip)
print("UDP target port: %s" % dst_port)
print("message size: %d" % size)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sum = 0
lasttime = 0

while True:
	sock.sendto(ar, (dst_ip, dst_port))
	sum = sum + size
	curr_time = round(time.time())
	if lasttime != curr_time:
		print(humanize.naturalsize(sum))
		sum = 0
		lasttime = curr_time
