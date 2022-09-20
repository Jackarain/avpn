#!/usr/bin/env python
#
# 使用下面命令添加tun7设备作为测试
# ip tuntap add dev tun7 mod tun
# ifconfig tun7 192.168.244.2 pointopoint 192.168.244.1 netmask 255.255.255.0
# ip link set tun7 up

import struct
import time
import humanize

from fcntl import ioctl

def openTun(tunName):
    tun = open("/dev/net/tun", "r+b", buffering=0)
    LINUX_IFF_TUN = 0x0001
    LINUX_IFF_NO_PI = 0x1000
    LINUX_TUNSETIFF = 0x400454CA
    flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
    ifs = struct.pack("16sH22s", tunName, flags, b"")
    ioctl(tun, LINUX_TUNSETIFF, ifs)
    return tun

tun = openTun(b"tun7")

#syn = b'E\x00\x00,\x00\x01\x00\x00@\x06\x00\xc4\xc0\x00\x02\x02"\xc2\x95Cx\x0c\x00P\xf4p\x98\x8b\x00\x00\x00\x00`\x02\xff\xff\x18\xc6\x00\x00\x02\x04\x05\xb4'
# tun.write(syn)

sum = 0
total_packet = 0
num_packet_sec = 0
lasttime = 0

while True:
    reply = tun.read(1500)
    sum = sum + len(reply)
    total_packet += 1
    num_packet_sec += 1
    curr_time = round(time.time())
    if lasttime != curr_time:
        print("Total ip %d, read ip: %d/s, total bandwidth: %s/s" %
              (total_packet, num_packet_sec, humanize.naturalsize(sum)))
        sum = 0
        num_packet_sec = 0
        lasttime = curr_time
