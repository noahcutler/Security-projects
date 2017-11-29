#!/usr/bin/env python
import argparse
from scapy.all import *

time_out = 4
parser = argparse.ArgumentParser(description='this tool lets you perform a zombie scan on an IP address, range of IP addresses, or maybe even URLs (with a crawlerin the future (?))')
parser.add_argument('-t', dest='target', type=str,help='single target IP adress')
parser.add_argument('-r', dest='range', type=str,help='scan a range of IP adresses. This may take a while.')
parser.add_argument('-z', dest='zombie', type=str,help='zombie IP address')
args = parser.parse_args()

def ExpandIPrange(i):
  #soon
  print i
def Bringoutyerdead(zombie):
    ping_packet=IP(dst=zombie)/ICMP()
    reply = sr1(ping_packet, timeout=time_out)
    if not (reply is None):
       print "someone's home!"
       reply.show()   
       return 1
    else:
        return 0
def Zscan(dest_ip):
    zomb = args.zombie
    if Bringoutyerdead(zomb)==0:
        print "sorry, this zombie is too... dead :/"
    else:
        ip_id_packet = IP(dst=zomb)/TCP(sport=31337,dport=(123),flags="SA")
        reply = sr1(ip_id_packet, verbose=0)
        initial_ip_id = reply.id
        print "initial IP id: "+ str(initial_ip_id)
        reply2 = sr1(ip_id_packet)
        second_ip_id = reply2.id
        if second_ip_id == (initial_ip_id + 1):
            initial_ip_id = second_ip_id
            print initial_ip_id
        else:
            print "sorry, too active, try another zombie..."
            print second_ip_id
            return 0
       ports = [21, 22, 23, 25, 80, 443, 8080, 1433, 135, 139, 445, 9100]
       for port in ports:
        zpack = IP(dst=dest_ip,src=zomb)/TCP(sport=123,dport=(port),flags="S")  #for loop
        zz = send(zpack, verbose=0)
        check = sr1(ip_id_packet, verbose=0)
        new_ip_id = check.id
        if new_ip_id - initial_ip_id <2
            print "port"+str(port) +"closed or filtered"
        else:
            print "port"+str(port) +"is open!!"
        initial_ip_id = new_ip_id 
if args.range:
    ExpandIPrange(args.range))
    for ip in expanded:
        ZScan(ip)
elif args.target:
    Zscan(args.target)
