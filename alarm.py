from scapy.all import *
import sys
import re
def alarms(packets):
	incnum = 0
	inci = ""
	srcip = ""
	protoc = ""
	portnum = ""
	payload = "no payload sorry"
	def soundthealarm(incnum, inci, srcip, protoc, payload):		
		print "AlERT #" + str(incnum) + ": " + str(inci) + " is detected from " + str(srcip) + "(" + str(protoc) + ") (" + str(payload) + ") !"
		incnum+=1
		return incnum
	for packet in packets:
			if packet.haslayer(TCP):
				if packet.haslayer(Raw):
					#Nikto check					
					if 'Nikto'in packet[Raw].load: 
						srcip = packet.getlayer(IP).src
						protoc = packet.getlayer(TCP).dport
						payload = packet[Raw].load						
						incnum = soundthealarm(incnum, "Nikto Scan", srcip, protoc, payload)			
					#Other Nmap check
					if 'Nmap'in packet[Raw].load: 
						srcip = packet.getlayer(IP).src
						protoc = packet.getlayer(TCP).dport
						payload = packet[Raw].load						
						incnum = soundthealarm(incnum, "other Nmap", srcip, protoc, payload)			

					#Username PW Check 				
					if 'USER'in packet[Raw].load: 
						srcip = packet.getlayer(IP).src
						protoc = packet.getlayer(TCP).dport
						payload = packet[Raw].load
					if 'PASS' in packet[Raw].load:
						payload += packet[Raw].load								
						incnum = soundthealarm(incnum, "plaintext USER/PASS", srcip, protoc, payload)
				#Credit card Check
					CC = "^(4[0-9]{3}?)(\-[0-9]{4}?){3}?|(4[0-9]{3}?)([0-9]{4}?){3}?|(4[0-9]{3}?)( [0-9]{4}?){3}?|6011(\-[0-9]{4}?){3}?|6011([0-9]{4}?){3}?|6011( [0-9]4?){3}?|(5[0-9]{3}?)(\-[0-9]{4}?){3}?| (5[0-9]{3}?)([0-9]4?){3}?|(5[0-9]{3}?)( [0-9]4?){3}?|(3[0-9]{3}?)(\-[0-9]{4}?){3}?|(3[0-9]{3}?)([0-9]{4}?){3}?|(3[0-9]{3}?)( [0-9]{4}?){3}?$"
					possible = re.compile(CC)
					real = possible.search(packet.getlayer(Raw).load)
					if real != None:
						srcip = packet.getlayer(IP).src
						protoc = packet.getlayer(TCP).dport
						payload = packet.getlayer(Raw).load
						incnum = soundthealarm(incnum, "plaintext Credit Card", srcip, protoc, payload)
				#NULL Scan check
				if packet.getlayer(TCP).flags == 0x00 and packet.getlayer(TCP).seq == 0:
					srcip = packet.getlayer(IP).src
					protoc = packet.getlayer(TCP).dport
					payload = packet.load					
					incnum = soundthealarm(incnum, "NULL Scan", srcip, protoc, payload)

				#FIN Scan Check
				elif packet.getlayer(TCP).flags == 0x01:	
					srcip = packet.getlayer(IP).src
					protoc = packet.getlayer(TCP).dport
					payload = packet.load
					incnum = soundthealarm(incnum, "FIN Scan", srcip, protoc, payload)

				#XMAS tree scan check
				elif packet.getlayer(TCP).flags == 0x29:
					srcip = packet.getlayer(IP).src
					protoc = packet.getlayer(TCP).dport
					payload = packet.load
					incnum = soundthealarm(incnum, "Merry XMAS Scan!", srcip, protoc, payload)
				
def help():
	print "usage: python alarm.py [-h][-i INTERFACE] [-r PCAPFILENAME]"
	print "A network sniffer that identifies basic vulnerabilities"
	print "optional arguments:"
	print "   -h or --help  usage information"
	print "   -i INTERFACE  Network interface to sniff on (will sniff on eth0 by default)"
	print "   -r PCAPFILE	  Read a .pcap file in instead of sniffing"			
def main():
	interf = "eth0"
	pfile = ""
	def startscannin(interf):
		packets = sniff(iface=interf)
		alarms(packets)		
	def readin(pfile):
		packets = rdpcap(pfile)
		alarms(packets)
	if len(sys.argv)>1:
		if sys.argv[1] == '-h' or sys.argv[1] == '--help':
			help()
		elif sys.argv[1] == '-i':
			if len(sys.argv)>2:
				interf = sys.argv[2]
			startscannin(interf)
		elif sys.argv[1] == '-r':
			if len(sys.argv)>2:
				readin(sys.argv[2])
		else:
			help()
	else:
		startscannin(interf)
main()



