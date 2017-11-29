from scapy.all import *
import base64
import imghdr

picstr = ""
packets = rdpcap("picture.pcap")
for pak in packets:
	if (pak.haslayer(TCP)):
		picstr+=pak.load
picstr = base64.b64decode(picstr)
ext = imghdr.what(None, picstr)
fname  = "output." + ext
f = open(fname, 'w+')
f.write(picstr)
f.close()
