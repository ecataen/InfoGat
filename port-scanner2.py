#!/usr/bin/env python
#Author Neat

from datetime import datetime
import nmap

target = raw_input("Enter your target host to perform port-scan: ")
print "Target locked as: "+target+"\n"

time1 = datetime.now()  #Recording started time
try:
	print "This could take a while. Please wait..."
	nm = nmap.PortScanner() #source:nmap documentation
	nm.scan(target,'1-65535')
	for host in nm.all_hosts():
		for proto in nm[host].all_protocols():
			print('[*] Protocol: %s' % proto)
			lport = nm[host][proto].keys()
			lport.sort()
			for port in lport:
				print ('[+] Port: %s/Open\tService: %s'% (port, nm[host][proto][port]['product']))
	time2 = datetime.now()
	totalTime = time2 - time1       #time taken for task
	print "\nScan Completed in ",totalTime
except KeyboardInterrupt:
	print "You pressed Ctrl+C"
	sys.exit()

