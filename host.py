#!/usr/bin/env python
#Reverse DNS search
#Author Neat

import socket
ip = raw_input("Enter the target IP: ")
try:
	name, alias, addresslist = socket.gethostbyaddr(ip)
	print ip+" has Reverse name as: "+name
except (socket.error, socket.herror, socket.gaierror, socket.timeout):
	print "Could not fetch hostname for "+ip
	print "\nSorry, something seems to be fishy here.\nCould be session timeout or multiple hosting under same IP."
