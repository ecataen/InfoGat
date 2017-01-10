#!/usr/bin/env python
#Author: Neat
#This script gathers IP address from domain name.

import socket

domain_name = raw_input("Enter a Domain to get IP address: ")
s = socket

def host_ip():
	host = s.gethostbyname(domain_name)

	try:
		print ('IP address: %s'%host)
	except s.error as err_msg:
		print ("%s: %s"%host.err_msg)

host_ip()
