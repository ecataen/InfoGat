#!/usr/bin/python
#Author Neat

#This script gathers public ip address of the host computer.
from urllib2 import urlopen

print "This script searches for your public IP address."
print "Getting your IP..."
print " "

public_ip = urlopen('http://ip.42.pl/ip').read()

print "Your public IP address for this Computer is: "+public_ip
