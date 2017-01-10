#!/usr/bin/env python
#Author Neat
#This script scans serer for http header response.
import urllib2

header = raw_input("Enter the target to locate header information: ")
try:
	print "Target locked as: "+header+"\n"
	req = urllib2.Request(header)
	res = urllib2.urlopen(req)
	print res.info()
	res.close();
except:
	print "Try inserting http:// or https:// infront of fqdn."
