#!/usr/bin/env python
#Author Neat
#This script tries DNS zone transfer.

import dns.resolver
import dns.query
import dns.zone
from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *

domain = raw_input("Enter the domain name to perform XFR: ")

print "\nGetting NS records for", domain
answers = dns.resolver.query(domain, 'NS')
ns = []

#for rdata in nsanswer:
 #       print rdata

for rdata in answers:
	n = str(rdata)
    	print "Found name server as:", n
   	ns.append(n)

for n in ns:
	print "\nTrying a zone transfer for %s from name server %s" % (domain, n)
    	try:
       		zone = dns.zone.from_xfr(dns.query.xfr(n, domain))
    	except DNSException, e:
       		print e.__class__, e
		print "No luck here.."

