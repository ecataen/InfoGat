#!/usr/bin/env python
#Author: Neat
#This script finds A, NS and MX record of x domain.
import dns.resolver

domain = raw_input("Enter the targeted domain: ")
print "Target locked as: "+domain

def a_answer():
	aanswer = dns.resolver.query(domain, 'A') #Gathers A record
	print ("\nGathering Address Record for "+domain)
	try:
		for rdata in aanswer:
			print rdata
	except:
		print "Query Failed."

def ns_answer():
	nsanswer = dns.resolver.query(domain, 'NS') #Gather NS record
	print (" ")
	print ("Gathering Name Server Record for "+domain)
	try:
		for rdata in nsanswer:
			print rdata
	except:
		print "Query Failed."

def mx_answer():
	mxanswer = dns.resolver.query(domain,'MX') #Gather MX record
	print (" ")
	print ("Gathering MX Record for "+domain)
	try:
		for rdata in mxanswer:
			print "Host at", rdata.exchange, "has preference", rdata.preference
	except:
		print "Query Failed."

def main():
	a_answer()
	ns_answer()
	mx_answer()

if __name__ == '__main__':
	main()
