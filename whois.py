#!/bin/env/python
#Author Neat

#This script performs whois scan

import os

domain = raw_input("Enter the targeted domain to gather whois information: ")
print "Gathering Whois information..."
command = "whois " + domain #Requires whois installed on host os.
process = os.popen(command)
results = str(process.read())
print results
