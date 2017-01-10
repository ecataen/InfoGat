#!/usr/bin/env python
#Author Neat

#This script performs port scanning of given IP and Port
#Reference Python for pentesters(book)

import optparse
from socket import *
from threading import *

screenLock = Semaphore(value=1) #Creating global variable sereenLock - Semaphore as value 1 for thread.

def connScan(tgtHost, tgtPort):	#Defining connedtion scan function and setting target host and port.
	try:
		connSkt = socket(AF_INET, SOCK_STREAM) #creating socket
		connSkt.connect((tgtHost, tgtPort))	#connecting to socket
		connSkt.send('hello\r\n')		#sending data from the socket

		results = connSkt.recv(100)		#grabbing the results from the socket
		screenLock.acquire()
		print "[+] " + str(tgtPort) + "/tcp open"
	except:
		screenLock.acquire()
		print "[-] " + str(tgtPort) + "/tcp closed"
	finally:
		screenLock.release()
		connSkt.close()

def portScan(tgtHost, tgtPorts):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print "[-] Cannot resolve " + tgtHost + ": Unknown host"
		return
	try:
		tgtName = gethostbyaddr(tgtIP)
		print "\n[+] Scan Results for: " + tgtName[0]
	except:
		print "\n[+] Scan results for: " + tgtIP

	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
		t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		t.start()

def Main():
	parser = optparse.OptionParser('Usage - ./code.py'+\
		'-H <target host> -p <target port>')
	parser.add_option('-H', dest='tgtHost', type='string', \
		help='specify target host')
	parser.add_option('-p', dest='tgtPort', type='string', \
		help='specify target port[s] seperated by comma')
	(options, args) = parser.parse_args()
	if (options.tgtHost == None) | (options.tgtPort == None):
		print parser.usage
		exit(0)
	else:
		tgtHost = options.tgtHost
		tgtPorts = str(options.tgtPort).split(',')

	portScan(tgtHost, tgtPorts)

if __name__ == '__main__':
	Main()
