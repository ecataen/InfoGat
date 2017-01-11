#!/usr/bin/env python
#Author: Neat

''' ---Released under GNU GENERAL PUBLIC LICENSE---
	For user flexibility, most of the modules can be used individual,
	and does not have inter-relation with CLI tool and GUI tool.
'''

from tkinter import *
import tkMessageBox
from urllib2 import urlopen	#from publicip.py
import socket			#from ip.py, from host.py
import dns.resolver		#from dnsinfo.py
import dns.query		#from zone-transfer.py
import dns.zone			#from zone-transfer.py
from dns.exception import DNSException	#from zone-transfer.py
from dns.rdataclass import *	#from zone-transfer.py
from dns.rdatatype import *	#from zone-transfer.py
import urllib2			#from header.py
import os			#from whois.py
import webbrowser		#from dork-search.py
from datetime import datetime	#from port scan
import nmap			#from port scan

s = socket

def get_public_ip(): #importing publicip module here, urllib2
	print "Getting your Public IP..."
	public_ip = urlopen('http://ip.42.pl/ip').read()
	print "\nYour public IP address for this Computer is: "+public_ip+"\n"
	print("*-"*25)

#could require closure everytime- i.e. function inside function, but could be managed in one function at times. Lets see..

def get_ip():	#importing code from module ip.py
	print "Target locked as: "+e1.get()+"\n"
#	def host_ip():	#closure comes handy here. nah! forget it..
	host = s.gethostbyname(e1.get())
	try:
		print ('IP address: %s'%host)
	except s.error as err_msg:
		print ("%s: %s"%host.err_msg)
#	host_ip()
	print"*-"*25

def get_hostname():	#importing code from module hostname.py
	print "Target locked as: "+e1.get()+"\n"
	print "Trying Reverse Domain Lookup."
	try:
		name, alias, addresslist = s.gethostbyaddr(e1.get())
		print (e1.get()+" has reverse name as: "+name)
	except (s.error, s.herror, s.gaierror, s.timeout):
		print "Could not fetch hostname for "+e1.get()
		print "\nSorry, something seems to be fishy here.\nCould be session timeout or multiple hosting under same IP."
	print"*-"*25

def get_dns_info(): #could give error while inserting 'www' in the target domain with fqdn because of cache problem, otherwise it's  fine.
	print "Target locked as: "+e1.get()+"\n"
	try:
		aanswer = dns.resolver.query(e1.get(), 'A') #Gathers A record
		print ("Gathering Address Record for "+e1.get())
		try:
			for rdata in aanswer:
				print rdata
		except:
			print "Query Failed."

		nsanswer = dns.resolver.query(e1.get(), 'NS') #Gather NS record
		print ("\nGathering Name Server Record for "+e1.get())
		try:
			for rdata in nsanswer:
				print rdata
		except:
			print "Query Failed."

		mxanswer = dns.resolver.query(e1.get(),'MX') #Gather MX record
		print ("\nGathering MX Record for "+e1.get())
		try:
			for rdata in mxanswer:
				print "Host at", rdata.exchange, "has preference", rdata.preference
		except:
			print "Query Failed."
	except:
		print "Try removing 'www' and try again with just name.domain only."
	print"*-"*25

def get_zone_transfer(): #importing code from zone-transfer.py module
	print "Target locked as: "+e1.get()+"\n"
	print "About to perform XFR now..."
	print "\nGetting NS records for", e1.get()
	answers = dns.resolver.query(e1.get(), 'NS')
	ns = []

	#for rdata in nsanswer:
 	#       print rdata

	for rdata in answers:
		n = str(rdata)
    		print "Found name server as:", n
   		ns.append(n)

	for n in ns:
		print "\nTrying a zone transfer for %s from name server %s" % (e1.get(), n)
    		try:
       			zone = dns.zone.from_xfr(dns.query.xfr(n, e1.get()))
    		except DNSException, e:
       			print e.__class__, e
		print "No luck here.."
	print"*-"*25

def get_header_info(): #requires http:// or https:// infront of fqdn
	print "Target locked as: "+e1.get()+"\n"
	print "Getting Server header information.\n"
	try:
		req = urllib2.Request(e1.get())
		res = urllib2.urlopen(req)
		print res.info()
		res.close();
	except:
		print "Try inserting http:// or https:// infont of fqdn domain.\n"
	print"*-"*25

def get_whois_info(): #uses inbuilt whois tool, nothing fancy here
	print "Target locked as: "+e1.get()+"\n"
	print "Please remember to insert only IP address for whois lookup\n"
	print "Gathering Whois information...\n"
	import time #could consume some process since module is imported inside function.
	time.sleep(5) #time for user to read the message.
	command = "whois " + e1.get() #Requires whois installed on host os.
	process = os.popen(command)
	results = str(process.read())
	print results
	print"*-"*25

def get_google_dork():
	print "Target locked as: "+e1.get()+"\n"
	tabUrl = "https://www.google.com.np/?#q="
	print "Script started successfully, \nIgnore the terminal outputs(Just in case), your browser shall open shortly.\n"
	print "Make sure that you enter your target and select the reqired buttons from below.\n"

	'''	Since firefox is giving problem, i am using google-chrome as a browser
		just make sure that google-chrome is what your system understands,
		or browser could be changed as prefered by user.
		Check Buttons were included to decrease processing load to the system.
	'''
	if check1.get():
	#Check for Directory listing
		webbrowser.get('google-chrome').open(tabUrl+"site:"+e1.get()+" intitle:index.of") #,new=new) - removed from all for debugging

	if check2.get():
	#Check for Configuration files Exposure
		webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+e1.get()+" ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini") #,new=new)

	if check3.get():
	#Check for Database files
		webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+e1.get()+" ext:sql | ext dbf | ext:mdb") #,new=new)

	if check4.get():
	#Check for log files
		webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+e1.get()+" ext:log") #,new=new)

	if check5.get():
	#Check for backup files
		webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+e1.get()+" ext:bkp | ext:bkf | ext:bak | ext:old | ext:backup") #,new=new)

	if check6.get():
	#Check for login pages
		webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+e1.get()+" inurl:login") #,new=new)

	if check7.get():
	#Check for sql injections points in x domain
		webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+e1.get()+" intext:'sql syntax near' | intext:'syntax error has occurred' | intext:'incorrect syntax near' | intext:'unexpected end of SQL command' | intext:'Warning: mysql_connect()' | intext:'Warning: mysql_query()' | intext:'Warning: pg_connect()'") #,new=new)

	if check8.get():
	#Check for publicly exposed documents
		webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+e1.get()+" ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv") #,new=new)

	if check9.get():
	#Check for phpinfo() file exposed in x domain
		webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+e1.get()+" ext:php intitle:phpinfo 'published by the PHP Group'") #,new=new)

	#Note: if firefox opens fine then remove newly added .get('google-chorme') from hardcoded source.

	print"*-"*25

def get_port_scan():
	print "Target locked as: "+e1.get()+"\n"

	time1 = datetime.now()	#Recording started time
	try:
		print "This could take a while. Please wait..."

		nm = nmap.PortScanner()	#source:nmap documentation
		nm.scan(e1.get(),'1-65535')

		for host in nm.all_hosts():
			for proto in nm[host].all_protocols():
				print('[*] Protocol: %s' % proto)
				lport = nm[host][proto].keys()
				lport.sort()
				for port in lport:
					print ('[+] Port: %s/Open\tService: %s'% (port, nm[host][proto][port]['product']))
		time2 = datetime.now()
		totalTime = time2 - time1	#time taken for task
		print "\nScan Completed in ",totalTime
	except KeyboardInterrupt:
		print "You pressed Ctrl+C"
		sys.exit()

	print"*-"*25

def about():
	tkMessageBox.showinfo("About", "Designed and Developed by Neat. \n| 2017 |\n")

def readme():
	with open("README.md","r") as f:	#Readme file here...
		text = f.readlines()
	for line in text:
		print line

def license():
	with open("License.txt","r") as f:	#Look for license information here...
		text = f.readlines()
	for line in text:
		print line

def callback():
	if tkMessageBox.askokcancel("Quit", "Do you really wish to quit?"):
        	master.destroy()
	print "Thanks for using InfoGat, hope to see you back again! - Neat"


master = Tk()
master.title("Information Gathering Toolkit v1.2")
master.minsize(width=520, height=440) #510)
master.maxsize(width=530, height=450) #520)

#For menubar
menubar = Menu(master)

#Creating pulldown menu
helpmenu = Menu(menubar, tearoff=0)
helpmenu.add_command(label="About", command=about)
helpmenu.add_command(label="How to use?", command=readme)
helpmenu.add_command(label="License", command=license)
menubar.add_cascade(label="Help", menu=helpmenu)

#Display the menu now
master.config(menu=menubar)

Label(master, text="Enter your target: ").grid(row=0)
#Label(master, text="Enter port number: ").grid(row=1) #only used while searching open ports.
#NOte: port is hardcoded now

e1 = Entry(master, background="light blue")
#e2= Entry(master) #for assigning port number port is hardcoded

e1.grid(row=0, column=1)
#e2.grid(row=1, column=1) #for assigning port number

#first row
Button(master, text="What is my IP", command=get_public_ip).grid(row=6, column=0, padx= 10, pady=10, sticky=W+E) #, sticky=W, pady=4)
Button(master, text="Server's IP", command=get_ip).grid(row=6, column=1, padx=10, pady=10, sticky=W+E) #, sticky=W, pady=4)
Button(master, text="Server's Hostname", command=get_hostname).grid(row=6, column=2, padx=10, pady=10, sticky=W+E) #, sticky=W, pady=4)

#second row
Button(master, text="DNS Information", command=get_dns_info).grid(row=8, column=0, padx=10, pady=10, sticky=W+E) #, sticky=W, pady=4)
Button(master, text="Try Zone Transfer", command=get_zone_transfer).grid(row=8, column=1, padx=10, pady=10, sticky=W+E) #, sticky=W, pady=4)
Button(master, text="Server's Header Info", command=get_header_info).grid(row=8, column=2, padx=10, pady=10, sticky=W+E) #, sticky=W, pady=4)

#third row
Button(master, text="Whois Lookup", command=get_whois_info).grid(row=10, column=0, padx=10, pady=10, sticky=W+E) #, sticky=W, pady=4)
Button(master, text="Google Dork", command=get_google_dork).grid(row=10, column=1, padx=10, pady=10, sticky=W+E) #, sticky=W, pady=4)
Button(master, text="Find Open Ports", command=get_port_scan).grid(row=10, column=2, padx=10, pady=10, sticky=W+E) #, sticky=W, pady=4)

Label(master, text="Selection for Dork").grid(row=11, column=1, padx=10, pady=10)
check1 = BooleanVar()
Checkbutton(master, text="Directory Listing", variable=check1).grid(row=12, column=0, padx=10, pady=10)
check2 = BooleanVar()
Checkbutton(master, text="Config Files", variable=check2).grid(row=12, column=1, padx=10, pady=10)
check3 = BooleanVar()
Checkbutton(master, text="Database Files", variable=check3).grid(row=12, column=2, padx=10, pady=10)
check4 = BooleanVar()
Checkbutton(master, text="Log Files", variable=check4).grid(row=13, column=0, padx=10, pady=10)
check5 = BooleanVar()
Checkbutton(master, text="Backup Files", variable=check5).grid(row=13, column=1, padx=10, pady=10)
check6 = BooleanVar()
Checkbutton(master, text="Login Page", variable=check6).grid(row=13, column=2, padx=10, pady=10)
check7 = BooleanVar()
Checkbutton(master, text="SQLI Errors", variable=check7).grid(row=14, column=0, padx=10, pady=10)
check8 = BooleanVar()
Checkbutton(master, text="Exposed Documents", variable=check8).grid(row=14, column=1, padx=10, pady=10)
check9 = BooleanVar()
Checkbutton(master, text="PHPInfo Files", variable=check9).grid(row=14, column=2, padx=10, pady=10)

#Quit button here
Button(master, text='Quit', command=callback).grid(row=15, column=2, padx=15, pady=15, sticky=W+E)

#Status bar here
status = Label(master, text="| Developed by Neat | 2017 |", relief=SUNKEN).grid(row=16, column=1, sticky=W+E, padx=10, pady=10)

#Ask while quit
master.protocol("WM_DELETE_WINDOW", callback)
#label = Label()

mainloop()
