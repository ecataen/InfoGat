#!/usr/bin/env python
#Author Neat
#This script uses browser to seearch using google dork techniques for exposed and vulnerable informations scattered in the web.
import webbrowser

#new = 2 #Open in new tab for firefox varible

tabUrl = "https://www.google.com.np/?#q="
domain = raw_input("Enter your targeted domain: ")
print "Script started successfully, \nIgnore the terminal outputs(Just in case), your browser shall open shortly."

#Since firefox is giving problem, i am using google-chrome as a browser

#Check for Directory listing
webbrowser.get('google-chrome').open(tabUrl+"site:"+domain+" intitle:index.of") #,new=new) - removed from all for debugging

#Check for Configuration files Exposure
webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+domain+" ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini") #,new=new)

#Check for Database files
webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+domain+" ext:sql | ext dbf | ext:mdb") #,new=new)

#Check for log files
webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+domain+" ext:log") #,new=new)

#Check for backup files
webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+domain+" ext:bkp | ext:bkf | ext:bak | ext:old | ext:backup") #,new=new)

#Check for login pages
webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+domain+" inurl:login") #,new=new)

#Check for sql injections points in x domain
webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+domain+" intext:'sql syntax near' | intext:'syntax error has occurred' | intext:'incorrect syntax near' | intext:'unexpected end of SQL command' | intext:'Warning: mysql_connect()' | intext:'Warning: mysql_query()' | intext:'Warning: pg_connect()'") #,new=new)

#Check for publicly exposed documents
webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+domain+" ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv") #,new=new)

#Check for phpinfo() file exposed in x domain
webbrowser.get('google-chrome').open_new_tab(tabUrl+"site:"+domain+" ext:php intitle:phpinfo 'published by the PHP Group'") #,new=new)

#Note: if firefox opens fine then remove newly added .get('google-chorme') from hardcoded source.
