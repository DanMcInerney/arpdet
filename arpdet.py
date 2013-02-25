#!/usr/bin/python

#Suppress scapy warnings, but not errors
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#turn off the output for scapy functions with conf.verb
from scapy.all import *
conf.verb=0

import sys
import time
import os
import smtplib
import re
import subprocess
import commands
bash = commands.getoutput
import argparse

class colors:
    PURPLE = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.PURPLE = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''

try:
	localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
except Exception:
	sys.exit(colors.WARNING+"[*]"+colors.ENDC+" No local IP found, check network connectivity")

IPandMAC = {}
MAC = ""
IPaddr = ""
MAClist = []
pktTime = []
detectTimer = 0
prefixIP = re.search('\d{2,3}\.\d{1,3}\.\d{1,3}\.', localIP).group()

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--promiscping", help="Start with a promiscuous ping scan", action="store_true")
args = parser.parse_args()

#Example usage of colors
#print bcolors.OKBLUE + "Check this out" + colors.ENDC
try:
	from user_pass import user, passwd, rcpt
except ImportError:
	print colors.WARNING+"[?]"+colors.ENDC+" Error importing user_pass. Are you sure its in this directory? Email won't send."

if args.promiscping == True:
	print colors.FAIL+"\n[!]"+colors.ENDC+" Possible promisucous mode enabled on the following clients: "
	ans,unans = promiscping(prefixIP+"*")

#Get the ESSID to match to iwlist scan "(.*?)" searches for all text between quotes
essidcmd = bash('iwgetid')
essid = re.search('"(.*?)"', essidcmd).group(1)

#Define interface in use and router IP
routecmd = bash('ip route')
routerinfo = re.search('default via (%s\d{1,3}) \w+ (\w[a-zA-Z0-9]\w[a-zA-Z0-9][0-9]?)' % prefixIP, routecmd)
interface = routerinfo.group(2)
routerIP = routerinfo.group(1)

ipalines=bash('ip addr').splitlines()
for l in ipalines:
	macsearch = re.search(interface+":", l)  
	if macsearch != None:
		indexof = ipalines.index(l)
		localMAC = re.search('([a-fA-F0-9]{2}[:|\-]?){6}', ipalines[indexof+1]).group()

#Define router MAC
linelist=bash('iwlist scan').splitlines()
startline=linelist.index('                    ESSID:"%s"' % essid)
routermac = re.search('([a-fA-F0-9]{2}[:|\-]?){6}', linelist[startline-5]).group()

#Populate the IPandMAC table with an arping
if len(IPandMAC) == 0:
	ans,unans = arping(prefixIP+"*")
	devices = len(ans)
	for s,r in ans:
		IPandMAC[r.sprintf("%ARP.hwsrc%")] = r.sprintf("%ARP.psrc%")
		IPandMAC[localMAC] = localIP

#Print the known information
print colors.OKBLUE+"\n[+]"+colors.ENDC+" Your device: "+colors.OKBLUE+interface+colors.ENDC+" at "+colors.OKBLUE+localIP+colors.ENDC+" with MAC "+colors.OKBLUE+localMAC+colors.ENDC
print colors.OKBLUE+"[+]"+colors.ENDC+" Router: "+colors.OKBLUE+essid+colors.ENDC+" at "+colors.OKBLUE+routerIP+colors.ENDC+" with MAC "+colors.OKBLUE+routermac
print "[+]"+colors.ENDC+" Number of devices on the local network:",colors.OKBLUE,devices+1,colors.ENDC
ans.show()
print localMAC, localIP, "\n"

#Send the email
def smtp(msg):
	try:
		server = smtplib.SMTP('smtp.gmail.com:587')
	except Exception:
		print colors.PURPLE+"\n[?]"+colors.ENDC+" Contacting Gmail server failed, trying again..."
	try:
		server = smtplib.SMTP('smtp.gmail.com:587')
	except Exception:
		print colors.PURPLE+"[?]"+colors.ENDC+" Contacting Gmail server failed. Could not send notification."
		return

	server.starttls()
	server.login(user,passwd)
	server.sendmail(user, rcpt, msg)

	print colors.WARNING+"[*]"+colors.ENDC+" Email sent to "+colors.WARNING+rcpt+colors.ENDC+"\n"

def newdevices(pkt):
	print colors.WARNING+"[*]"+colors.ENDC+" New device joined the network"
	print colors.WARNING+"[*]"+colors.ENDC+" Device IP: "+colors.WARNING+IPaddr+colors.ENDC+" Device MAC: "+colors.WARNING+MAC
	print "[*]"+colors.ENDC+" Updated list of current or previously connected devices:\n"
	for k,v in IPandMAC.iteritems():
		print k,v
	if len(IPandMAC) > devices:
		newdevicemsg = "From: From Me <%s>\nTo: <%s>\nSubject:\n\nNew device joined network! IP: %s MAC: %s" % (user, rcpt, IPaddr, MAC)
		smtp(newdevicemsg)

#Launch the deauth packets and send the email
def deauth(pkt):
	print colors.FAIL+"[!]"+colors.ENDC+" ARP spoof detected!"
	print colors.FAIL+"[!]"+colors.ENDC+" Attacker IP: "+colors.FAIL+IPandMAC[MAC]+colors.ENDC+" Attacker MAC: "+colors.FAIL+MAC+colors.ENDC

# Start monitor mode
	moncmd = bash('airmon-ng start %s' % interface)
	moniface = re.search('(mon[0-9])', moncmd).group()

	print 'aireplay-ng -0 2 -a %s -c %s %s' % (routermac, MAC, moniface)
	deauthcmd = bash('aireplay-ng -0 1 -a %s -c %s %s' % (routermac, MAC, moniface))
	print deauthcmd

	monexit = bash('airmon-ng stop %s' % moniface)

	#Healing packet function here
	print colors.WARNING+"[*]"+colors.ENDC+" Sending healing packets"
	send(ARP(op=2, psrc=localIP, pdst=routerIP, hwdst="ff:ff:ff:ff:ff", hwsrc=localMAC), count=10)

	#Send email
	arpdetmsg = "From: From Me <%s>\nTo: <%s>\nSubject:\nMIME-Version: 1.0\nContent-type: text/plain\n\nArp spoof detected! Attacker IP: %s Attacker MAC: %s" % (user, rcpt, IPandMAC[MAC], MAC)
	smtp(arpdetmsg)

	#Reset the IPandMAC table
	IPandMAC[localMAC] = localIP

def arppingDet():

	global pktTime
	global detectTimer
	global MAClist

	pktTime.append(time.mktime(time.gmtime())) 
	pktDif = [pktTime[i+1]-pktTime[i] for i in range(len(pktTime)-1)]
	MACcounter = 0
	timeCounter = 0

	if len(MAClist) < 8: 
		MAClist.append(MAC)
		for a in MAClist:
			if a == MAC:
				MACcounter += 1
		if MACcounter > 6:
			for b in pktDif:
				if b == 0:
					timeCounter += 1	
			if timeCounter > 5:
				curTimer = time.mktime(time.gmtime())
				lastDet = curTimer - detectTimer
				if lastDet > 30:
					detectTimer = time.mktime(time.gmtime())
					print colors.FAIL+"[!]"+colors.ENDC+" ARP ping detected!"
					print colors.FAIL+"[!]"+colors.ENDC+" Attacker IP: "+colors.FAIL+IPandMAC[MAC]+colors.ENDC+" Attacker MAC: "+colors.FAIL+MAC+colors.ENDC
					arpPingmsg = "From: From Me <%s>\nTo: <%s>\nSubject:\n\nARP ping detected! IP: %s MAC: %s" % (user, rcpt, IPaddr, MAC)
					smtp(arpPingmsg)
			MACcounter = 0
			timeCounter = 0

	else:
		MAClist = []
		pktDif = []
		pktTime = []

def monitor(pkt):

	global IPaddr, MAC, detectTimer

	#Fill in MAC and IPAddr variables. Sometimes it gets a packet where pkt.getlayer(ARP) is None, that's why MAC is wrapped in try
	if pkt.getlayer(ARP).psrc == None:
		return
	if pkt.getlayer(ARP).psrc == '00:00:00:00:00:00':
		return
	if pkt.getlayer(ARP).psrc == localIP:
		return
	MAC = pkt.getlayer(ARP).hwsrc
	if re.search(prefixIP, pkt.getlayer(ARP).psrc) == None:
		return
	IPaddr = pkt.getlayer(ARP).psrc

	arppingDet()

	#Check for arp spoof
	if MAC in IPandMAC:
		if IPaddr != IPandMAC[MAC]:
			deauth(pkt) 
	else:
		IPandMAC[MAC] = IPaddr
		newdevices(pkt)

while 1:
	try:
		sniff(store=0, filter='arp', prn=monitor, iface=interface)
	except Exception:
		print Exception
		print colors.WARNING+"[!] "+colors.ENDC+"Network down, trying again in a minute."
		time.sleep(60)
