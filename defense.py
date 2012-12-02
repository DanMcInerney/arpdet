#!/usr/bin/python
import re
import subprocess
import os
import sys
import time
from Tkinter import *

#Save a few colors for the print function
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''

#Example usage of colors
#print bcolors.OKBLUE + "Check this out" + bcolors.ENDC

#Open logfile
defenselog = open('defense-log.txt', 'w')


#Set attack mac, attack IP, and Tkinter root variables as globalvars
root = ''
checkmac = ''
attackip = ''	
iface = ''


#Define what kind of local IP is used
ipprefixcmd = subprocess.Popen('ip addr', shell=1, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
ipprefixtxt = ipprefixcmd.communicate()[0]
ipprefixinfo = re.search('(\d{2,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}/24', ipprefixtxt)
if ipprefixinfo == None:
	sys.exit("No local IP prefix found. Exiting")
ipprefix = ipprefixinfo.group(1)

#Define interface in use and router IP
routecmd = subprocess.Popen('ip route', shell=1, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
routetxt = routecmd.communicate()[0]
routerinfo = re.search('default via (%s\d{1,3}) \w+ (\w[a-zA-Z0-9]\w[a-zA-Z0-9][0-9]?)' % ipprefix, routetxt)
if routerinfo == None:
	sys.exit("No active interface detected. Exiting.")
iface = routerinfo.group(2)
routerip = routerinfo.group(1)

#Define my MAC and IP
ipcmd = subprocess.Popen('ip addr', shell=1, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
iptxt = ipcmd.communicate()[0]
findip = re.search('(%s\d{1,3})/24' % ipprefix, iptxt)
if findip == None:
	sys.exit("No local client IP detected. Exiting.")
findmac = re.search(r'ether (([a-fA-F0-9]{2}[:|\-]?){6}).brd..................[\n]....inet %s' % ipprefix, iptxt) 
if findmac == None:
	sys.exit("No local client MAC detected. Exiting.")
myip = findip.group(1)
mymac = findmac.group(1)

#Define router MAC
routercmd = subprocess.Popen('ip neigh', shell=1, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
routertxt = routercmd.communicate()[0]
findrouter = re.search('%s \w+ \w[a-zA-Z0-9]\w[a-zA-Z0-9][0-9]? \w+ (([a-fA-F0-9]{2}[:|\-]?){6})' % routerip, routertxt)
if findrouter == None:
	sys.exit("Router MAC not found. Exiting.")
routermac = findrouter.group(1)


#Print variables
print '\nCurrent local IP prefix: ' + bcolors.OKBLUE + '%s' % ipprefix + bcolors.ENDC
print 'Current interface: ' + bcolors.OKBLUE + '%s' % iface + bcolors.ENDC
print 'Current MAC: ' + bcolors.OKBLUE + '%s' % mymac + bcolors.ENDC
print 'Current IP: ' + bcolors.OKBLUE + '%s' % myip + bcolors.ENDC
print 'Current gateway MAC: ' + bcolors.OKBLUE + '%s' % routermac + bcolors.ENDC
print 'Current gateway IP: ' + bcolors.OKBLUE + '%s' % routerip + bcolors.ENDC

#Kill any instances of monitor mode before starting
checkmoncmd = subprocess.Popen('airmon-ng', stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
checkmontxt = checkmoncmd.communicate()[0]
searchmon = re.search('mon[0-9]', checkmontxt)
if searchmon == None:
	print '\nClosing all monitor mode interfaces...'
if searchmon != None:
	monup = searchmon.group()
	killmon = subprocess.Popen(['airmon-ng', 'stop', '%s' % monup], stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))

#Create Tkinter GUI 
class popup:

        def __init__(self, master):

                frame = Frame(master)
                frame.pack()

                self.deauth = Button(frame, text="Deauth", command=self.deauth)
                self.deauth.pack(side=LEFT)

                self.info = Button(frame, text="Log info", command=self.info)
                self.info.pack(side=LEFT)

                self.infodeauth = Button(frame, text="Info + Deauth", fg='red', command=self.infodeauth)
                self.infodeauth.pack(side=LEFT)

#Create death button in GUI to launch aireplay
        def deauth(self):
          
		print 'Preparing ammunition: >>>' + bcolors.WARNING + 'airmon-ng start %s' % iface + bcolors.ENDC 
		moncmd = subprocess.Popen(['airmon-ng', 'start', iface], stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
		montxt = moncmd.communicate()[0] 
		findmon = re.search('(mon[0-9])', montxt)
		if findmon == None: 
			sys.exit('Interface could not be put into monitor mode. Exiting.')
		moniface = findmon.group()
 
		print 'Firing .50cal:        >>>' + bcolors.WARNING + 'aireplay-ng -0 5 -a %s -c %s %s' % (routermac, checkmac, moniface) + bcolors.ENDC
                deauthcmd = subprocess.Popen(['aireplay-ng', '-0', '999999', '-a', '%s' % routermac, '-c', '%s' % checkmac, '%s' % moniface], stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
		deauthoutput = deauthcmd.communicate()[0]

		text = Text(root)
		text.pack()
		text.insert(END, deauthoutput) 

		defenselog.write(deauthoutput)

		MonExit = subprocess.Popen(['airmon-ng', 'stop', '%s' % moniface], stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))

#Create info button for launching nmap
        def info(self):

		print 'Intensive intelligence gathering: >>>' + bcolors.WARNING + 'nmap -A -T4 -v -PE %s' % attackip + bcolors.ENDC
		nmapcmd = subprocess.Popen(['nmap', '-A', '-T4', '-v', '-PE', '%s' % attackip], stdout=subprocess.PIPE, stderr=open(os.devnull))
		nmapoutput = nmapcmd.communicate()[0]

		text = Text(root)
		text.pack()
		text.insert(END, nmapoutput)

		defenselog.write(nmapoutput)

#Create button for launching nmap, logging info, then deauthing with aireplay
        def infodeauth(self):
		print 'Intensive intelligence gathering: >>>' + bcolors.WARNING + 'nmap -A -T4 -v -PE %s' % attackip + bcolors.ENDC
                nmapcmd = subprocess.Popen(['nmap', '-A', '-T4', '-v', '-PE', '%s' % attackip], stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
                nmapoutput = nmapcmd.communicate()[0]

                text = Text(root)
                text.pack()
                text.insert(END, nmapoutput)
                defenselog.write(nmapoutput)
		#time.sleep(5)

                print 'Preparing ammunition:             >>>' + bcolors.WARNING + 'airmon-ng start %s' % iface + bcolors.ENDC
                moncmd = subprocess.Popen(['airmon-ng', 'start', iface], stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
                montxt = moncmd.communicate()[0]
                findmon = re.search('(mon[0-9])', montxt)
                if findmon == None:
                        sys.exit('Interface could not be put into monitor mode. Exiting.')
                moniface = findmon.group()

                print 'Firing .50cal:                    >>>' + bcolors.WARNING + 'aireplay-ng -0 999999 -a %s -c %s %s' % (routermac, checkmac, moniface) + bcolors.ENDC
                deauthcmd = subprocess.Popen(['aireplay-ng', '-0', '5', '-a', '%s' % routermac, '-c', '%s' % checkmac, '%s' % moniface], stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
                deauthoutput = deauthcmd.communicate()[0]

                text = Text(root)
                text.pack()
                text.insert(END, deauthoutput)

		defenselog.write(deauthoutput)

		MonExit = subprocess.Popen(['airmon-ng', 'stop', '%s' % moniface], stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))

#Check router mac against router mac in arp table every .2 seconds
def compare():

	while 1:

		global checkmac
		global attackip
		global root

		checkcmd = subprocess.Popen('ip neigh', shell=1, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
		checktxt = checkcmd.communicate()[0]
		findcheck = re.search('(([a-fA-F0-9]{2}[:|\-]?){6})', checktxt)
		if findcheck == None:
			sys.exit("No active router MAC detected. Exiting.")
		checkmac = findcheck.group()
#		print 'Updated gateway MAC: %s' % checkmac

		if checkmac != routermac:		
			checkip = subprocess.Popen('ip neigh', shell=1, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
			checkiptxt = checkip.communicate()[0]
			findattackip = re.search('(%s\d{1,3}) \w+ %s \w+ %s' % (ipprefix, iface, checkmac), checkiptxt)
			if findattackip == None:
				sys.exit("No attack IP found. Exiting")
			attackip = findattackip.group(1) 
			print '\nARP spoof detected! ' + bcolors.FAIL + '%s' % attackip + bcolors.ENDC + ' at ' + bcolors.FAIL + '%s' % checkmac+ bcolors.ENDC + ' is the attacker!\n'
			root = Tk()
			root.title('ARP Spoof found!')
			app = popup(root)
			Label(root,text='Attacker: %s at %s' % (attackip, checkmac)).pack(pady=10)
			root.mainloop()
			raw_input("Hit [Enter] to exit: ")
			defenselog.close()
			sys.exit("Quitting")

		time.sleep(.2) 

#Run the comparative function which will then call Tkinter GUI
compare()

