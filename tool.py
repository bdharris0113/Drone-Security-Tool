import os,re,commands,sys
from subprocess import Popen, PIPE
import ftplib

def tools_needed():
	print "the dependencies needed for this tool to function properly are:"
	print "ftp"
	print "nmap"
	print "telnet"
	print "netdiscover"
	print "aircrack-ng"
	print
	print "if for any reason the install failed, the following commands were used to install the programs listed above"
	print 'sudo apt-get install <program_name>'
	print 'where program_name is any of the above programs (eg telnet)'
	print "if you are having further problems and google has failed you, post a comment on the git for this tool"
	pause = raw_input('press enter to continue')


def tutorial(ip):
	print "Nmap will scan the entire network looking for device names, OS detection, and as much information about all devices it can gather"
	print "This process is slow, since its gathering lots of information about all devices on the network , but makes it easier to find the drone , since more info is displayed"
	print "Nmap needs a network range to scan, defalt it scans all devices on your controllers/computers network, but you can reset this to any IP range you wish"
	print
	print "Netdiscover works very fast, scanning all devices on the network (as well as other networks), but displays limited info about each device."
	print "for Netdiscover, press Control+C when finished scanning for your drone"
	print
	print "BE SURE TO WRITE DOWN THE IP ADDRESS SO YOU DON'T HAVE TO RESCAN"
	print "For either selection , if you aren't sure which is your drone, or simply don't see it listed, you can simply pick nothing and no scanning will be performed"
	pause = raw_input('press enter when ready to continue onto selection')
	find_drone_ip(ip)


def install_dep():
	os.system("sudo apt-get update")
	os.system("sudo apt-get upgrade")
	os.system("sudo apt-get install ftp")
	os.system("sudo apt-get install nmap")
	os.system("sudo apt-get install telnet")
	os.system("sudo apt-get install netdiscover")
	os.system("sudo apt-get install aircrack-ng")
	pause = raw_input('system updated and dep installed; press enter to continue')
	return

def get_ipmac():
	os.system("ifconfig")
	data = Popen(['ifconfig'], stdout=PIPE).communicate()
	a =  data[0].split('\n\n')
	ip,mac = '',''
	for i in a:
		if "lo:" in i:
			pass
		elif "inet " in i:
			ip = re.search('inet .* n',i)
			mac = re.search('.{2}:.{2}:.{2}:.{2}:.{2}:.{2}',i)

	if ip:
		ip = ip.group(0)
		ip = ip[5:-2]
	else:
		print "i couldn't find your IP "
		print "it should be the number following inet in your network"
		ip = input('please input your ip')
	if mac:
		mac = mac.group(0)
	else: 
		print "i coldn't find your mac"
		print "it should be the number following 'ether'"
		mac = raw_input('please input your mac')

	pause = raw_input('ip/mac set, press enter to continue')

	return ip,mac

def check_ipmac(ip,mac):
	test1,test2 = False,False
	mactest = re.search('.{2}:.{2}:.{2}:.{2}:.{2}:.{2}',mac)
	if mactest:
		test1 = True
	else:
		print "your mac address was not in the correct format"
		print 'it must be in the form:   00:00:00:00:00:00'
	iptest = re.search('\d*\.\d*\.\d*\.\d*',ip)
	if iptest:
		test2 = True
	else:
		print 'your ip address was not in the correct format'
		print 'it must be in the form:    xxx.xxx.xxx.xxx'
		print 'where x is a number (each octet does not have to be 3 in length'
	if test1 and test2:
		print 'your ip is: ',ip
		print 'your mac is: ',mac
		return
	else:
		print "1) try again"
		print "2) return to main menu"
		selection = input("try again, or return to menu?")
		if selection == 1:
			ip = raw_input("what is your ip?")
			mac = raw_input("what is your mac?")
			check_ipmac(ip,mac)
		else:
			print 'your ip is: ',ip
			print 'your mac is: ',mac
			return

def encryption(drone_ip,drone_mac):
	os.system('clear')
	pause = raw_input("if you haven't yet, please plug in your wireless adapter (if needed); press enter when ready")
	os.system('ifconfig')
	wifi = raw_input("please input your wireless adapter's name (copy/paste): ")
	os.system('sudo airmon-ng start '+wifi)
	os.system('clear')
	os.system('iwconfig')
	new_wifi = raw_input("please copy/paste new wifi name (should end with mon, and hit enter ")
	os.system('clear')
	print "on the next screen you will see all available networks , with their encryption level"
	print 'opn = no encryption, wpa = bad encryption, wpa2 = good encryption'
	print "REMINDER: YOUR DRONE'S IP IS: ",drone_ip
	print "REMINDER: YOUR DRONE'S BSSID IS: ",drone_mac
	pause = raw_input("press enter to continue.  Press Control + C when finished monitoring")
	os.system('sudo airodump-ng '+new_wifi)
	os.system('sudo airmon-ng stop '+new_wifi)
	pause = raw_input("monitor mode has been turned off.  press enter to continue")
	check = raw_input("were you able to see your network traffic (y or n)? ")
	if check == 'y':
		pass
	elif check == 'n':
		os.system('clear')
		print "1) rescan for network"
		print "2) back to main menu"
		choice = raw_input('what would you like to do ?')
		if choice == 1:
			encrypted(drone_ip)
		else:
			return False
	os.system('clear')
	pause = raw_input("was your network traffic listed as either OPN or WPA (y or n)?  ")
	if pause == 'y':
		return False
	if pause == 'n':
		return True
		

def find_drone_ip(ip):
	os.system('clear')
	temp = re.search('\d*\.\d*\.\d*\.',ip)
	ip = temp.group(0) + '*'
	print "Nmap network to scan if selected: ",ip
	print "Nmap & Netdiscover will help you find your drone's IP."
	print "if you need advice or a refresher on either select option 0"
	print "0) help me pick"
	print "1) Nmap"
	print "2) Netdiscover"
	print "3) return to main menu"
	print "4) switch nmap network to scan"
	print
	select = input("would you like to search for your drone's IP/MAC with Nmap or Netdiscover?")
	if select == 0:
		tutorial(ip)
	elif select == 1:
		os.system('sudo nmap -Pn -f -O '+ip)
		pause = raw_input("write down the IP/MAC, or any usefull info.  Press enter when done")
	elif select == 2:
		os.system('sudo netdiscover')
	elif select == 3:
		return -9,-9
	elif select == 4:
		new_ip = raw_input("what is the network to scan (must be in the form xxx.xxx.xxx.xxx) ")
		check_ipmac(new_ip,'00:00:00:00:00:00')
		find_drone_ip(new_ip)
	print
	print "1) Yes i found it"
	print "2) No i didn't find it"
	select = raw_input("did you find your drone's ip?")
	if select == '1':
		drone_ip = raw_input("what is your drone's IP? ")
		drone_mac = raw_input("what is your drone's MAC? ")
		check_ipmac(drone_ip,drone_mac)
		return drone_ip,drone_mac
	else:
		print "1) try again with a new search"
		print "2) return to main menu"
		select = input('?  ')
		if select == 1:
			find_drone_ip(ip)
		else:
			return '',''

def open_ports(drone_ip):
	os.system('clear')
	print "We will use Nmap to scan your drone for open ports"
	pause = raw_input("press enter when ready   ")
	os.system('clear')
	#os.system('sudo nmap -Pn -f -O -oN open_ports.txt '+drone_ip)
	os.system('sudo nmap -Pn -F -oN opn_ports.txt '+drone_ip)
	print
	print
	port_data = []
	f = file('opn_ports.txt')
	data = f.readlines()
	f.close()

	for i in data:
		if "open" in i:
			port_data.append(i.rstrip('\n'))
	ports = []
	for line in port_data:
		tmp = ''
		for i in line:
			if i in '1234567890':
				tmp += i
			if i == '/':
				ports.append(tmp)
				break

	print ports
	print port_data
	pause = raw_input("Information has been saved.  Press enter when done")
	return ports,port_data


def check_services(drone_ip,ports):
	ssh_pass,ftp_pass,telnet_pass = '','',''
	os.system('clear')
	print "RUNNING TESTS ON OPEN PORTS"
	print "this may take a minute"
	if '21' in ports:
		try:
			ftp=ftplib.FTP(drone_ip)
			response = ftp.login()
			if '230' in response:
				ftp_pass = True
			else:
				ftp_pass = False
		except:
			pass
	if '22' in ports:
		try:
			username = 'bob'
			ret,out = commands.getstatusoutput("ssh -n -o PasswordAuthentication=no "+username+"@"+drone_ip)
			if ret == 0:
			   ssh_pass = False
			else:
			   ssh_pass = True
		except:
			pass
	if '23' in ports:
		try:
			data = Popen(['telnet','192.168.88.204'], stdout=PIPE).communicate()[0]
			if 'login' in data or 'password' in data:
				telnet_pass = True
			else:
				telnet_pass = False
		except:
			pass
	print
	print "ssh has a password: ", ssh_pass
	print "ftp has a password: ", ftp_pass
	print "telnet has a password: ", telnet_pass
	print
	pause = raw_input("info saved, press enter to continue")
	return ssh_pass,ftp_pass,telnet_pass

def summary(ports,encrypt,ssh_pass,ftp_pass,telnet_pass):
	no_pass = []
	if ftp_pass == False:
		no_pass.append('port 21: ftp')
	if ssh_pass == False:
		no_pass.append('port 22: ssh')
	if telnet_pass == False:
		no_pass.append('port 23: telnet')
	unknown = []
	for p in ports:
		if p not in [21,22,23]:
			unknown.append(p)
	os.system('clear')
	if encrypt:
		print "you are currently communicating to your drone on an encrypted network, no further work needed here"
	else:
		print "You are currently communicating to your drone on an unencrypted network.  This can be configured in the drone settings and should be fixed"
	print
	print '----------------------------------------------------------------------------------------------------------------------------------------------'
	print
	print "Currently you have the following ports open and unfiltered", ports
	print "These being unfiltered means anyone can attempt to talk to your drone on these ports at anytime."
	if len(no_pass) > 0:
		print "these known services are unfiltered and have no password protection "
		for i in no_pass:
			print i
		print "these can be fixed by accessing your drone from your computer/controller and setting a password (see tutorial video)"
	else:
		print "but all services listed above use a password , which means this doesn't need further attention"
	print
	if len(unknown) > 0:
		print "the other ports listed above, are running unknown services, but are open and unfiltered"
		print "a more thorough nmap scan can likely resolve what services and vulnerabilities these are ports are utilizing , but this is beyond the scope of this tool currently"
	else:
		print "you have no unknown services running on open ports, this is good and requires no further work from you"
	print
	pause = raw_input("when you have finished reading press enter to return to the main menu")
	return




def menu():
	ip,mac,drone_ip,drone_mac,ports,port_data,encrypt = '','','','',[],[],''
	ssh_pass,ftp_pass,telnet_pass = '','',''
	drone_ip,drone_mac = '192.168.88.204','F0:9F:C2:64:D2:61'
	#ip,mac = '192.168.88.188' ,'00:07:ba:54:90:ad'
	#ports = [21,22,23]
	'''
	21 = ftp
	22 = ssh
	23 = telnet
	'''
	while 1:
		os.system('clear')

		print "0) list tools to be installed"
		print "1) install dependencies & update system"
		print "2) get your ip/mac (your computer/controller)"
		print "3) input your ip/mac (i know what it is)"
		print "4) manually input drone's IP/mac (i already know it)"
		print "5) get your drone's ip/mac (i don't know it)"
		print "6) check encrypted traffic"
		print "7) scan for open ports"
		print "8) check port services for password protection"
		print "9) Security Summary"
		print "10) exit"
		print
		print "                                                       DATA"
		print
		print "                                           your ip is set at: ",ip
		print "                                           your mac is set at: ",mac
		print "                                           your drone's ip: ",drone_ip
		print "                                           your drone's MAC/BSSID: ",drone_mac
		print "                                           Encrypted traffic: ",encrypt
		print "                                           OPEN PORTS: ",ports
		print "                                           ssh_pass: ",ssh_pass
		print "                                           ftp_pass: ",ftp_pass
		print "                                           telnet_pass: ",telnet_pass

		selection = input("Please select an option: ")


		if selection == 0:
			tools_needed()
		elif selection == 1:
			install_dep()
		elif selection == 2:
			ip,mac = get_ipmac()
			check_ipmac(ip,mac)
		elif selection == 3:
			ip = raw_input("what is your ip?")
			mac = raw_input("what is your mac?")
			check_ipmac(ip,mac)
		elif selection == 4:
			drone_ip = raw_input("what is your drone's ip?")
			drone_mac = raw_input("what is your drone's mac?")
			check_ipmac(drone_ip,drone_mac)
		elif selection == 5:
			if ip == '':
				pause = raw_input("you must first get your controller/computer's ip.  press enter to continue")
			else:
				#drone_ip,drone_mac = find_drone_ip(ip)
				tmp1,tmp2 = find_drone_ip(ip)
				if tmp1 == -9:
					pass
				else:
					drone_ip,drone_mac = find_drone_ip(ip)
		elif selection == 6:
			encrypt = encryption(drone_ip,drone_mac)
		elif selection == 7:
			ports,port_data = open_ports(drone_ip)
		elif selection == 8:
			ssh_pass,ftp_pass,telnet_pass = check_services(drone_ip,ports)
		elif selection == 9:
			summary(ports,encrypt,ssh_pass,ftp_pass,telnet_pass)
		elif selection == 10:
			sys.exit()

menu()