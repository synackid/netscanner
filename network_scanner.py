import os
import sys
import time
from scapy.all import *

bold = '\033[1m'
normal = '\033[0m'
white = "\033[37m"
red = "\033[31m"
green = "\033[32m"

				

def clearConsole():
	cmd = 'clear'
	if os.name in ('nt', 'dos'):  
		cmd = 'cls'
	os.system(cmd)


def banner():
	clearConsole()
	print(bold + """

  _   _      _    _____                                 
 | \ | |    | |  / ____|                                
 |  \| | ___| |_| (___   ___ __ _ _ __  _ __   ___ _ __ 
 | . ` |/ _ \ __|\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |\  |  __/ |_ ____) | (_| (_| | | | | | | |  __/ |   
 |_| \_|\___|\__|_____/ \___\__,_|_| |_|_| |_|\___|_|   
                										
-------------------Coded By SynAckID-------------------""" + normal)

	

def menu():
	print("")
	print(bold + "[*] Choose the scan type: " + normal)
	print(bold + "1" + normal + " - Host Discovery: ARP_Scan")

	print(bold + "2" + normal + " - Portscan: SYN_Scan")

	print(bold + "3" + normal + " - Portscan: TCP_Scan")

	print(bold + "4" + normal + " - Portscan: UDP_Scan")
	
	print(bold + "5" + normal + " - Exit")
	
	print("")
	print("")


		
def ctrlc():
	print("")
	print(bold + "[*] Ctrl-C pressed." + normal)
	print(bold + "[*] Quitting" + normal)
	sys.exit(0)



def check_file():
		if os.path.exists('result.tmp'):
			os.remove('result.tmp')

def main():
	while True:
		check_file()
		banner()
		menu()
		choice = input(str())	
		print("")
		if choice == "1":				
			clearConsole()
			print(bold + """
  _    _           _   _____  _                                   
 | |  | |         | | |  __ \(_)                                  
 | |__| | ___  ___| |_| |  | |_ ___  ___ _____   _____ _ __ _   _ 
 |  __  |/ _ \/ __| __| |  | | / __|/ __/ _ \ \ / / _ \ '__| | | |
 | |  | | (_) \__ \ |_| |__| | \__ \ (_| (_) \ V /  __/ |  | |_| |
 |_|  |_|\___/|___/\__|_____/|_|___/\___\___/ \_/ \___|_|   \__, |
                                                             __/ |
                                                            |___/

--------------------------Coded By SynAckID-------------------------""" + normal)
			print("")
			#host scan
			interface = input(bold + "[*] Enter the interface name: " + normal)
			sub = input(bold + "[*] Enter the subnet to scan: " + normal)
			print("")
			print(bold + "[*] Scanning" + normal)
			start_time = time.time()
			ans,unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst = sub),
						timeout=2,
						iface=interface,
						inter=0.1,
						verbose=0)
			print("")
			print(bold + "[*]\t   MAC\t\t- \tIP" + normal)
			W = "[*] \t   MAC\t\t-  \tIP\n" 
			with open("result.tmp","a+") as file:
					file.write(W)
					file.close
		

			for snd,rcv in ans:
				with open("result.tmp","a") as file:
					print(rcv.sprintf("[-] " + r"%Ether.src%   -  %ARP.psrc%"))
					V = (rcv.sprintf("[-] " + r"%Ether.src%   -  %ARP.psrc%") +"\n")
					file.write(V)
					file.close()
			print("")
			eta = (time.time() - start_time)
			print(bold + "[*] Scan finished" + normal)
			print(bold + "[*] The scan takes: " + normal + str(round(eta,2)) + bold + " seconds" + normal)
		
			print(bold + "[*] Do you want to save the result? [y/n]" + normal)		
			#save or delete file	
			save = input(bold + "[*] " + normal)
			while save not in ["y","n"]:
				save = input(bold + "[*] Please enter y o n: " + normal)
			if save == "y":
				new_name = (datetime.now().strftime("%d-%m-%Y_%H-%M-%S") + ".txt")
				if os.name in ('nt', 'dos'):
					os.rename('result.tmp', '.\\host_discovery_results\\'+ new_name)
				else:
					os.rename('result.tmp', './host_discovery_results/'+ new_name)
			elif save =="n":
					os.remove("result.tmp")	
			print("")
			q = input(bold + "[*] Press a key to go back" + normal ) 
			





		elif choice == "2":
			clearConsole()
			print( bold + """
 _______   ___   _                     
/  ___\ \ / / \ | |                    
\ `--. \ V /|  \| |___  ___ __ _ _ __  
 `--. \ \ / | . ` / __|/ __/ _` | '_ \ 
/\__/ / | | | |\  \__ \ (_| (_| | | | |
\____/  \_/ \_| \_/___/\___\__,_|_| |_|
                                       
--------------Coded By SynAckID------------""" + normal)
			print("")
			host = input(bold + "[*] Enter the IP: " + normal)
			#hostname resolution
			try:
				h = socket.gethostbyaddr(host)
				print(bold + "[*] " + normal + str(h))
			except socket.herror:
				print(bold + "[*] Unknow Host" + normal)
			except socket.gaierror:
				print(bold + "[*] Host unreachable" + normal)
			start_time = time.time()
			#syn scan
			with open("ports.txt", "r") as porte:
				ports = porte.read().split(",")
			porte.close()
			print(bold + "[*] Scanning" + normal)
			for port in ports:
				with open("result.tmp","a") as result:
					try:
						request = IP(dst=host)/TCP(dport=int(port), flags='S')
						response = sr1(request, timeout=1, verbose=0)
						if response.getlayer(TCP).flags=='SA':
							print(bold + "[*] " + green + "Open: " + normal + white + str(port))
							V = ("Open: " + str(port) + "\n")
							result.write(V)
							sr1( IP(dst=host)/TCP(dport=int(port), flags='R'), timeout=1, verbose=0)
						else:
							print(bold + "[*] " + red + "Closed: " + normal + white + str(port))
							V = ("Closed: " + str(port) + "\n")
							result.write(V)
					except AttributeError:
						print(bold + "[*] " + red + "Closed: " + normal + white + str(port))
						V = ("Closed: " + str(port) + "\n")
						result.write(V)
				result.close()
			eta = (time.time() - start_time)
			print(bold + "[*] The scan takes: " + str(round(eta,2)) + " seconds" + normal)
			print("")
			print(bold + "[*] Do you want to save the result? [y/n]" + normal)		
		
			#save or delete file	
			save = input(bold + "[*] " + normal)
			while save not in ["y","n"]:
				save = input(bold + "[*] Enter y o n: " + normal)
			if save == "y":
				new_name = (datetime.now().strftime("%d-%m-%Y_%H-%M-%S") + ".txt")
				if os.name in ('nt', 'dos'):
					os.rename('result.tmp', '.\\syn_scan_results\\'+ new_name)
				else:
					os.rename('result.tmp', './syn_scan_results/'+ new_name)
				
			elif save =="n":
				os.remove("result.tmp")
			print("")
			q = input(bold + "[*] Press a key to go back" + normal)




		elif choice == "3":
			clearConsole()
			print( bold + """
  _______ _____ _____                     
 |__   __/ ____|  __ \                    
    | | | |    | |__) |__  ___ __ _ _ __  
    | | | |    |  ___/ __|/ __/ _` | '_ \ 
    | | | |____| |   \__ \ (_| (_| | | | |
    |_|  \_____|_|   |___/\___\__,_|_| |_|

--------------Coded By SynAckID------------""" + normal)
			print("")
			host = input(bold + "[*] Enter the IP: " + normal)
			#hostname resolution
			try:
				h = socket.gethostbyaddr(host)
				print(bold + "[*] " + normal + str(h))
			except socket.herror:
				print(bold + "[*] Unknow Host" + normal)
			except socket.gaierror:
				print(bold + "[*] Host unreachable" + normal)
			start_time = time.time()
			with open('ports.txt', "r") as file:
				ports = file.read().split(",")
			file.close()
			print(bold + "[*] Scanning" + normal)
			for port in ports:
				with open("result.tmp","a") as results:
					try:
						s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						s.settimeout(0.5)
						check_conn = s.connect_ex((host,int(port)))
						if check_conn == 0:
							try:
								service = socket.getservbyport(int(port))
								#banner = s.recv(100)
								print(bold + "[*] " + green + "Open: " + normal + white + str(port) + green + bold + " Service: " + normal + white + str(service)) 
								V = ("Open: " + str(port) + " Service: " + str(service) + "\n")
								results.write(V)
							except socket.timeout:
								print(bold + "[*] Timeout" + normal)
							except OSError: 
								pass	
							except KeyboardInterrupt:
								pass			
							s.close()
						else:	
							print(bold + "[*] " + red + "Closed: " + normal + white + str(port))
							V = ("Closed: " + str(port) + "\n")
							results.write(V)
							s.close()
					except socket.gaierror:
						print(bold + "[*] Host Unreachable" + normal)
					except KeyboardInterrupt:
						pass
			results.close()

			eta = (time.time() - start_time)
			print(bold + "[*] The scan takes: " + str(round(eta,2)) + " seconds" + normal)
			print("")
			print(bold + "[*] Do you want to save the result? [y/n]" + normal)		
		
			#save or delete file	
			save = input(bold + "[*] " + normal)
			while save not in ["y","n"]:
				save = input(bold + "[*] Enter y o n: " + normal)
			if save == "y":
				new_name = (datetime.now().strftime("%d-%m-%Y_%H-%M-%S") + ".txt")
				if os.name in ('nt', 'dos'):
					os.rename('result.tmp', '.\\tcp_scan_results\\'+ new_name)
				else:
					os.rename('result.tmp', './tcp_scan_results/'+ new_name)
				
			elif save =="n":
				os.remove("result.tmp")	
			print("")
			q = input(bold + "[*] Press a key to go back" + normal)

				
		
		elif choice == "4":
			clearConsole()
			print( bold + """
  _    _ _____  _____                     
 | |  | |  __ \|  __ \                    
 | |  | | |  | | |__) |__  ___ __ _ _ __  
 | |  | | |  | |  ___/ __|/ __/ _` | '_ \ 
 | |__| | |__| | |   \__ \ (_| (_| | | | |
  \____/|_____/|_|   |___/\___\__,_|_| |_|

-------------Coded By SynAckID-------------""" + normal)
			print("")
			host = input(bold + "[*] Enter the IP: " + normal)
			with open("ports.txt", "r") as file:
				ports = file.read().split(",")
			file.close()
			start_time = time.time()
			for port in ports:
				with open("result.tmp","a") as file:				
					if True:
						try:	
							data = "HELLO"
							s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
							s.sendto(data.encode('utf_8'),(host,int(port)))
							s.settimeout(1)
							recv = s.recvfrom(1024)
							if recv == 0:
								print(bold + "[*] " + red + "Closed: " + normal + white + str(port))
								V = ("Closed: " + str(port) + "\n")
								file.write(V)		
							else:
								service = socket.getservbyport(int(port))
								print(bold + "[*] " + green + "Open: " + normal + white + str(port) + green + bold + " Service: " + normal + white + str(service))
								V = ("Open: " + str(port) + " Service: " + str(service) + "\n")
								file.write(V)
						except socket.timeout:
							print(bold + "[*] " + red + "Closed: " + normal + white + str(port))
							V = ("Closed: " + str(port) + "\n")
							file.write(V)
						except KeyboardInterrupt:
							pass
			file.close()
			eta = (time.time() - start_time)
			print(bold + "[*] The scan takes: " + str(round(eta,2)) + " seconds" + normal)
			print("")
			print(bold + "[*] Do you want to save the result? [y/n]" + normal)		
		
			#save or delete file	
			save = input(bold + "[*] " + normal)
			while save not in ["y","n"]:
				save = input(bold + "[*] Enter y o n: " + normal)
			if save == "y":
				new_name = (datetime.now().strftime("%d-%m-%Y_%H-%M-%S") + ".txt")
				if os.name in ('nt', 'dos'):
					os.rename('result.tmp', '.\\udp_scan_results\\'+ new_name)
				else:
					os.rename('result.tmp', './udp_scan_results/'+ new_name)
				
			elif save =="n":
				os.remove("result.tmp")	
			print("")
			q = input(bold + "[*] Press a key to go back" + normal)


		
		elif choice == "5":
			clearConsole()
			print( bold + """
   ____        _ _   _   _             _ 
  / __ \      (_) | | | (_)           | |
 | |  | |_   _ _| |_| |_ _ _ __   __ _| |
 | |  | | | | | | __| __| | '_ \ / _` | |
 | |__| | |_| | | |_| |_| | | | | (_| |_|
  \___\_\\__,_|_|\__|\__|_|_| |_|\__, (_)
                                  __/ |  
                                 |___/  

------------Coded By SynAckID------------""" + normal)
			print("")
			time.sleep(1)
			clearConsole()
			sys.exit(0)
			
					
		else:
			clearConsole()
			print( bold + """
  ____            _ _   _                 _               
 |  _ \          | | \ | |               | |              
 | |_) | __ _  __| |  \| |_   _ _ __ ___ | |__   ___ _ __ 
 |  _ < / _` |/ _` | . ` | | | | '_ ` _ \| '_ \ / _ \ '__|
 | |_) | (_| | (_| | |\  | |_| | | | | | | |_) |  __/ |   
 |____/ \__,_|\__,_|_| \_|\__,_|_| |_| |_|_.__/ \___|_|   
 
----------------------Coded By SynAckID---------------------""" + normal)
			print("")
			time.sleep(2)


	
	
if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		ctrlc()

	