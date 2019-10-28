#!/usr/bin/python3
# Imports
import socket
import sys
import requests
from colorama import Fore, Style
from warnings import filterwarnings
import concurrent.futures
import masscan
import dns.resolver
import argparse
from base64 import b64decode
from pyfiglet import Figlet
# Imports

################################
#          Globals             #
################################
# Ignore warnings
filterwarnings('ignore')

# Ports for masscan
smtp = '25'
https = '443'
ldap = 389

# Initialize masscan
mas = masscan.PortScanner()

# Border
middle = '-' * 60
border = f"[+] {middle} [+]"

# Graphics
banner = Figlet(font='cyberlarge')

################################
#           Globals            #
################################

def get_args():
	parser = argparse.ArgumentParser(description="Exchange/Domain Controller Hunter for PrivExchange.")
	parser.add_argument('-d','--domain',type=str,help="Target Domain.")

	args = parser.parse_args()

	return args

def smtp_scan():
	print(Fore.BLUE+border+Style.RESET_ALL)
	print(Fore.YELLOW+"[*] Using Masscan to Scan for SMTP Servers"+Style.RESET_ALL)
	print(Fore.BLUE+border+Style.RESET_ALL)

	smtp_servers = []

	try:
		mas.scan(ports=smtp,arguments='-sS -Pn -n --randomize-hosts -v --rate=10000 --range=10.0.0.0/8 --range=172.16.0.0/12 --range=192.168.0.0/16')
	except Exception as e:
		print(Fore.RED+f"[!] ERROR: {e}"+Style.RESET_ALL)

	for ip in mas.scan_result['scan']:
		smtp_servers.append(ip)

	return smtp_servers

def https_scan(smtp_servers):
	print(Fore.BLUE+border+Style.RESET_ALL)
	print(Fore.YELLOW+"[+] Using Masscan to Scan SMTP Servers for Open HTTPS"+Style.RESET_ALL)
	print(Fore.BLUE+border+Style.RESET_ALL)

	https_list = []

	for sublist in cut_list(smtp_servers, 255):
		sublist_string = " ".join(sublist)
		try:
			mas.scan(sublist_string, ports=https, arguments='-sS -Pn -n --randomize-hosts -v --rate=10000')
		except Exception as e:
			print(Fore.RED+f"[!] Error: {e}"+Style.RESET_ALL)
		for ip in mas.scan_result['scan']:
			https_list.append(ip)

	return https_list

def make_request(ip):
	print("\033[K", end='\r')
	print(Fore.YELLOW+f"    [+] Trying IP: {ip}"+Style.RESET_ALL, end='\r')
	url = f'https://{ip}/ews/Exchange.aspx'
	user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
	headers = {'User-Agent':user_agent}
	try:
		r = requests.get(url, verify=False, timeout=3)
		if 'WWW-Authenticate' in r.headers:
			return ip
	except Exception as e:
		print(Fore.RED+f"[!] ERROR: {e}"+Style.RESET_ALL)
	print("\033[K", end='\r')

def save_to_file(list_, type):
	if type == 'exchange':
		f = open('exchange-servers.txt', 'w+')
		for ip in list_:
			f.write(ip+"\n")
		f.close()
	elif type == 'dcs':
		f = open('domain-controllers.txt', 'w+')
		for ip in  list_:
			f.write(ip+"\n")
		f.close()

def cut_list(list_,n):
	for i in range(0, len(list_), n):
		yield list_[i:i +n]

def a_lookup(record):
	ip = ""
	answers = dns.resolver.query(record,'A')
	for ip in answers:
		return ip

def get_dnsServers(args):
	dnsServers = {}
	answers = dns.resolver.query(args.domain,'NS')
	for record in answers:
		record = str(record).strip('.')
		dnsServers[record] = a_lookup(record)
	return dnsServers

def srv_lookup(args, dnsServers):
	srv_record = f"_ldap._tcp.dc._msdcs.{args.domain}"
	dcs = {}
	records = []
	for k,v in dnsServers.items():
		dnsServer = str(v)
		my_resolver = dns.resolver.Resolver()
		my_resolver.nameservers = [dnsServer]
		try:
			answers = my_resolver.query(srv_record, 'SRV')
			for data in answers:
				dc = str(data).split(' ')[3].strip('.')
				if dc not in dcs:
					dcs[dc] = a_lookup(dc)
		except Exception as e:
			continue
	return dcs

def ldap_check(ip):
	print("\033[K", end='\r')
	print(Fore.YELLOW+f"    [+] Trying IP: {ip}"+Style.RESET_ALL)
	try:
		ip = str(ip)
		sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.settimeout(3)
		result = sock.connect_ex((ip, ldap))
		if result == 0:
			return ip
	except socket.error as se:
		print(Fore.RED+f"[!] ERROR: {se}"+Style.RESET_ALL)
	print("\033[K", end='\r')

def main():
	args = get_args()

	if args.domain is not None:
		# Print Banners
		print(Fore.GREEN+Style.BRIGHT+banner.renderText('exchange hunter')+Style.RESET_ALL)

		print(Fore.BLUE+border+Style.RESET_ALL)
		print(Fore.GREEN+Style.BRIGHT+"[+] Hunting for Exchange Servers..."+Style.RESET_ALL)
		print(Fore.BLUE+border+Style.RESET_ALL)

		smtp_servers = smtp_scan()

		https_list = https_scan(smtp_servers)

		print(Fore.BLUE+border+Style.RESET_ALL)
		print(Fore.YELLOW+f"[+] Number of hosts with both SMTP and HTTPS Open: {len(https_list)}"+Style.RESET_ALL)
		print(Fore.BLUE+border+Style.RESET_ALL)

		results = []
		exchange_servers = []
		with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
			future_to_url = {executor.submit(make_request, ip): ip for ip in https_list}
			for future in concurrent.futures.as_completed(future_to_url):
				url = future_to_url[future]
				try:
					results.append(future.result())
				except Exception as exc:
					print(Fore.RED+f"[!] ERROR: {exc}"+Style.RESET_ALL)

		for result in results:
			if result is not None:
				exchange_servers.append(result)
			else:
				continue

		print(Fore.BLUE+border+Style.RESET_ALL)
		print(Fore.GREEN+Style.BRIGHT+f"[+] Number of Exchange Servers Found: {len(exchange_servers)}"+Style.RESET_ALL)
		print(Fore.YELLOW+"[+] Saving Exchange Server IP's to exchange-servers.txt"+Style.RESET_ALL)
		print(Fore.BLUE+border+Style.RESET_ALL)

		save_to_file(exchange_servers, 'exchange')
		print(Fore.YELLOW+"[+] File Saved: exchange-servers.txt"+Style.RESET_ALL)

		print(Fore.BLUE+border+Style.RESET_ALL)
		print(Fore.YELLOW+"[+] Hunting for Domain Controllers Now."+Style.RESET_ALL)
		print(Fore.BLUE+border+Style.RESET_ALL)

		print(Fore.YELLOW+"[+] Looking for DNS Servers Now"+Style.RESET_ALL)
		print(Fore.BLUE+border+Style.RESET_ALL)
		dnsServers = get_dnsServers(args)

		print(Fore.GREEN+Style.BRIGHT+f"[+] Number of DNS Servers Found: {len(dnsServers)}"+Style.RESET_ALL)
		print(Fore.YELLOW+"[+] Querying DNS Servers For DC SRV Records."+Style.RESET_ALL)
		print(Fore.BLUE+border+Style.RESET_ALL)
		dcs = srv_lookup(args, dnsServers)

		print(Fore.GREEN+Style.BRIGHT+f"[+] Number of DC SRV Records Found: {len(dcs)}"+Style.RESET_ALL)
		print(Fore.YELLOW+"[+] Performing quick port scan on DC's to check LDAP"+Style.RESET_ALL)
		print(Fore.BLUE+border+Style.RESET_ALL)
		dc_ips = []

		for k,v in dcs.items():
			dc_ips.append(v)

		results = []
		valid_dcs = []

		with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
			future_to_url = {executor.submit(ldap_check, ip): ip for ip in dc_ips}
			for future in concurrent.futures.as_completed(future_to_url):
				url = future_to_url[future]
				try:
					results.append(future.result())
				except Exception as exc:
					print(Fore.RED+f"[!] ERROR: {exc}"+Style.RESET_ALL)
		for result in results:
			if result is not None:
				valid_dcs.append(result)
			else:
				continue

		print(Fore.GREEN+Style.BRIGHT+f"[+] Number of Viable DCs: {len(valid_dcs)}"+Style.RESET_ALL)
		print(Fore.YELLOW+"[+] Saving Viable Domain Controller IP's to domain-controllers.txt"+Style.RESET_ALL)

		save_to_file(valid_dcs, 'dcs')
		print(Fore.YELLOW+"[+] File Saved: domain-controllers.txt"+Style.RESET_ALL)

	else:
		print(Fore.GREEN+Style.BRIGHT+banner.renderText('exchange hunter')+Style.RESET_ALL)
		print(Fore.RED+"[!] Look at help menu for correct options."+Style.RESET_ALL)
		exit(-1)

if __name__ == '__main__':
	main()
