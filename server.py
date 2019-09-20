#!/usr/bin/env python
# -*- coding: utf-8 -*-

# By: Lucas "K4L1" Nathaniel
# $ python server.py port

import subprocess
import hashlib
import sys
import socket
import threading
import datetime

_buffsize = 4096
_dehydrated = "/etc/dehydrated/"
_nginxAvaliable = "/etc/nginx/sites-available/"
_nginxEnabled = "/etc/nginx/sites-enabled/"

#Function for Log documentation and show outputs
def writeLog(message):
	print message
	with open("log.txt", "a") as log:
		log.write(str("%s | %s\n" %(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), message)))

#Function for execute bash scripts
def createProcess(bash_command, client):
	try:
		process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE)
		output, error = process.communicate()
	except:
		writeLog("Invalid: %s" %(bash_command))
		return closeConnection(client)
	return output

#Function for close connection
def closeConnection(client):
	client.close()
	return

#Mainly multithread function
def clientThread(client):

	msg = "Nitroglycerin | AutoForce\n"
	client.send(msg.encode())
	
	#Requisition should be: secret_hash:domain.com.br:subdomain1,subdomain2
	requisition = client.recv(_buffsize).strip().decode('ascii').split(":")
	try:
		secret_hash, domain, subdomains = requisition
	except:
		writeLog("Invalid Sintax: %s" %(requisition))
		return closeConnection(client)
	subdomains = " ".join(subdomains.split(","))

	#Check secret hash
	if( hashlib.sha256(secret_hash.encode()).hexdigest() != "01db4afde7cf5a7019454eedb3fe7c0ac892fc896bc185a0aac0c71d4b3f50b6"):
		writeLog("Invalid hash")
		return closeConnection(client)
	
	#Check host
	output = createProcess("host %s" %(domain), client)

	#Check Host IP for Digital Ocean
	if(output.split()[3][0:3] != "138"):
		writeLog("Invalid Host IP")
		return closeConnection(client)
	writeLog("Valid secret and Host IP C:")

	#Write domain
	old_domain = ""
	with open("%sdomains.txt" %(_dehydrated), "r") as domains_file:
		domain_lines = domains_file.readlines()
	with open("%sdomains.txt" %(_dehydrated), "w") as domains_file:
		for domain_line in domain_lines:
			if len(domain_line) >= 2:
				if domain_line.split()[0] != domain:
					domains_file.write(domain_line)
				else:
					subdomains += " "+" ".join(domain_line.split()[1:])
					subdomains = " ".join(list(dict.fromkeys(subdomains.split())))
					domains_file.write("%s %s\n" %(domain, subdomains))

	with open("%sdomains.txt" %(_dehydrated), "a") as domain_file:
		domain_file.write("%s %s\n" %(domain, subdomains))

	#Config Dehydrated
	output = createProcess("%sdehydrated -c -f %sconfig" %(_dehydrated, _dehydrated), client)
	if ("Challenge validation has failed :(") in output:
		writeLog("Generate certificate FAIL")
		return closeConnection(client)
	if ("Too Many Requests") in output:
		writeLog("Generate certificate FAIL | Too Many Requests")
		return closeConnection(client)

	#Config NGINX
	check_symbolic_link = "test -e %s%s; echo $?" %(_nginxAvaliable, domain)
	if(createProcess(check_symbolic_link, client) == 1):
		config_nginx = "cp %stemplate %s%s" %(_nginxAvaliable, _nginxAvaliable, domain)
		output = createProcess(config_nginx, client)
		replaceTemplate = "sed -i 's/dominio.com.br/%s/g' %s%s" %(domain, _nginxAvaliable, domain)
		output = createProcess(replaceTemplate, client)
		
		#Create Symbolic Link
		create_symbolic_link = "ln -s %s%s %s%s" %(_nginxAvaliable, domain, _nginxEnabled, domain)
		output = createProcess(create_symbolic_link, client)
	else:
		writeLog("File already exist: %s%s" %(_nginxEnabled, domain))

	#Check NGINX
	output = createProcess("nginx -t", client)
	writeLog("Log Check NGINX: %s" %(output))

	#Reload NGINX
	if "nginx: configuration file /etc/nginx/nginx.conf test is successful" in output:
		output = createProcess("systemctl reload nginx", client)
		writeLog("Log Reload NGINX: %s" %(output))
	client.close()

def main():
	#Verifing Execution
	if(len(sys.argv) != 2):
		writeLog("[*] Use: python server.py port")
		sys.exit()
	bind_ip = "0.0.0.0"
	bind_port = int(sys.argv[1])
	if(bind_port != 37337):
		writeLog("[*] WRONG PORT! >:(")
		sys.exit()
	
	#Check if port is already in use
	check_port_command = "lsof -t -i tcp:%s" %(str(bind_port))
	check_port_process = subprocess.Popen(check_port_command.split(), stdout=subprocess.PIPE)
	output, error = check_port_process.communicate()
	print "Old Process:", output
	if output != "":
		writeLog("[*] Port is already in use, trying restart the DEFAULT port(37337)...")
		kill_port_command = "kill -9 %s" %(output[0:-1])
		check_port_process = subprocess.Popen(kill_port_command.split(), stdout=subprocess.PIPE)

	#Create Connection
	print "[*] Connecting...",
	while 1:
		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			server.bind((bind_ip, bind_port))
			print ""
			break
		except:
			sys.stdout.write('.')
			continue

	#Connection is OK C:
	server.listen(5)
	writeLog("[*] Listening: %s %s" %(bind_ip, bind_port))

	while(1):
		client, addr = server.accept()
		writeLog("[*] New Client: %s %s" %(addr[0], addr[1]))
	
		#Thread start here:
		client_handler = threading.Thread(target=clientThread, args=(client,))
		if(client_handler == 1):
			continue
		client_handler.start()
	server.close()

if __name__ == '__main__':
	try:
		main()
	except (KeyboardInterrupt):
		print "Exiting by KeyboardInterrupt!"
