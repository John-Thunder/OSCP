# theHarvester: Automated OSINT Email Gathering
requires some apis setup. 
```
theHarvester -d <domain> -b all 
```

# NMAP: Network Scan
check network with ping sweep
```
sudo nmap -sn -oA PingScan 192.168.1.0/24
```
get just the IP addresses for further searches. 
```
awk '{ print $2 }' PingScan.gnmap | sed 's/Nmap//g' > up.txt
```
look for interesting things one might want to attack
```
sudo nmap -A -sV -sC -p T:21-25,53,80,110,135-139,389,443,445,465,993,995,1433,1434,3389,8000,8080 -oA TCPScan 192.168.1.0/24    
sudo nmap -A -sV -sC -sU -p U:53,135-139,1434 -oA UDPScan 192.168.1.0/24
```
look for interesting things one might want to attack from up.txt to save time
```
sudo nmap -A -sV -sC -p T:21-25,53,80,110,135-139,389,443,445,465,993,995,1433,1434,3389,8000,8080 -oA -iL up.txt
sudo nmap -A -sV -sC -sU -p U:53,135-139,1434 -oA UDPScan -iL up.txt
```

# Feroxbuster: Website File and Directory Discovery
grab everything. will need to be modified to work. 
```
feroxbuster -e -f -k -x js php ini inf jsp htm html json pdf txt xlsx docx svg axd -w /usr/share/wordlists/dirb/common.txt -u http://10.129.35.132/login.php 
```
More usable searches
```
feroxbuster -e -k -x js php htm html json txt-w /usr/share/wordlists/dirb/common.txt -u http://10.129.35.132/login.php 
feroxbuster -e -f -k -w /usr/share/wordlists/dirb/common.txt -u http://10.129.35.132
```

# Nikto: Vulnerability Scanner
Hosts, ports and protocols may also be specified by using a full URL syntax, and it will be scanned:
```
nikto -h https://192.168.0.1:443/
```
There is no need to specify that port 443 is encrypted, as Nikto will first test regular HTTP and if that fails, HTTPS. If you are sure it is an SSL/TLS server, specifying -s (-ssl) very slightly will speed up the test (this is also useful for servers that respond HTTP on port 443 even though content is only served when encryption is used).
```
nikto -h 192.168.0.1 -p 443 -ssl
```
Nikto can scan multiple ports in the same scanning session. To test more than one port on the same host, specify the list of ports in the -p (-port) option. Ports can be specified as a range (i.e., 80-90), or as a comma-delimited list, (i.e., 80,88,90). This will scan the host on ports 80, 88 and 443.
```
nikto -h 192.168.0.1 -p 80,88,443
```































