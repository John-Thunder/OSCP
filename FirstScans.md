# NMAP First Scans
```
# double check with ping sweep
sudo nmap -pN -oA PingScan 192.168.1.0/24
# look for interesting things one might want to attack
sudo nmap -A -sV -sC -p T:21-25,53,80,110,135-139,389,443,445,465,993,995,1433,1434,3389,8000,8080 -oA TCPScan 192.168.1.0/24    
sudo nmap -A -sV -sC -sU -p U:53,135-139,1434 -oA UDPScan 192.168.1.0/24
```


# Feroxbuster grab everything
will need to be modified to work. 
```
feroxbuster -e -f -k -x js php ini inf jsp htm html json pdf txt xlsx docx svg axd -w /usr/share/wordlists/dirb/common.txt -u http://10.129.35.132/login.php 
```
More usable searches
```
feroxbuster -e -k -x js php htm html json txt-w /usr/share/wordlists/dirb/common.txt -u http://10.129.35.132/login.php 
feroxbuster -e -f -k -w /usr/share/wordlists/dirb/common.txt -u http://10.129.35.132
```


































