# First Scans
```
# look for interesting things one might want to attack
sudo nmap -A -sV -sC -p T:21-25,53,80,8000,8080,443,110,135-139,389,1433,1434 -oA TCPScan 192.168.1.0/24    
sudo nmap -A -sV -sC -sU -p U:53,135-139,1434 -oA UDPScan 192.168.1.0/24
# double check with ping sweep
sudo nmap -pN -oA PingScan 192.168.1.0/24
```








































