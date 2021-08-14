# Disabling Windows Defender Anti-Virus and Firewall
## Disable Windows Defender from command line
1. Open command prompt with administrative privileges
2. Run the following command:
```
sc stop WinDefend
```

## Disable Windows Defender permanently from command line
run the following command:
```
sc config WinDefend start= disabled
sc stop WinDefend
```

## Check the current state of the Windows Defender service
run the following command:
```
sc query WinDefend
```
Check the STATE variable. It should be in RUNNING state if it is enabled.

## Permanently Disable Windows Defender Using PowerShell
1. Run PowerShell with administrative privileges (Windows key + X + A)
2. run the following command:
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

## Permanently Turn Off Windows Defender Using Group Policy
1. Open Group Policy Editor (Run –> gpedit.msc)
2. Go to Computer Configuration –> Administrative Templates –> Windows Components –> Windows Defender Antivirus
3. From the right-hand pane, open Turn off Windows Defender Antivirus and select Enabled
This setting can be accessed through Local Group Policy as well as Domain Group Policy. The local policy will turn off Windows Defender for all local users while the domain policy will disable it for all systems on which the policy is applied

## Permanently Disable Windows Defender Using Windows Registry
1. Go to Run –> regedit. This will open the Windows Registry Editor.
2. Navigate to the following key:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender
```
3. In the right pane, right-click the empty area and create a new DWORD (32-bit) value.
4. Rename the new item to DisableAntiSpyware
5. Double-click DisableAntiSpyware and change its value to 1.
Windows Defender will not load after the next computer restart. 

## Turn off Windows Firewall only
To turn off Windows Firewall only and keep using other Windows Defender functionality, follow the steps below:
1. Open Windows Settings (Windows key + i)
2. Click on Update & Security and then Windows Security
3. In the right-hand pane, click on Open Windows Security
4. From the left-hand pane, select Firewall & network protection
5. In the right-hand pane, you will see three protection types. Domain network, Private network, Public network.
6. Click on each network type and toggle it to disabled.
This will only turn off the firewall. The antivirus and other functionality of Windows Defender will keep on working.

## Turn off Windows Defender real-time antivirus only
If you want to turn off the antivirus real-time functionality only, you can follow the steps below:
1. Open Windows Settings (Windows key + i)
2. Click on Update & Security and then Windows Security
3. From the left-hand pane, click on Virus & threat protection
4. right-hand pane, toggle real-time protection to off.







