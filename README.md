ssopass
=======

Similar to sshpass but goes one step further enabling the user to log into a privileged account.
libssh (http://www.libssh.org) is required to compile as follows:

`gcc -o ssopass ssopass.c ttymodes.c -lssh`

Example
-------

This gets the user into a root shell on the remote host (via sudo)
```
bash-4.2$ exec 3<<<mypassword
bash-4.2$ ./ssopass -h 192.168.1.20 -u quick -d 3 -s root -t sudo
Last login: Sat Jan  3 15:52:02 2015 from laptop.linuxproblems.org
-bash-4.1$ sudo bash
[sudo] password for quick: 
[root@centos quick]#
```
