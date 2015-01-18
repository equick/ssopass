ssopass
=======

Similar to sshpass but goes one step further enabling the user to log into a remote host and then into a privileged account either through sudo or pbrun. It also works with jumphosts eg, for accessing hosts in the dmz.

At the moment this only works for interactive sessions.


Dependencies
------------

libssh (http://www.libssh.org) is required to compile as follows:

`gcc -o ssopass ssopass.c ttymodes.c -lssh`

Examples
--------

Log into 192.168.1.20 as myuser and sudo to root
`exec 3<<<mypassword
`ssopass -h 192.168.1.20 -u quick -d 3 -s root -t sudo

```
Last login: Sat Jan  3 15:52:02 2015 from laptop
-bash-4.1$ sudo bash
[sudo] password for quick: 
[root@192.168.1.20]#
```

Log into 192.168.1.20 as testuser
`exec 4<<<mypassword
`ssopass -h 192.168.1.20 -u quick -d 4 -s testuser -t sudo

```
Last login: Sun Jan 18 13:08:21 2015 from laptop
-bash-4.1$ sudo -u testuser bash
[sudo] password for quick: 
[testuser@192.168.1.20]$ 
```

Log into 192.168.1.24 via the jump host 192.168.1.20 and sudo to test user
`exec 4<<<mypassword
`ssopass -h 192.168.1.24 -j 192.168.1.20 -u quick -d 4 -s testuser -t sudo

```
[quick@192.168.1.20 ~]$ ssh -t 192.168.1.24 sudo -u testuser bash
quick@192.168.1.24's password: 
[sudo] password for quick: 
[testuser@192.168.1.24]$ 
```

Log into 192.168.1.20 as testuser using powerbroker
`exec 4<<<mypassword
`ssopass -h 192.168.1.20 -u quick -d 4 -s testuser -t pbrun

```
-bash-4.1$ pbrun -u testuser bash
Password:
[testuser@192.168.1.20]$
```

Log into 192.168.1.25 via the powerbroker gateway 192.168.1.20 and become testuser using powerbroker
`exec 4<<<mypassword
`ssopass -h 192.168.1.25 -j 192.168.1.20 -u quick -d 4 -s testuser -t pbrun

```
[quick@192.168.1.20 ~]$ pbrun -h 192.168.1.24 -u testuser bash
Password:
[testuser@192.168.1.24]$
```

TODO
----

* Add functionality for sudo and powerbroker - fixed in ssopass (18/01/15)
* Add functionality to log in via a jumpbox - fixed in ssopass (18/01/15)
* Handle non-interactive sessions
* Handle window resizing
* copy profile to remote host
