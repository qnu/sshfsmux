

# Quick Start #

## Install ##
If your machine can run SSHFS, then SSHFS-MUX should also run without problem. Download stable package from [here](http://code.google.com/p/sshfsmux/downloads/list) or checkout latest source code by
```
$ hg clone https://sshfsmux.googlecode.com/hg/ sshfsmux
```

To install prerequisite [GNOME library](http://library.gnome.org/) in Debian/Ubuntu system, simply type
```
$ sudo apt-get install libglib2.0-dev
```

Then compile sshfsm as usual,
```
$ ./configure
$ make
$ make install
```

## Mount ##
```
$ sshfsm  hostA:dirA  hostB:/dirB  hostC:  mountpoint
```

## Unmount ##
```
$ fusermount -u mountpoint
```
`*`_fusermount should be already installed if your system has FUSE_.

# Advanced Usage #

Please use "`sshfsm -h`" and "`man sshfsm`" for quick reference.

## Host Attributes ##

SSHFS-MUX allows fine-grained control of how to connect a host by using _host attributes_.

### Rank ###
Each host is attached with a _rank_ during the mount time, according the its appearance in command arguments. And host with higher rank is the place where file looking up first takes place and new files are created. For example, in following case,

```
$ sshfsm hostA:dirA hostB:/dirB hostC: mountpoint
```

the rank of hostA > the rank of hostB > the rank of hostC.

When a file lookup, e.g. `stat()`, is issued, SSHFS-MUX first searches at dirA
of hostA. If the target file is found, then it stops further searching and
return to application. Otherwise, it continues search in hostB and hostC until
the target file is found or returns `ENOEXIST` if the target file does not
exist.
When some file is newly created, e.g. `mkdir()` or `creat()`, it is also
created in host with higher rank.

Therefore, you can straightforwardly arrange hosts in command arguments based on your preference, e.g., distances from your local desktop.

### Local Mode ###
_Local mode (l-mode)_ is useful when you want to merge and manipulate files in
local server with files in remote servers.
Though you can do
```
$ sshfsm localhost: remotehost: mountpoint
```
where SSHFS-MUX spans a connection to localhost and starts SFTP server as
usuall.

In following case,
```
$ sshfsm localhost:=l remotehost: mountpoint
```
SSHFS-MUX directly access the local file system using native file system calls
instead of SFTP, which achieves a better performance.

Also, you can use SSHFS-MUX as UnionFS/UnionFS-FUSE with local mode. For example,
```
$ sshfsm localhost:/directory1=l localhost:/directory2=l mountpoint
```

### Preserve Mode ###
_Preserve mode (p-mode)_ is like local mode, but uses _unix domain_
socket to connect local sftp server, where "`-o sftp_server=PATH`" is used to
specify the path of local SFTP server.

This is option originally provided for developement, debug, and performance
tuning.

### Using Raw Socket for High-Throughput Transfer ###
Option "`-o directport=PORT`" allows SSHFS/SSHFS-MUX to use raw sockets
bypassing ssh channels and connect to remote sftp-server subsystem.
This feature requires an intermediate server should wait connection on
specified port and bridge SFTP server for you.

Start a listen server on server side as follows

```
server$ sshfsm -D [-p 5285] [-o sftp_server=PATH]
```

and then connect to the server using

```
client$ sshfsm -o directport=5285 server: mountpoint
```

SInce using raw socket also bypasses the SSH authentication, it is not safe if we allow any client to connect the server. SSHFS-MUX implemented a simple challenge handshake protocol to authenticate client before establishing the SFTP connections. Therefore, users should provide pre-shared key files "`~/.sshfsm/key`" on both client and server sides with the same key stored in them. Also, it is strongly recommended that you shutdown server daemon by "`killall sshfsm`" after you finished using the file system.

However, if you concern your data integrity and security, you should go back
to SSH or try [HPN-SSH](http://www.psc.edu/networking/projects/hpn-ssh/).

# FAQ #
Since SSHFS-MUX is fully compatible with SSHFS, please check SSHFS [FAQ](http://sourceforge.net/apps/mediawiki/fuse/index.php?title=SshfsFaq) first.

# Bug Reports #
Please go to [Issues](http://code.google.com/p/sshfsmux/issues/list) page to report bugs and submit your feature requests.