# libppspp

## Building

```shell script
mkdir build
cd build
cmake ..
make
```

## Usage

```
Peer-to-Peer Streaming Peer Protocol proof of concept
usage:
./ppspp: -acfhlpstv
-a ip_address:port:	numeric IP address and udp port of the remote SEEDER, enables LEECHER mode
			example: -a 192.168.1.1:6778
-c:			chunk size in bytes valid only on the SEEDER side, default: 1024 bytes
			example: -c 1024
-f dir or filename:	filename of the file or directory name for sharing, enables SEEDER mode
			example: -f ./filename
			example: -f /path/to/directory
-h:			this help
-l:			list of pairs of IP address and udp port of other seeders, separated by comma ','
			valid only for SEEDER
			example: -l 192.168.1.1:6778,192.168.1.2:6778,192.168.1.4:6778
-p port:		UDP listening port number, valid only on SEEDER side, default 6778
			example: -p 7777
-s sha1:		SHA1 of the file for downloading, valid only on LEECHER side
			example: -s 82da6c1c7ac0de27c3fedf1dd52560323e7b1758
-t:			timeout of network communication in seconds, default: 180 seconds
			example: -t 10
-v:			enables debugging messages

Invocation examples:
SEEDER mode:
./ppspp -f filename -c 1024
./ppspp -f filename -c 1024 -t 5 -l 192.168.1.1:6778
./ppspp -f /tmp/test -c 1024 -t 5 -l 192.168.1.1:6778,192.168.1.2:6778 -p 6778

LEECHER mode:
./ppspp -a 192.168.1.1:6778 -s 82da6c1c7ac0de27c3fedf1dd52560323e7b1758 -t 10
```