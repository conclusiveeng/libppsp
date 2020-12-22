# libperegrine

## Building

Minimal build
```shell script
mkdir build
cd build
cmake ..
make
```

Build Debian package
```bash
cd build
cmake -DPACKAGE_DEB=YES ..
make
cpack
```

Build doxygen documentation
```bash
cd build
cmake -DBUILD_DOCS=YES ..
make
```

Build static library & static example app
```bash
cd build
cmake -DBUILD_STATIC=YES ..
make
```

## Usage

Example application arguments:

```bash
Usage: examples/app/peregrine -lhpfdrs 
Options:
-h      show this help message 
-l      local port      (eg. -l <port>) 
-p      peer address    (eg. -p <ip addr>:<port> OR -p <hostname>:<port>) 
-f      file, sha1      (eg. -f <filename> or -f <filename>:<sha1> ) 
-d      directory       (eg. -d <path/to/directory> ) 
-r      remain minutes  (eg. -r 15 ) 
-s      enable showing summary (if disabled only callbacks will be used ) 
```

`<hostname>:<port>` - can be used to pass hostname, then DNS A entries will be used as list of IPv4 peers

Seeder mode (directory):

```bash
examples/app/peregrine -l 12345 -d ~/directory_to_seed -s
```

Seeder mode (file)

```bash
examples/app/peregrine -l 12345 -f ~/directory_to_seed/picture.png -f ~/directory_to_seed/file2.jpg -s
```

Leecher mode

```bash
examples/app/peregrine -l 54321 -f picture.png:b46abe4de7e6825ee8b2627a8d6723e471ace343 -p  127.0.0.1:12345 -s
```

## Directory structure

- examples/
  - app/
    - peregrine.c *- example application using libperegrine*
- include/
  - peregrine/
    - peregrine.h *- Public API header file*
- src/ *- internal sources directory*
