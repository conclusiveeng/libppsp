# libperegrine

## Building

```shell script
mkdir build
cd build
cmake ..
make
```

## Usage

Example application arguments:

```bash
Usage: examples/app/peregrine -lhpfds 
Options:
-h      show this help message 
-l      local port      (eg. -l <port>) 
-p      peer address    (eg. -p <host>:<port>) 
-f      file, sha1      (eg. -f <filename> or -f <filename>:<sha1> ) 
-d      directory       (eg. -d <path/to/directory> ) 
-s      enable showing summary (if disabled only callbacks will be used )
```

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
