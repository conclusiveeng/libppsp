# libperegrine

## Building

```shell script
mkdir build
cd build
cmake ..
make
```

## Usage

Seeder mode (directory):

```bash
./examples/app/peregrine -l 12345 -d ~/directory_to_seed 
```

Seeder mode (file)

```bash
./examples/app/peregrine -l 12345 -f ~/directory_to_seed/picture.png
```

Leecher mode

```bash
./examples/app/peregrine
```

## Directory structure

- examples/
  - app/
    - peregrine.c *- example application using libperegrine*
- include/
  - peregrine/
    - peregrine.h *- Public API header file*
- src/ *- internal sources directory*
