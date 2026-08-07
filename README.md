# Nwos

## prerequisites

```bash
sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
sudo dpkg --add-architecture arm64
sudo apt update
sudo apt install libxml2-dev:arm64
sudo apt install libicu-dev:arm64
sudo apt install libxml2-dev libicu-dev

```

Static build would most probably work on any 64 bit ARM and may not require any dependencies.
Static build does not work in Github CI. Not sure.

## Build flags

| S.No | option | description |
|------|--------|-------------|
| 1 | `COMPILER_GCC` | use GCC to compile the code |
| 2 | `COMPILER_CLANG` | use CLANG to compile the code |
| 3 | `DEBUG` | enable debugging prints |
| 4 | `STATIC_BUILD` | static build (does not work 100%) |
| 5 | `COMPILER_ARM` | use ARM compiler (arm64) |
| 6 | `WITH_WOLFSSL` | With WolfSSL crypto library |

### Build configuration

**1. GCC Static Build**

```bash
cmake .. -DCOMPILER_GCC=on -DDEBUG=on -DSTATIC_BUILD=on
```

**2. Clang Build**

```bash
cmake .. -DCOMPILER_CLANG=on -DDEBUG=on
```

**3. ARM Build**

```build
cmake .. -DCOMPILER_ARM=on -DDEBUG=on
```

## Setting up

**1. Running netosd**

```bash
sudo setcap cap_net_admin,cap_net_raw+ep ./netosd
./netosd -f config/config.xml
```

**2. Running netos_pgen**

```bash
sudo setcap cap_net_admin,cap_net_raw+ep ./netos_pgen
./netos_pgen
```

### Generating interfaces

Run the script `gen_interfaces.py` on Linux.

```bash
bash gen_interfaces.py create dummy 10
```

Would create 10 interfaces on Linux.

## Ids

### Capturing events

1. Every frame that is being receive is parsed and validated.
2. During parsing, the frame is checked with the common known attacks.
3. IF on a match, the event type and description are stored in the rx buffer context.
4. Once the parser returns, it then passes the event into the event manager.

## Build status

[![gcc build](https://github.com/devendranaga/nwos/actions/workflows/gcc-build.yml/badge.svg)](https://github.com/devendranaga/nwos/actions/workflows/gcc-build.yml)
[![clang build](https://github.com/devendranaga/nwos/actions/workflows/clang-build.yml/badge.svg)](https://github.com/devendranaga/nwos/actions/workflows/clang-build.yml)

