# Nwos

This project sole purpose is to educate on the Networking and software design / architectures.

This project is not meant to be a real world usecase of a network stack.

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

## Build flags

| S.No | option | description |
|------|--------|-------------|
| 1 | `COMPILER_GCC` | use GCC to compile the code |
| 2 | `COMPILER_CLANG` | use CLANG to compile the code |
| 3 | `DEBUG` | enable debugging prints |
| 4 | `STATIC_BUILD` | static build (does not work 100%) |
| 5 | `COMPILER_ARM` | use ARM compiler (arm64) |
| 6 | `WITH_WOLFSSL` | With WolfSSL crypto library |

## Macro defines / feature flags

| S.No | option | description |
|------|--------|-------------|
| 1 | `NETOS_PERF` | Performance measurement interface. |
| 2 | `NETOS_DEBUG` | Enable print based debugging. |

### Build configuration

**1. GCC Static Build**

```bash
cmake .. -DCOMPILER_GCC=on -DDEBUG=on -DSTATIC_BUILD=on -DWITH_WOLFSSL=on
```

**2. Clang Build**

```bash
cmake .. -DCOMPILER_CLANG=on -DDEBUG=on -DWITH_WOLFSSL=on
```

**3. ARM Build**

```build
cmake .. -DCOMPILER_ARM=on -DDEBUG=on
```

For a valgrind check, disable `DDEBUG` option in cmake and use any compiler option above.
In debug builds, the ASAN checkers are linked.

## Setting up

**1. Running netosd**

netosd does not require the super user permissions if set the permissions via the setcap utility.

```bash
sudo setcap cap_net_admin,cap_net_raw+ep ./netosd
./netosd -f config/config.xml
```

**2. Running netos_pgen**

```bash
sudo setcap cap_net_admin,cap_net_raw+ep ./netos_pgen
./netos_pgen
```

3. Running netctl

`netctl` is used to get the statistical information about the netosd internal state.

```bash
sudo ./netctl -p ./netctl.sock -s ./netos_ctrl.sock
```

### Generating interfaces

Run the script `gen_interfaces.py` on Linux.

```bash
python3 gen_interfaces.py create dummy 10
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

[![gcc static build](https://github.com/devendranaga/nwos/actions/workflows/gcc-static-build.yml/badge.svg)](https://github.com/devendranaga/nwos/actions/workflows/gcc-static-build.yml)


[![clang build](https://github.com/devendranaga/nwos/actions/workflows/clang-build.yml/badge.svg)](https://github.com/devendranaga/nwos/actions/workflows/clang-build.yml)


[![clang static build](https://github.com/devendranaga/nwos/actions/workflows/clang-static-build.yml/badge.svg)](https://github.com/devendranaga/nwos/actions/workflows/clang-static-build.yml)

