# netos

Network OS

# Build

## Compilation options

1. CLANG_COMPILER : set it to ON or OFF during cmake config
2. GCC_COMPILER : set it to ON or OFF during cmake config
3. CMAKE_DEBUG_BIN : set it to ON to generate binaries with symbols and gdb.


If CMAKE_DEBUG_BIN is not given, compiler optimisations are enabled.

## using Clang

```bash
scan-build-20 -v -k -enable-checker alpha.cplusplus -enable-checker security -enable-checker unix --use-c++=clang++ make
```

# Introduction

# Ingress

Ingress processing is done as follows:

1. Frame is received in a separate thread.
2. Thread queues into the parser thread.
3. Parsing happens based on protocols from L2 to L4.
4. Based on the parsing, frame is queued to the protocol specific layer.
5. Each protocol specific layer could run its own thread or multiple threads.

## ARP frame processing

# Egress

