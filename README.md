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

