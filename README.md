# netos

Network OS

# Build

## using Clang

```bash
scan-build-20 -v -k -enable-checker alpha.cplusplus -enable-checker security -enable-checker unix --use-c++=clang++ make
```

