# Pgen

## Running MACsec

The procedure (for now) to generate the MACsec frame is as follows:

**Authentication operation**

```bash
macsec.enable
macsec.encrypt off
macsec.key macsec_key.bin # key file will decide if key is 16 or 32 bytes
macsec.es on # end station mode
ifname dummy0
run
```

**Encryption operation**

```bash
macsec.enable
macsec.encrypt on
macsec.key macsec_key.bin
macsec.es on
ifname dummy0
run
```

