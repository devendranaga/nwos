# Design notes

**Notes**
1. First notes on IP handling - 18/06/2026.

## Parser to protocol handler handoff

1. Parser directly parses the frame and in case of ARP it handles it over to the ARP handler.
2. However, for ip and other protocols, this is not gonna cut in, because the frame needs to be parsed and understood by the rest of the layers for the Ids.
3. Any frame errors thus can get detected and dropped.
4. May possibly call the protocol handler directly soon as the parsing completes in the Rx path.
5. Does this needs to be in a separate thread? not sure yet. Once the TCP and other implementations start, make the full design later.

## MACsec implementation

### Key database format

```c

struct macsec_key_info {
    uint8_t sci[8];
    uint8_t is_tx; // 1 - tx sa 0 - rx sa
    uint8_t an;
    uint8_t key_len;
    uint8_t cipher_suite;
    uint8_t key[32];
} __attribute__ ((__packed__));

```

```c
struct macsec_key_metadata {
    uint8_t     version;
    uint8_t     n_secy;
    uint16_t    db_len;
    // list of MACsec encrypted keys of type macsec_key_info
} __attribute__ ((__packed__));
```

**Design details**

1. SCI will link to a particular TxSC or RxSC.
2. To index into an SA (tx or rx) the SC type is needed either as Tx or Rx.
3. AN will tell which SA in either tx or rx SAs.
4. Key length must be known in order to do either 128 or 256 bit is the key.
5. Key metadata stays in plaintext and the keys are encrypted in a bunch using the AES-KeyWrap.
6. The wrapping key is stored somewhere securely.
7. During initialization, keys are decrypted and loaded into secy's SAs.

## IPv4 implementation

### Initialization

1. IP layer does not really need to know the device' ip here until the frame is received from the interface or from the upper layer.
2. IP maintains a routing table to make forwarding decisions.
3. Registration interface where all the protocols can register to the ip layer with their protocol number and their handler.

### Rx path
Frame parser can pass the parsed IPv4 frame to the IPv4 layer. 

1. If ingress frame is destined to us may be prepare a pass through to the TCP or other layers. Destination is the host.
2. Set `to_us` flag in the buffer. (TTL 0 being dropped at the parser).
3. Setup a dispatch table during the protocol registration to the IP layer.
4. since the protocol is a number it can be index into the dispatch table, 256 entries could consume quiet a memory, but it is performant.
5. direct index and validate the function pointer.
6. If the frame is destined to a device or hop that the IPv4 layer know, try to forward.

#### IP forwarding

**Routing Table**

Routing must always be done with longest prefix match first. Gemini says `Radix Trie`, need to learn that.

1. if the frame egress is known, two things to be done.
    1. Relace Frame's TTL (reduce it by 1) based on the user's config in xml. Recompute the checksum if TTL is changed.
    2. Replace the Frame's DSCP based on the frame match in the Ids Rules. If no Ids Rule, do not change the DSCP. Recompute the checksum if TTL is changed.
2. Queue the frame to the egress.

**Fragmentation handling**

**Reassembly**


## Tooling

### Packet generator

**Design**

1. A simple console is provided to enter in commands.
2. User presented with some set of executable commands.
3. 
