# Design notes

## Rule heirarchy and optimisations

Right now the DAG is very complex to implement. Lets learn it little more and understand how a DAG can be created following this rule definitions.

In order to the DAG, we also need to look at the duplicate rules which can be redundant in the DAG and might cause false positives.

First split the implementations into two parts.

1. Ethertype based matches.
2. Flow based matches.

First the rule needs to be split based on the ethertype.

Each of these become list entries in a long list of rules.

List will contain for example arp_rule -> vlan_rule -> tcp_udp_flow_rule.

The arp_rule will further contains a list of sub rules.
For the connection tracking tcp_udp_flow rules will be a list of sub rules.

Each of the tcp_udp_flow will then be a hash table instead of a list.

The 5 tuple is hashed to figure out which is the best rule match for this input frame.

Organize the rules such that direct hash based matches can be performed on TCP / UDP specific flows.

Assume src_port = 0 when doing the hashing.

## Configuration

**config design**

```xml
<config>
    <!-- for both tx and rx pools per each interface -->
    <pkt_buf_pool_size>1024</pkt_buf_pool_size>
    <protocols>
        <arp>
            <arp_cache_size>32</arp_cache_size>
        </arp>
        <macsec>
            <!--
                Enabling MACsec should be dynamic,
                if the macsec frame appear, the mapping has to be done
                directly based on the ethertype from rx point.

                Lookup will happen and decryption / verify needs to be done.

                if on tx, the capabilities must be set per interface pointer.
                if the pointer is not macsec capable, it can be bypassed both
                on tx and rx sides.
            -->
            <max_sci>128</max_sci>
            <tx_sc_per_sci>1</tx_sc_per_sci>
            <rx_sc_per_sci>16</rx_sc_per_sci>
        </macsec>
    </protocols>
</config>
```

## Design considerations

### Latency measurements

Notes: 15/06/2026

On an AMD Ryzen 5 5500u,

1. `recvfrom` without `MSG_DONTWAIT` takes anywhere between 2 to 300-400 microseconds.
2. New ARP entries can either overrun the buffer or spend a lot of time in allocation.
3. Generic buffer pool is required.
4. `calloc` takes anywhere between 0.1 usec to 10 usec at random (real `mmap` called more than once instead of once by `calloc` ?)
5. `pthread_mutex_lock` and `pthread_mutex_unlock` takes anywhere betwen 4 to 14 microseconds.

Since `recvfrom` is waiting in a dedicated rx thread per interface, so it could be because there is no frame data and the `recvfrom` is in wait.
There is another approach to do this is via the `select` or `epoll` system call by registering the socket and doing the rx in the callback.

For every new ARP entry (i.e. cache miss) there is new allocation and this can repeatedly happen if there are as many new ARP replies or
requests. (attack is one example)
Also the allocation path takes up a lot of time and so this needs to be pool allocated.

Since the problem is allocation and is all over the place the buffer pool must be generic of what is written for the pkt_buffer.

Most of the processing time gets lost in here and most of the allocations must always been in the static allocation.

Moving to static queues might help to cut down on the repeated calls to the `calloc` and `free` when `push` and `pop` are being called.
Right now, `atomic` seem to be an approach to the single producer and single consumer problem. So new C might have already `_Atomic`
and this can be used along with the circular buffer.

Notes: 17/06/2026

1. Atomic tests did not yeild good results with CPU load. The waiting must be there somewhere otherwise, the busy lop returns.
   possible with `futex`, need to learn about that.

2. Hot path limit is also with the buffer pool lock which could also consume some latency.

3. Ring reduces latency by half and now the double digit usec are rare occurence.

Notes: 18/06/2026

**on IPsec**:

1. IPsec requires a lot of ECDH and KDFs with X.509 exchanges. This means the software needs to understand the certificate formats.

2. 4 message IPsec is very hard to implement from the supported lists and ciphers. Will need to read the spec in detail.

Requires a strong crypto library interface so that the control and data path protocols can be implemented.

## Network stack

### Init path

### Rx path

Following actions happen on the rx path:
1. Rx thread waits on the receive path.
2. Receives one frame, takes the parse / process thread lock, queues it, wakes up process thread.
3. Process thread wakes up, retrieves the head item.
4. Passes it to the protocol parser.
5. Protocol parsers runs the layer specific handler.

### Egress Queue controller

Egress queue controller orchestrates the queueing and shaping. The following Egress Queueing algorithms exist.

1. Strict Priority
2. Round robin

**Strict Priority Queueing**

1. Frames are placed one of the 8 queues based on their priority.
2. The priroity is determined based on the VLAN's PCP or any priority assignment within the ingress path or protocol level.
3. The SP scheduler wakes up on a queued item.
4. Loops around each priority queue from 7 to 0.
5. Dequeues and transmits all the frames from queue 7.
6. Repeats it for queue 6, 5, .. and so on to queue 0.

Strict priority queueing is particularly useful in case where encrypted traffic could take the highest priority by default because of its sensitivity.

Thus all of the MACsec traffic could go sit on the highest priority queue waiting to be sent.


## Configuration

The configuration is an xml file. The configuration is parsed as follows;

1. Look at the XML branch.
2. If there's callback attached to it, call it.
3. In the callback, check if its a branch or leaf nodes.
4. If its a branch, repeat the step 2.
5. If its a leaf node, parse it and set it to the variable.
6. Repeat until the parser reaches the end of file.

This way the configuration parsing become extensible with just adding new functions instead of writing parsing code again and again.

The parsing objects are u16, u32, u8 *[mac], u32 ip address, u8 [ip6 address], string. The APIs are written to these and
the leaf_callbacks will call these functions to reduce repeated parsing as well.

## Crypto layer

Crypto layer is a function pointer table that is set by underlying cryptography implementation. Any cryptography implementation can hook and return a valid pointer of type `crypto_intf_t`.

The callers will get this pointer in the crypto context structure. The user will get an abstract APIs that wrap this callback pointers for more easier API calls.

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
