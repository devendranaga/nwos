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



## TODOs

- [ ] WRR egress scheduling
- [ ] correct handling of ref count in rx and egress
- [ ] MACsec implementation
- [ ] Cryptography wrapper callback interface
- [ ] MbedTLS GCM
- [ ] IPsec implementation
- [ ] Event capture and storage tests
- [ ] Address translation must be done right before the parser and straight to egress.
- [ ] DRR egress scheduling
- [ ] static ARP cache allocation strategy
- [ ] select cpus statically based on the number of CPUs in the system
- [ ] Events: Storage maintenance (create timer to delete the events first items in the queues gets purged)
- [ ] Handling Ctrl + C
- [ ] Define event storage format, the same format is used for upload of events
- [ ] Define event storage encryption
- [ ] Define MACsec for massive scale usecase (128 SecY) - check what the SAI offers
- [ ] CMAC PRF
- [ ] Store the received packets in a PCAP
- [ ] Tooling: ARP spoofing
- [ ] Expand the Events matching to suricata
- [ ] Skip the IPv4 options if we cannot parse them
- [ ] Tools: Multilevel VLAN generation.
- [ ] Tools: Missing error handling in pgen.
- [ ] GRE: decode GRE protocol.
- [ ] Tooling to display ARP cache.
- [ ] Tooling to support adding the static ARP entries.
- [ ] IPv6 frame options parsing
- [ ] LLDP frame parsing
- [ ] ICMP6 frame serialization
- [ ] Tooling: ICMP6 frame generation
- [ ] Tooling: ICMP seq_no increment for every packet
- [ ] Tooling: more descriptive help for each command
- [ ] Tooling: ICMP6 Neighbor solicitations and advertisements generation
- [ ] LLDP frame parsing
- [ ] LLDP frame generation
- [ ] NDP implementation
- [ ] MKA frame parsing
- [ ] MKA frame generation
- [ ] recvmsg using the scatter gather approach
- [ ] recvfrom using the PACKET_MMAP with tpacketv3
- [ ] 6in4 tunnel frame parsing
- [ ] 6in4 tunnel frame generation
- [ ] IPv6 frame generation
- [ ] Tooling: MACsec auto PN increment for every packet that is sent
- [ ] Tooling: document the command usages
- [ ] Tooling: when test finishes, reset the PN
- [ ] Tooling: IPv4 over MACsec
- [ ] bfifo queueing discipline
- [ ] Tooling: IPv6 frame generation
- [ ] Tooling: UDP over IPV4
- [ ] Tooling: UDP over IPv6
- [ ] Tooling: TCP over IPV4
- [ ] Tooling: TCP over IPv6
- [ ] UDP generation over IPv4
- [ ] UDP generation over IPv6
- [ ] TCP generation over IPv4
- [ ] TCP generation over IPv6
- [ ] stateful NAT implementation
- [ ] stateful NAT64 implementation
- [ ] IPv4 options parsing
- [ ] DHCP frame parsing
- [ ] DHCP frame serialization
- [ ] DHCPv6 frame parsing
- [ ] DHCPv6 frame serialization
- [ ] DNS frame parsing
- [ ] DNS frame serializataion
- [ ] EAPOL-MKA frame parsing
- [ ] EAPOL-MKA frame serialization
- [ ] MKA key generation
- [ ] Cipher: CMAC routine interface
- [ ] Cipher: WolfSSL CMAC interface
- [ ] 8021br frame parsing
- [ ] 8021br frame serialization
- [ ] Mirror mode operation
- [ ] Linux RNG interface to /dev/random
- [ ] IP forwarding support using NAT / NAT64
- [ ] IP fragmentation and reassembly support
- [ ] TCP statemachine
- [ ] UDP Demux and Mux
- [ ] TCP Demux and Mux
- [ ] ICMP echo reply generation for a echo request frame
- [ ] ARP request generation from the IP query to ARP
- [ ] recvmsg and sendmsg support
- [ ] PKT_MMAP or PF_RING support to receive and transmit frames
- [ ] global MIBs for all protocols
- [ ] Tooling: CLI tool for statistics
- [ ] Enable PCAP write mode
- [ ] Event manager to write logs to a network or to a file
- [ ] Gtest support
- [ ] Signal handling
- [ ] Tooling: Multiple interface transmit on pgen
- [ ] ATU implementation
- [ ] ICMPv6: implement Multicast listener report v2 parsing
- [ ] ICMPv6: implement Router solicitations and Router advertisements
- [ ] TCP: Parse options
- [ ] Syslog: Parse Syslog protocol
- [ ] LACP: Parse LAG
- [ ] NTP: Parse NTP
- [ ] pfifo_fast: with 3 queues mapped from vlan priorities 7-0.
- [ ] SFQ: stochastic fair queueing without re-hashing.
- [ ] Tool ctl: to control or view the insides of the netos

## Done

- [x] selectable scheduler from a tx path (via egress algorithm type)
- [x] Dynamic hash table
- [x] ARP rx processing
- [x] Fix RR egress scheduling (all frames are not egressing if multiple queues exist)
- [x] Tooling: pgen for ethernet frames (speed, ipg, repeat, number of frames)
- [x] Static queues using ring buffer
- [x] Fix leak of packet buffers (never freed)
- [x] IPv4 checksum validation
- [x] gcd framework
- [x] See if we really need ref count on `pkt_buffer`
- [x] See if `_Atomic` can be usde on `pkt_buffer`.
- [x] Tooling: Generate ARP frames
- [x] ARP cache invalidation
- [x] ICMP frame parsing
- [x] ICMP checksum validation
- [x] Tooling: Generate VLAN frames
- [x] ICMP serialize for echo request and reply.
- [x] IPv4 serialize and checksum generation
- [x] TCP frame parsing
- [x] TCP checksum validation
- [x] UDP checksum validation
- [x] IPv6 frame parsing
- [x] ICMP6 frame parsing
- [x] ICMP6 checksum validation
- [x] Tooling: MACsec farme generation
- [x] WolfSSL GMAC interface
- [x] CPU affinity per thread
- [x] Count number of CPUs and tie each thread to a CPU
- [x] Tooling: packet replay from a file in pgen
- [x] Tooling: packet capturing tooling
- [x] Tooling: MACsec: setting any TCI bits via command line
- [x] Tooling: MACsec key setting via pgen
- [x] pfifo queueing discipline
- [x] Take pkt buffer numbers from xml config
- [x] WolfSSL Encryption
- [x] Tooling: MACsec encrypt implementation
- [x] Tooling: implement the up arrow and down arrow detection and history buffer


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

## Switching

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

[![C cmake CI](https://github.com/devendranaga/nwos/actions/workflows/cmake-multi-platform.yml/badge.svg?branch=master)](https://github.com/devendranaga/nwos/actions/workflows/cmake-multi-platform.yml)

