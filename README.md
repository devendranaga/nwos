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
| 1 | COMPILER_GCC | use GCC to compile the code |
| 2 | COMPILER_CLANG | use CLANG to compile the code |
| 3 | DEBUG | enable debugging prints |
| 4 | STATIC_BUILD | static build (does not work 100%) |
| 5 | COMPILER_ARM | use ARM compiler (arm64) |

## TODOs

- [ ] WRR egress scheduling
- [ ] correct handling of ref count in rx and egress
- [ ] MACsec implementation
- [ ] Cryptography wrapper callback interface
- [ ] MbedTLS, wolfSSL GCM & GMAC
- [ ] IPsec implementation
- [ ] TCP frame parsing
- [ ] Event capture and storage tests
- [ ] Address translation must be done right before the parser and straight to egress.
- [ ] DRR egress scheduling
- [ ] IPv6 frame parsing
- [ ] IPv4 serialize and checksum generation
- [ ] TCP checksum validation
- [ ] UDP checksum validation
- [ ] Take pkt buffer numbers from xml config
- [ ] static ARP cache allocation strategy
- [ ] CPU affinity per thread
- [ ] Count number of CPUs and tie each thread to a CPU
- [ ] Events: Storage maintenance (create timer to delete the events first items in the queues gets purged)
- [ ] Handling Ctrl + C
- [ ] Define event storage format, the same format is used for upload of events
- [ ] Define event storage encryption
- [ ] ICMP6 frame parsing
- [ ] ICMP6 checksum validation
- [ ] Define MACsec for massive scale usecase (128 SecY) - check what the SAI offers
- [ ] CMAC PRF
- [ ] Tooling: packet replay from a file in pgen
- [ ] Store the received packets in a PCAP
- [ ] Tooling: ARP spoofing
- [ ] Tooling: implement the up arrow and down arrow detection and history buffer
- [ ] pfifo queueing discipline
- [ ] Expand the Events matching to suricata
- [ ] Skip the IPv4 options if we cannot parse them
- [ ] Tools: Multilevel VLAN generation.
- [ ] Tools: Missing error handling in pgen.
- [ ] ICMP serialize for echo request and reply.
- [ ] GRE: decode GRE protocol.
- [ ] Tooling to display ARP cache.
- [ ] Tooling to support adding the static ARP entries.

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

