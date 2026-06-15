# Nwos

## TODOs

- [ ] WRR egress scheduling
- [ ] Fix RR egress scheduling (all frames are not egressing if multiple queues exist)
- [ ] Static queues
- [ ] correct handling of ref count in rx and egress
- [ ] MACsec implementation
- [ ] Cryptography wrapper callback interface
- [ ] MbedTLS, wolfSSL GCM & GMAC
- [ ] IPsec implementation
- [ ] TCP frame parsing
- [ ] IPv4 checksum validation
- [ ] Event capture and storage tests
- [ ] ICMP frame parsing
- [ ] ICMP checksum validation
- [ ] gcd framework
- [ ] ARP cache invalidation
- [ ] Address translation must be done right before the parser and straight to egress.
- [ ] DRR egress scheduling
- [ ] IPv6 frame parsing
- [ ] TCP checksum validation
- [ ] UDP checksum validation
- [ ] Take pkt buffer numbers from xml config
- [ ] static ARP cache allocation strategy

## Done

- [x] selectable scheduler from a tx path (via egress algorithm type)
- [x] Dynamic hash table
- [x] ARP rx processing
- [x] Tooling: pgen for ethernet frames (speed, ipg, repeat, number of frames)


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

