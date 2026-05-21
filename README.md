# netos

Network OS

# Build

## Compilation options

1. CLANG_COMPILER : set it to ON or OFF during cmake config
2. GCC_COMPILER : set it to ON or OFF during cmake config
3. CMAKE_DEBUG_BIN : set it to ON to generate binaries with symbols and gdb.

**default compiler command:**

The `CMAKE_DEBUG_BIN` is always used for testing.

```bash
cmake .. -CMAKE_DEBUG_BIN=on -DSTATIC_BUILD=on -DCLANG_COMPILER=on
cd build
make -j
```

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

## MACsec

```
|---------|-----|-----|----------|-------------|-------|
| TCI AN  | SL  | PN  |   SCI    | Secure Data |  ICV  |
|---------|-----|-----|----------|-------------|-------|

```
**Figure: MACsec frame format**

```
|---------|----|----|-----|---|---|--------|
| Version | ES | SC | SCB | E | C |   AN   |
|---------|----|----|-----|---|---|--------|
```

**Figure: TCI AN format**

Following cipher suites are available in the standard:

1. AES-GCM-128
2. AES-GCM-256
3. AES-GCM-XPN-128
4. AES-GCM-XPN-256

For AES-GCM the following are the inputs:

1. AAD
2. IV
3. SAK
4. Payload
5. Payload length

The outputs are the ciphertext and the GCM Tag.

## ARP frame handling

ARPs are used to translate an IP address to a real device Mac so the frames can be sent at the switch / hardware level.

ARP states:

```c
enum arp_state {
    ARP_STATE_NONE,
    ARP_STATE_REQUESTED,
    ARP_STATE_COMPLETE,
    ARP_STATE_REFRESH,
}


```
### ARP Transmit handling

**1. When triggered by higher layer:**

1. L3 (IPv4) can ask for the address in which ARP table is searched. If the search return fail the ARP query is registered.

2. The freshness timer runs and looks at the query bit and triggers an ARP frame generation.

3. The `retry_counter` on this entry will be incremented.

4. If there is a response, the retry_counter will be cleared and the ARP state is set to `RESOLVED`.

5. If there is no response for over a configured threshold in `network.json` the entry is cleared.

6. In the success case and failure cases, the notification will be sent to the IP layer about the mac address availability or non availability.

It wouldn't be much of a trouble if the freshness timer triggers very later after the query is registered by the IP layer. This is a control frame and does not have to be sent very quickly.

**2. When triggered by freshness timer**

1. Freshness timer loops around the entire table.

2. Looks for the ARP entry's last update timestamp in msec.

3. If the timestamp is beyond the configured value in the `network.json`, the timer generates the ARP frame and transmits it.

4. Frame processing and timeout handling is specified in point 1 above (look for points 4, 5 and 6).

### ARP Receive handling

Assuming that the packet parser already parsed the ARP frame and detected no errors and the ARP layer callback is triggered. If there are parser errors, the frame will be dropped and the counters will be incremented.

1. Frame is matched against any existing entry first, if matched, the entry's state is checked and if its in `ARP_REQUESTED` or `ARP_COMPLTE_REFRESH` then the timestamp of that entry is updated.

2. Frame is not matched, check if its `ARP_REQUEST`, if yes then add the entry and create a response frame.

3. If the Frame is an `ARP_REPLY` frame, and the entry is not matched, drop it.

## ICMP frame handling

### ICMP Transmit handling

### ICMP Receive handling

# Egress

## Egress Controller

Egress controller performs the following operations.

1. Creates the Egress queues.
2. Figure out which queue to push the frame for transmission. Scheduling the frame to an egress queue is done by the controller.

### Egress queue

Egress queue is part of the Egress Controller. It does the following operations.

1. check the frame priority in the frame's VLAN and place the frame in the right position in the egress queue.

# Cloud interface

## protocol definition


# TODOs

## netwd

- [ ] Fix invalid free or no free of parsed_pkt buffers. (ref counting)
- [ ] Fix packet_buf allocation as a single large pointer.
- [ ] Fix packet_buf free or no free. (ref counting)
- [ ] Cli interface for the netwd for configuration and statistics dumping
- [ ] enable logging to console via the config
- [ ] enable mmap based file writing
- [ ] enable pcap to write files via mmap
- [ ] during initialization of an interface, if the ip address is already given in the configuration, set it.
- [ ] enable configuration to bypass icmp checksum.
- [ ] rewrite the hash table to C++ implementation.
- [ ] implement LLDP parsing

### MACsec

- [ ] MACsec header definitions

## pktgen

- [ ] Generate ICMP messages
- [ ] Perform arping
