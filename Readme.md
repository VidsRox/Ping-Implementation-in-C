# Ping from Scratch in C

A ground-up implementation of the `ping` utility in C, built in two parts. Part 1 uses standard OS abstractions to get a working ping end-to-end. Part 2 rebuilds the same thing following [Dr. Jonas Birch's](https://www.youtube.com/playlist?list=PLdNUbYq5poiXDcqmOAW4I-U30i9rxUIe7) architectural approach - manually constructing every layer of the network stack without relying on OS shortcuts.

Claude was instrumental throughout the learning process, guiding concept development through a Socratic question-and-answer methodology rather than simply providing solutions.

---

## Why This Project

Most networking code hides the packet structure from you. A browser, a curl call, even a basic TCP socket - the OS builds the headers, handles byte order, calculates checksums. You just send data.

This project removes every abstraction, one layer at a time:

- **Part 1**: OS handles the IP header. We build ICMP manually.
- **Part 2**: We build everything - ICMP, IP, and Ethernet - byte by byte.

The goal isn't just a working ping. It's a mental model of what actually happens on the wire.

---

## Part 1 - Working Ping (stdlib approach)

Located in `simple_version/icmp.c`.

### What it does
- Constructs ICMP echo request packets manually, field by field
- Calculates RFC 1071 Internet checksum from scratch
- Sends via raw socket (`SOCK_RAW + IPPROTO_ICMP`)
- Receives and parses the IP header using IHL to locate the ICMP payload
- Measures RTT with nanosecond precision using `CLOCK_MONOTONIC`
- Handles timeouts via `SO_RCVTIMEO` and `EAGAIN`
- Catches `SIGINT` (Ctrl+C) and prints statistics on exit

### Sample output
```
64 bytes from 8.8.8.8: icmp_seq=1 time=28.618 ms
64 bytes from 8.8.8.8: icmp_seq=2 time=31.204 ms
64 bytes from 8.8.8.8: icmp_seq=3 time=29.871 ms
^C
--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss
rtt min/avg/max = 28.618/29.897/31.204 ms
```

### Key concepts implemented
- `__attribute__((packed))` to prevent compiler padding on network structs
- `htons()` for 16-bit fields, `inet_addr()` for IP address conversion
- IP header parsing: `buffer[0] & 0x0F` extracts IHL, multiply by 4 for byte length
- One's complement checksum: 16-bit chunks summed into 32-bit accumulator, overflow folded, result bitflipped
- `CLOCK_MONOTONIC` for RTT - never jumps backwards unlike wall clock time
- `SIGINT` handler with global statistics counters

### Build and run
```bash
cd simple_version
gcc icmp.c -o ping
sudo ./ping 8.8.8.8
```
Requires root for raw socket access. Developed and tested on Ubuntu (native Linux VM - WSL2 has NAT limitations that prevent receiving raw ICMP replies from internet addresses).

---

## Part 2 - Jonas Birch Rebuild ✅ Complete

Located in `ping_v2.c`.

This is a complete rebuild following the architectural approach from Dr. Jonas Birch's ping series. The core idea is the **two-struct pattern**: every protocol layer has a logical struct for convenient in-code representation and a packed raw struct that exactly matches the wire format. An `eval_*` function converts between them at send time.

```
mkicmp()  →  logical icmp struct  →  eval_icmp()  →  raw wire bytes  ↘
mkip()    →  logical ip struct    →  evalip()     →  raw wire bytes  →  sendto()
mkether() →  logical ether struct →  evalether()  →  raw wire bytes  ↗
```

The receive path is the exact mirror: raw bytes arrive from the socket, are stripped layer by layer, and reconstructed into nested logical structs.

Before starting Part 2, LeetCode #271 Encode and Decode Strings was studied specifically because length-prefix serialization - encoding structured data into a flat byte stream and recovering it - is exactly the pattern `eval_icmp()` implements.

### Build and run
```bash
gcc ping_v2.c -o ping_v2
sudo ./ping_v2
```

### Sample output
```
(e *)Received = {
  size:  60 bytes total
  protocol:  0x08
mac src:  52:54:00:12:35:02
mac dst:  08:00:27:37:3a:c7
}
(ip *)payload = {
  size:  46 bytes total
  kind:  0x03
  id:    0x64
  src:   8.8.8.8
  dst:   10.0.2.15
}
(icmp *)payload = {
 kind:   echo reply
 size:   18 bytes of payload
}
payload:
68656c6c6f20776f
726c640000000000
0000
```

### ICMP Layer

- `s_icmp` logical struct: `kind`, `identifier`, `seq_num`, `size`, `*data`
- `s_rawicmp` raw struct: `Type`, `code`, `checksum`, `identifier`, `seq_num`, `data[]` - packed, matches RFC 792 wire format exactly
- `mkicmp()` - constructor, heap-allocates logical struct
- `eval_icmp()` - serializes to wire bytes, two-stage copy (header then payload), checksum computed last over assembled buffer
- `show_icmp()` - debug printer with hex dump
- `free_icmp()` - cleanup

**Design decision**: identifier and sequence number are kept in the ICMP header per RFC 792, rather than in a nested payload struct as Jonas does. This stays closer to the spec.

### IP Layer

- `s_ip` logical struct: `kind`, `src`, `dst`, `id`, `*payload`
- `s_rawip` raw struct: all RFC 791 fields packed - version, IHL, DSCP, ECN, length, id, flags, offset, TTL, protocol, checksum, src, dst
- `mkip()` - constructor with dual id/counter parameter pattern for flexible ID assignment
- `evalip()` - serializes IP header and calls `eval_icmp()` internally to nest the ICMP payload
- `showip()` - debug printer that recurses into `show_icmp()` for the payload
- `recvip()` - inverse of `evalip()`, strips layers inward to reconstruct nested logical structs from raw bytes. Phase 8: no longer calls `recvfrom()` internally - receives a pre-stripped buffer from `recv_frame()` instead

**Key concept**: bit field ordering in `s_rawip`. On little-endian x86, the compiler fills bit fields from the least significant bit upward. To get `version` in the upper 4 bits and `ihl` in the lower 4 bits of the first byte - as RFC 791 requires - they must be declared in reverse order: `ihl:4` first, then `version:4`. The same applies to `ecn:2` and `dscp:6`.

### Ethernet Layer

- `ethertype` enum: `tIP = 0x0800`, `tARP = 0x0806` - matches `ETH_P_IP` and `ETH_P_ARP` in the Linux kernel source (`net/ethernet/eth.c`)
- `mac` struct: 48-bit MAC address stored as lower 48 bits of `uint64_t` - enables single-integer comparison and assignment
- `s_ether` logical struct: `protocol`, `src`, `dst`, `*payload`
- `s_rawether` raw struct: `dst`, `src`, `type` - destination MAC first on wire per Ethernet spec
- `mkether()` - constructor
- `evalether()` - serializes Ethernet header, calls `evalip()` for the payload. No checksum - hardware handles FCS
- `show_ether()` - prints MACs as `xx:xx:xx:xx:xx:xx` via shift+mask byte extraction
- `free_ether()` - frees the full `ether → ip → icmp` chain in order (children before parent)
- `recv_frame()` - receives raw Ethernet frame, checks EtherType, strips header, passes IP bytes to `recvip()`

**Key change from Phase 7**: socket upgraded from `AF_INET` to `AF_PACKET + SOCK_RAW`. This drops below the IP layer - the OS hands raw Ethernet frames directly, bypassing all IP/TCP/UDP processing. `IP_HDRINCL` removed since the OS never touches the IP header at the Ethernet layer.

### ARP Resolution

- `arp` struct: 28-byte wire format per RFC 826 - `htype`, `ptype`, `hlen`, `plen`, `op`, `sha`, `spa`, `tha`, `tpa`
- No separate logical struct - ARP is used exactly once for gateway discovery
- `send_arp()` - broadcasts ARP request for gateway IP (`10.0.2.2`). Destination MAC `FF:FF:FF:FF:FF:FF`. Frame built manually into a stack buffer since there is no IP layer - `sendframe()` cannot be reused here
- `recv_arp()` - listens for ARP reply, extracts `sha` (sender hardware address = gateway MAC). Returns zeroed `mac` as error sentinel

### Interface Helpers

- `setup()` - creates `AF_PACKET` raw socket, sets 2-second receive timeout
- `if2idx()` - resolves interface name to kernel index via `ioctl(SIOCGIFINDEX)`. Used by `sendframe()` and `send_arp()` to populate `sockaddr_ll.sll_ifindex`
- `get_mac()` - reads own MAC via `ioctl(SIOCGIFHWADDR)`. Uses `uint64_t` intermediate for `memcpy` since bit fields have no addressable memory location
- `get_ip()` - reads own IPv4 address via `ioctl(SIOCGIFADDR)`. Casts `ifr.ifr_addr` to `sockaddr_in *` to extract `sin_addr.s_addr`
- `sendframe()` - calls `evalether()` to produce a complete frame, sends via `sendto()` with `sockaddr_ll`

### Verified end-to-end

ARP exchange and ICMP ping/reply confirmed with tcpdump:
```
ARP, Request who-has 10.0.2.2 tell 10.0.2.15
ARP, Reply 10.0.2.2 is-at 52:54:00:12:35:02
IP 10.0.2.15 > 8.8.8.8: ICMP echo request, id 1, seq 1, length 19
IP 8.8.8.8 > 10.0.2.15: ICMP echo reply, id 1, seq 1, length 19
```

---

## Concepts Studied via DSA Practice

Each concept was studied through a targeted problem before the implementation phase that required it.

| Concept | Applied In |
|---|---|
| Bit manipulation and masking | Packet field parsing, MAC byte extraction |
| Bit streaming and byte reordering | Endianness conversion, `htons()` usage |
| One's complement arithmetic | Internet checksum (ICMP + IP) |
| Byte stream parsing by leading bits | IP header IHL parsing |
| Sliding window over a buffer | In-flight packet tracking |
| Length-prefix serialization | `eval_*` function pattern |
| IPv4 and IPv6 string validation | IP address handling in `mkip()` |
| Linked list reversal | Understanding pointer chain traversal for free chain |
| LRU Cache | Understanding MAC address cache design (ARP table concept) |

---

## Reading

- Beej's Guide to Network Programming - cover to cover before Part 2
- RFC 792 - ICMP specification
- RFC 791 - IPv4 specification
- RFC 826 - ARP specification
- Linux kernel source: `net/ethernet/eth.c` - EtherType constants
- iputils ping source (`apt source iputils-ping`) - production implementation comparison
- Jonas Birch's `esther.h` and `esther.c` - reference implementation

---

## Project Structure

```
ping/
├── simple_version/
│   └── icmp.c          # Part 1 - complete working ping using stdlib
├── ping_v2.c           # Part 2 - Jonas Birch rebuild, complete
└── README.md
```

---

## Environment

Developed on Ubuntu 22.04 in a VirtualBox VM. WSL2 is insufficient for this project - its NAT layer intercepts ICMP replies from internet addresses before raw sockets can receive them. Native Linux is required for raw socket work beyond loopback.

---

**Note**: This is a learning project built from first principles. The intent is depth of understanding, not production readiness.