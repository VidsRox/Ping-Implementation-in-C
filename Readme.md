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

## Part 2 - Jonas Birch Rebuild (in progress)

Located in `ping_v2.c`.

This is a complete rebuild following the architectural approach from Dr. Jonas Birch's ping series. The core idea is the **two-struct pattern**: every protocol layer has a logical struct for convenient in-code representation and a packed raw struct that exactly matches the wire format. An `eval_*` function converts between them at send time.

```
mkicmp()  →  logical icmp struct  →  eval_icmp()  →  raw wire bytes  →  sendto()
```

Before starting Part 2, LeetCode #271 Encode and Decode Strings was studied specifically because length-prefix serialization - encoding structured data into a flat byte stream and recovering it - is exactly the pattern `eval_icmp()` implements.

### ICMP Layer ✅ Complete

- `type` enum: `unassigned`, `echo`, `echoreply`, `L4icmp`, `L4tcp`, `L4udp`
- `s_icmp` logical struct: `kind`, `identifier`, `seq_num`, `size`, `*data`
- `s_rawicmp` raw struct: `Type`, `code`, `checksum`, `identifier`, `seq_num`, `data[]` - packed, matches RFC 792 wire format exactly
- `mkicmp()` - constructor, heap-allocates logical struct
- `eval_icmp()` - serializes to wire bytes, two-stage copy (header then payload), checksum computed last over assembled buffer
- `show_icmp()` - debug printer with hex dump
- `free_icmp()` - cleanup

**Design decision**: identifier and sequence number are kept in the ICMP header per RFC 792, rather than in a nested payload struct as Jonas does. This is a deliberate divergence that stays closer to the spec.

### IP Layer ✅ Complete

- `s_ip` logical struct: `kind`, `src`, `dst`, `id`, `*payload`
- `s_rawip` raw struct: all RFC 791 fields packed - version, IHL, DSCP, ECN, length, id, flags, offset, TTL, protocol, checksum, src, dst
- `mkip()` - constructor with dual id/counter parameter pattern for flexible ID assignment
- `evalip()` - serializes IP header and calls `eval_icmp()` internally to nest the ICMP payload, checksum computed over assembled buffer
- `showip()` - debug printer that recurses into `show_icmp()` for the payload
- `free_ip()` - cleanup
- `setup()` - raw socket creation with `IP_HDRINCL` so the OS doesn't prepend its own IP header
- `sendip()` - calls `evalip()` then `sendto()`
- `recvip()` - inverse of `evalip()`, strips layers inward to reconstruct nested logical structs from raw wire bytes

**Key concept**: bit field ordering in `s_rawip`. On little-endian x86, the compiler fills bit fields from the least significant bit upward. To get `version` in the upper 4 bits and `ihl` in the lower 4 bits of the first byte - as RFC 791 requires - they must be declared in reverse order: `ihl:4` first, then `version:4`. The same applies to `ecn:2` and `dscp:6` sharing the second byte.

**Verified**: echo request sent to `8.8.8.8`, echo reply received and parsed correctly. tcpdump confirmed correct id and seq fields on the wire.

### What's next

Drop to Layer 2 using `AF_PACKET` raw sockets. Manual Ethernet frame construction with MAC addresses and EtherType. `getifaddrs()` for interface enumeration. ARP resolution for destination MAC address.

---

## Concepts Studied via DSA Practice

Each concept was studied through a targeted problem before the implementation phase that required it.

| Concept | Applied In |
|---|---|
| Bit manipulation and masking | Packet field parsing |
| Bit streaming and byte reordering | Endianness conversion |
| One's complement arithmetic | Internet checksum |
| Byte stream parsing by leading bits | IP header IHL parsing |
| Sliding window over a buffer | In-flight packet tracking |
| Length-prefix serialization and deserialization | eval_* function pattern |
| IPv4 and IPv6 string validation | IP address handling in mkip() |

---

## Reading

- Beej's Guide to Network Programming - cover to cover before Part 2
- RFC 792 - ICMP specification
- RFC 791 - IPv4 specification
- iputils ping source (`apt source iputils-ping`) - production implementation comparison

---

## Project Structure

```
ping/
├── simple_version/
│   └── icmp.c          # Part 1 - complete working ping
├── ping_v2.c           # Part 2 - Jonas Birch rebuild (in progress)
└── README.md
```

---

## Environment

Developed on Ubuntu 24.04 in a VirtualBox VM. WSL2 is insufficient for this project - its NAT layer intercepts ICMP replies from internet addresses before raw sockets can receive them. Native Linux is required for raw socket work beyond loopback.

---

**Note**: This is a learning project built from first principles. The intent is depth of understanding, not production readiness.