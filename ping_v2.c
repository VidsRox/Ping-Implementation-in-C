#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <net/if.h>        /* struct ifreq, IFNAMSIZ - must come before linux/if_packet.h
                              to avoid kernel/glibc header conflict over struct ifreq definition */
#include <sys/ioctl.h>     /* ioctl(), SIOCGIFINDEX */
#include <linux/if_packet.h> /* struct sockaddr_ll - link-layer socket address for AF_PACKET */
#include <net/ethernet.h>

#define packed __attribute__((packed))

typedef enum{
    unassigned = 0,
    echo,
    echoreply,
    L4icmp,
    L4tcp,
    L4udp
} type;

/* Saw both of these as ETH_P_IP and ETH_P_ARP in the Linux kernel source (net/ethernet/eth.c).
   These values live in the Ethernet header's 16-bit EtherType field - they tell the receiving
   NIC what protocol the payload contains. They are NOT the same as IP protocol numbers. */
typedef enum{
    unset = 0,
    tIP  = 0x0800, /* payload is an IPv4 packet */
    tARP = 0x0806  /* payload is an ARP packet - used for gateway MAC resolution */
} packed ethertype;

/* A MAC address is 6 bytes - 48 bits. Storing it as the lower 48 bits of a uint64_t lets us
   pass it around as a single integer rather than an array of 6 bytes, which makes comparison
   and assignment cleaner. The :48 bit field constrains it so the upper 16 bits are always zero. */
typedef struct s_mac{
    uint64_t addr:48;
} packed mac;

/* logical struct - convenient in-code representation of an ICMP packet */
typedef struct s_icmp{
    type kind:3;
    uint16_t identifier;
    uint16_t seq_num;
    uint16_t size;
    uint8_t *data;
} packed icmp;

/* raw struct - exact wire format. flexible array member data[] lets the struct sit at the
   front of a flat buffer with the payload immediately following in memory. */
typedef struct s_rawicmp{
    uint8_t Type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t seq_num;
    uint8_t data[];
} packed rawicmp;

/* logical struct - convenient in-code representation of an IP packet */
typedef struct s_ip{
    type kind:3;
    uint32_t src;
    uint32_t dst;
    uint16_t id;
    icmp *payload;
} packed ip;

/* raw struct - exact wire format per RFC 791.
   Bit field ordering: ihl:4 before version:4, ecn:2 before dscp:6.
   On little-endian x86, the compiler fills bit fields LSB-first within each byte,
   so the lower-bits field must be declared first to match the wire layout. */
typedef struct s_rawip{
    uint8_t ihl:4;     /* IP header length in 32-bit words. Always 5 for us (no options): 5*4=20 bytes */
    uint8_t version:4;
    uint8_t ecn:2;
    uint8_t dscp:6;
    uint16_t length;
    uint16_t id;
    uint16_t flags:3;
    uint16_t offset:13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
    uint8_t options[];
} packed rawip;

/* logical struct - convenient in-code representation of an Ethernet frame.
   payload points to the IP packet inside. Protocol tells us the EtherType. */
typedef struct s_ether{
    ethertype protocol;
    mac src;
    mac dst;
    ip *payload;
} packed ether;

/* raw struct - exact wire format. Note: destination MAC comes first on the wire,
   then source, then EtherType. This is the layout the NIC expects. */
typedef struct s_rawether{
    mac dst;       /* destination first on wire */
    mac src;       /* then source */
    uint16_t type; /* EtherType last - 0x0800 for IP, 0x0806 for ARP */
} packed rawether;

/* ARP packet structure per RFC 826 - 28 bytes total for Ethernet/IPv4.
   No separate logical struct needed - ARP is used exactly once for gateway MAC resolution,
   so we work directly with the wire format. */
typedef struct arp_struct{
    uint16_t htype; /* hardware type - 1 for Ethernet */
    uint16_t ptype; /* protocol type - 0x0800 for IPv4, shares numbering with EtherType */
    uint8_t  hlen;  /* hardware address length in bytes - 6 for MAC */
    uint8_t  plen;  /* protocol address length in bytes - 4 for IPv4 */
    uint16_t op;    /* operation: 1 = request, 2 = reply */
    mac      sha;   /* sender hardware address - MAC of whoever sent this packet */
    uint32_t spa;   /* sender protocol address - IP of whoever sent this packet */
    mac      tha;   /* target hardware address - zero in a request (unknown), filled in reply */
    uint32_t tpa;   /* target protocol address - IP we are trying to resolve */
} packed arp;

uint16_t checksum(uint8_t *data, int length){
    uint32_t sum = 0; /* 32 bits needed - summing multiple 16-bit values can overflow 16 bits */
    for(int i = 0; i < length; i += 2){
        uint16_t chunk = *(uint16_t *)(data + i); /* read 2 bytes as-is from memory */
        sum += chunk;
    }
    while(sum>>16){ /* if bits above lower 16 exist, overflow occurred - fold them back in */
        sum = (sum>>16) + (sum & 0xFFFF);
    }
    return ~sum;
}

/* constructor for logical ether struct.
   Sets payload to NULL - caller attaches the ip * after construction. */
ether *mkether(ethertype type, mac *source, mac *dest){
    uint16_t size;
    ether *e;
    if(!type || !source || !dest) return (ether *)0;
    size = sizeof(ether);
    e = (ether *)malloc(size);
    assert(e);
    memset(e, 0, size);
    e->src = *source;
    e->dst = *dest;
    e->protocol = type;
    e->payload = (ip *)0;
    return e;
}

/* constructor for logical ip struct.
   Takes everything needed to describe an IP packet in convenient form and produces
   a heap-allocated ip struct. Catches invalid destinations - inet_addr() returns 0
   for "0.0.0.0" which is not a valid ping target. */
ip *mkip(type kind, const uint8_t *src, const uint8_t *dst, uint16_t id_, uint16_t *cntptr){
    uint16_t id;
    uint16_t size;
    ip *pkt;
    if(!kind || !src || !dst) return (ip *)0;
    if(id_){
        id = id_;
    } else{
        id = *cntptr++;
    }
    size = sizeof(ip);
    pkt = (ip *)malloc(size);
    assert(pkt);
    memset(pkt, 0, size);
    pkt->kind = kind;
    pkt->id = id;
    pkt->src = inet_addr((char *)src);
    pkt->dst = inet_addr((char *)dst);
    pkt->payload = (icmp *)0;
    if(!pkt->dst){
        free(pkt);
        return (ip *)0;
    }
    return pkt;
}

/* constructor for logical icmp struct.
   data pointer is stored directly - no copy. Caller owns the data buffer. */
icmp *mkicmp(type kind, const uint8_t *data, uint16_t size, uint16_t id, uint16_t seq){
    uint16_t n;
    icmp *p;
    if(!data || !size || !id || !seq) return (icmp *)0;

    n = sizeof(struct s_icmp) + size;
    p = (icmp *)malloc(n);
    assert(p);
    memset(p, 0, n);

    p->kind = kind;
    p->size = size;
    p->data = (uint8_t *)data;
    p->identifier = id;
    p->seq_num = seq;

    return p;
}

/* eval_icmp - converts logical icmp struct to wire-format bytes.
   Two-stage pattern: populate rawicmp on stack, malloc a flat buffer,
   copy header in, copy payload after it, then compute and patch in checksum.
   Returns heap-allocated buffer - caller must free(). */
uint8_t *eval_icmp(icmp *pkt){
    rawicmp raw = {0}; /* stack-allocated wire struct, zeroed */
    rawicmp *rawptr;

    if(!pkt || !pkt->data) return NULL;

    switch(pkt->kind){
        case echo:
            raw.Type = 8; /* ICMP echo request type number per RFC 792 */
            raw.code = 0;
            break;
        case echoreply:
            raw.Type = 0;
            raw.code = 0;
            break;
        default:
            return 0;
            break;
    }
    raw.code = 0;
    raw.identifier = htons(pkt->identifier); /* 16-bit fields going onto the wire need byte-swapping */
    raw.seq_num    = htons(pkt->seq_num);

    raw.checksum   = 0; /* zeroed before checksum computation - required by the checksum algorithm */

    uint16_t size = sizeof(rawicmp) + pkt->size;
    if(size%2) size++; /* checksum algorithm reads 2 bytes at a time - pad to even length */

    uint8_t *buf = calloc(size, 1);
    uint8_t *ret = buf;
    assert(buf);

    memcpy(buf, &raw, sizeof(rawicmp));         /* copy ICMP header */
    buf = buf + sizeof(rawicmp);                /* advance cursor past header */
    memcpy(buf, pkt->data, pkt->size);          /* copy payload after header */

    uint16_t check = checksum(ret, size);

    rawptr = (rawicmp *)ret;
    rawptr->checksum = check;                   /* patch checksum directly into the buffer */

    return ret;
}

/* evalip - converts logical ip struct to wire-format bytes.
   Calls eval_icmp() to serialize the payload, then prepends the IP header.
   sizeof(rawip)/4 gives ihl automatically - no hardcoding needed since we never use options,
   and sizeof(rawip) == ihl*4 == 20 bytes always.
   Returns heap-allocated buffer - caller must free(). */
uint8_t *evalip(ip *pkt){
    rawip rawpkt;
    rawip *rawptr;
    uint16_t check;
    uint8_t *p, *ret;
    uint8_t protocol;
    uint16_t length_le;
    uint16_t length_be;
    uint8_t *icmp_ptr;
    uint16_t size;

    if(!pkt) return (uint8_t *)0;

    protocol = 0;
    switch(pkt->kind){
        case L4icmp:
            protocol = 1; /* IPPROTO_ICMP = 1 per IANA */
            break;
        default:
            return (uint8_t *)0;
            break;
    }

    rawpkt.checksum = 0;
    rawpkt.dscp     = 0;
    rawpkt.ecn      = 0;
    rawpkt.dst      = pkt->dst;
    rawpkt.flags    = 0;
    rawpkt.id       = htons(pkt->id);
    rawpkt.ihl      = (sizeof(rawip)/4); /* = 5, meaning 20 bytes. Used both as a header field
                                            and to compute total length below. */

    length_le = 0;

    if(pkt->payload){
        /* total = IP header + ICMP header + ICMP payload */
        length_le  = (rawpkt.ihl * 4) + pkt->payload->size + sizeof(rawicmp);
        length_be  = htons(length_le);
        rawpkt.length = length_be;
    } else{
        length_le = rawpkt.length = (rawpkt.ihl * 4);
    }

    rawpkt.offset   = 0;
    rawpkt.protocol = protocol;
    rawpkt.src      = pkt->src;
    rawpkt.ttl      = 250;
    rawpkt.version  = 4;

    if(length_le%2) length_le++; /* pad to even for checksum */
    size = sizeof(rawip);
    p = (uint8_t *)malloc(length_le);
    ret = p;
    assert(p);
    memset(p, 0, length_le);
    memcpy(p, &rawpkt, size); /* copy IP header */
    p += size;                /* advance cursor past IP header */

    icmp_ptr = eval_icmp(pkt->payload); /* serialize ICMP - chain call downward */
    if(icmp_ptr){
        memcpy(p, icmp_ptr, sizeof(rawicmp) + pkt->payload->size); /* copy ICMP after IP header */
        free(icmp_ptr);
    }

    check = checksum(ret, length_le);

    rawptr = (rawip *)ret;
    rawptr->checksum = check; /* patch checksum into buffer */

    return ret;
}

/* evalether - converts logical ether struct to a complete wire-format Ethernet frame.
   Calls evalip() to serialize the IP+ICMP payload, then prepends the Ethernet header.
   No checksum at the Ethernet layer - hardware handles FCS automatically.
   sizeof(rawip) substitutes directly for ihl*4 since we never use IP options.
   Returns heap-allocated buffer - caller must free(). */
uint8_t *evalether(ether *e){
    rawether raw_ether; /* wire-format struct - what actually goes on the wire */
    uint8_t *ip_bytes;  /* raw bytes returned by evalip() */
    uint8_t *p, *ret;   /* p: write cursor, ret: start of buffer to return */
    uint16_t size;      /* total frame size: ether header + IP + ICMP + payload */
    if(!e) return (uint8_t *)0;
    /* populate wire-format Ethernet header from logical struct */
    raw_ether.src  = e->src;
    raw_ether.dst  = e->dst;
    raw_ether.type = htons(e->protocol); /* EtherType is a 16-bit big-endian wire field */

    /* no ihl variable needed - sizeof(rawip) == ihl*4 == 20 bytes, no options */
    size = sizeof(rawether) + sizeof(rawip) + sizeof(rawicmp) + e->payload->payload->size;
    p = (uint8_t *)malloc(size);
    ret = p;

    assert(p);
    memset(p, 0, size);
    /* copy wire-format Ethernet header (not logical struct e) - two-struct pattern */
    memcpy(p, &raw_ether, sizeof(rawether));
    p += sizeof(rawether); /* advance cursor past Ethernet header */

    /* let evalip() handle IP+ICMP serialization - chain call downward */
    ip_bytes = evalip(e->payload);
    if(ip_bytes){
        memcpy(p, ip_bytes, sizeof(rawip) + sizeof(rawicmp) + e->payload->payload->size);
        free(ip_bytes);
    }
    return ret;
}

void show_icmp(uint8_t *id, icmp *pkt){
    if(!pkt) return;
    printf("(icmp *)%s = {\n", (char *)id);
    printf(" kind:\t %s\n size:\t %d bytes of payload\n}\npayload:\n",
        (pkt->kind == echo) ? "echo" : "echo reply",
        pkt->size);
    if(pkt->data){
        if((pkt->kind==echo) || (pkt->kind==echoreply)){
            for(int i = 0; i < pkt->size; i++){
                printf("%02x", pkt->data[i]);
                if((i+1)%8==0) printf("\n");
            }
            printf("\n");
        }
    }
}

void free_icmp(icmp *pkt){
    free(pkt);
}

void showip(uint8_t *id, ip *pkt){
    uint16_t n;
    if(!pkt) return;
    if(pkt->payload){
        n = sizeof(rawicmp) + sizeof(rawip) + pkt->payload->size;
    } else{
        n = sizeof(rawip);
    }
    printf("(ip *)%s = {\n", (char *)id);
    printf("  size:\t %d bytes total\n", (int)n);
    printf("  kind:\t 0x%.02hhx\n", (char)pkt->kind);
    printf("  id:\t 0x%.02hhx\n", (int)pkt->id);
    struct in_addr source;
    source.s_addr = pkt->src;
    struct in_addr dest;
    dest.s_addr = pkt->dst;
    printf("  src:\t %s\n", inet_ntoa(source));
    printf("  dst:\t %s\n", inet_ntoa(dest));
    printf("}\n");
    if(pkt->payload)
        show_icmp("payload", pkt->payload);
    return;
}

/* show_ether - prints Ethernet-layer fields only.
   MAC addresses are printed as xx:xx:xx:xx:xx:xx by extracting each byte via shift+mask:
   (addr >> (n*8)) & 0xFF gives byte n of the 48-bit MAC stored in uint64_t.
   showip() is called for the IP payload - no duplication of IP fields here. */
void show_ether(uint8_t *id, ether *e){
    uint16_t n;
    if(!e) return;
    if(e->payload->payload){
        n = sizeof(rawether) + sizeof(rawicmp) + sizeof(rawip) + e->payload->payload->size;
    } else{
        n = sizeof(rawether);
    }
    printf("(e *)%s = {\n", (char *)id);
    printf("  size:\t %d bytes total\n", (int)n);
    printf("  protocol:\t 0x%.02hhx\n", (char)e->protocol);
    printf("mac src:\t%02x:%02x:%02x:%02x:%02x:%02x\n",
        (uint8_t)(e->src.addr & 0xFF),
        (uint8_t)((e->src.addr >> 8)  & 0xFF),
        (uint8_t)((e->src.addr >> 16) & 0xFF),
        (uint8_t)((e->src.addr >> 24) & 0xFF),
        (uint8_t)((e->src.addr >> 32) & 0xFF),
        (uint8_t)((e->src.addr >> 40) & 0xFF));
    printf("mac dst:\t%02x:%02x:%02x:%02x:%02x:%02x\n",
        (uint8_t)(e->dst.addr & 0xFF),
        (uint8_t)((e->dst.addr >> 8)  & 0xFF),
        (uint8_t)((e->dst.addr >> 16) & 0xFF),
        (uint8_t)((e->dst.addr >> 24) & 0xFF),
        (uint8_t)((e->dst.addr >> 32) & 0xFF),
        (uint8_t)((e->dst.addr >> 40) & 0xFF));
    printf("}\n");
    if(e->payload->payload)
        showip("payload", e->payload->payload);
    return;
}

void free_ip(ip *pkt){
    free(pkt);
}

void free_ether(ether *e){
    if(!e) return;
    free_icmp(e->payload->payload);
    free_ip(e->payload);
    free(e);
}

/* setup - creates and configures the raw socket.
   Phase 8 change: AF_INET → AF_PACKET + SOCK_RAW.
   AF_PACKET gives access below the IP layer - the OS hands raw Ethernet frames directly,
   bypassing IP/TCP/UDP processing entirely. htons(tIP) tells the kernel to hand us
   only frames with EtherType 0x0800 (IPv4).
   IP_HDRINCL removed - it was needed with AF_INET to prevent the OS from adding its own
   IP header. With AF_PACKET the OS never touches the IP header at all. */
uint32_t setup(){
    uint32_t s;
    signed int tmp;
    struct timeval tv;
    tv.tv_sec  = 2;
    tv.tv_usec = 0;
    tmp = socket(AF_PACKET, SOCK_RAW, htons(tIP));
    if(tmp>2) s = (uint32_t)tmp;
    else      s = (uint32_t)0;
    setsockopt((int)s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    return s;
}

/* if2idx - resolves a network interface name to its kernel integer index.
   Uses ioctl(SIOCGIFINDEX): fill ifreq with the name, kernel writes the index back.
   Think of it as handing the kernel a form with the interface name filled in -
   it stamps the index on it and hands it back.
   The index is what sockaddr_ll needs to know which interface to send frames on. */
int if2idx(uint32_t s, const char *ifname){
    struct ifreq ifr; /* two-way communication channel with the kernel via ioctl() */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1); /* IFNAMSIZ=16, -1 leaves room for null terminator */
    if(ioctl((int)s, SIOCGIFINDEX, &ifr) < 0) return -1;
    return ifr.ifr_ifindex; /* kernel wrote the index here */
}

/* sendframe - sends a complete Ethernet frame.
   Phase 8 replacement for sendip(). Uses evalether() instead of evalip() to produce
   a full frame including the Ethernet header. sockaddr_ll replaces sockaddr_in -
   at the Ethernet layer the kernel doesn't route by IP, it just needs to know
   which interface index to send the frame out on. */
bool sendframe(uint32_t s, ether *frames){
    uint8_t *raw;
    uint16_t n;
    signed int ret;
    struct sockaddr_ll sock;
    if(!s || !frames) return false;
    memset(&sock, 0, sizeof(sock));
    raw = evalether(frames); /* serialize full frame: Ethernet + IP + ICMP */
    n   = sizeof(rawether) + sizeof(rawip) + sizeof(rawicmp) + frames->payload->payload->size;
    sock.sll_ifindex = if2idx(s, "enp0s3"); /* interface index - not IP/MAC address */
    ret = sendto((int)s, raw, (int)n, 0, (const struct sockaddr *)&sock, sizeof(sock));
    free(raw);
    if(ret<0) return false;
    else      return true;
}

/* send_arp - broadcasts an ARP request to discover the gateway's MAC address.
   ARP payload goes directly inside the Ethernet frame - no IP layer in between,
   so sendframe() cannot be reused here (it assumes an IP payload exists).
   Instead we build the frame manually: rawether + arp packed into a stack buffer,
   then call sendto() directly.
   Destination MAC is FF:FF:FF:FF:FF:FF - the Ethernet broadcast address,
   meaning every device on the local network receives this frame.
   EtherType is tARP (0x0806), not tIP.
   tha (target hardware address) is left zero - that's what we're asking for.
   spa/sha identify us as the sender so the gateway knows where to send the reply. */
bool send_arp(uint32_t socket, mac *mac_src, uint32_t *ip_src, uint32_t *ip_dst){
    arp request;
    uint8_t buf[sizeof(rawether) + sizeof(arp)]; /* stack-allocated - no malloc needed,
                                                    buffer is only used inside this function */
    rawether raw_ether;
    signed int ret;
    uint8_t *p;
    struct sockaddr_ll sock;

    memset(&request, 0, sizeof(arp)); /* zeroes tha - correct for ARP request */

    request.htype = htons(1);       /* Ethernet hardware type */
    request.ptype = htons(tIP);     /* resolving IPv4 addresses */
    request.hlen  = 6;              /* MAC address length in bytes */
    request.plen  = 4;              /* IPv4 address length in bytes */
    request.op    = htons(1);       /* 1 = request, 2 = reply - big-endian wire field */
    request.sha   = *mac_src;       /* our MAC - dereference pointer to copy struct value */
    request.spa   = *ip_src;        /* our IP - already in network byte order from inet_addr() */
    request.tpa   = *ip_dst;        /* gateway IP we want to resolve */
    /* tha left zero - memset above already handled it */
    raw_ether.dst.addr = 0xFFFFFFFFFFFF; /* broadcast - all 48 bits set */
    raw_ether.src      = *mac_src;
    raw_ether.type     = htons(tARP);

    memset(buf, 0, sizeof(buf));
    p = buf;
    memcpy(p, &raw_ether, sizeof(rawether)); /* Ethernet header first on wire */
    p += sizeof(rawether);
    memcpy(p, &request, sizeof(arp));        /* ARP payload immediately after */

    memset(&sock, 0, sizeof(sock));
    sock.sll_ifindex = if2idx(socket, "enp0s3");
    /* broadcast destination MAC is inside the frame itself - sockaddr_ll only needs
       the interface index, not a destination address */
    ret = sendto((int)socket, buf, sizeof(rawether) + sizeof(arp), 0,
                 (const struct sockaddr *)&sock, sizeof(sock));

    if(ret<0) return false;
    else      return true;
}

/* recvip - parses raw IP bytes into a logical ip struct.
   Phase 8 change: no longer reads from the socket directly. recv_frame() makes the
   single recvfrom() call, strips the Ethernet header, and passes just the IP bytes here.
   This avoids making two separate recvfrom() calls (which would read two different packets).
   buf points to the start of the IP header - Ethernet header already stripped by caller. */
ip *recvip(uint8_t *buf, uint16_t n){
    ip *ip_pkt;
    rawip *raw_ip;
    uint8_t src[16], dst[16];
    uint16_t id;
    type kind;
    uint16_t check_sum;
    rawicmp *raw_icmp;
    icmp *icmp_pkt;
    type icmpkind;
    uint16_t icmp_checksum;
    uint16_t len;
    uint8_t *tmp;
    raw_ip = (rawip *)buf; /* buf is already a pointer - no & needed */
    id = ntohs(raw_ip->id);
    memset(&src, 0, 16);
    memset(&dst, 0, 16);
    struct in_addr addr;
    addr.s_addr = raw_ip->src;
    tmp = inet_ntoa(addr);
    len = strlen(tmp);
    memcpy(&src, tmp, len);
    struct in_addr addr2;
    addr2.s_addr = raw_ip->dst;
    tmp = inet_ntoa(addr2);
    len = strlen(tmp);
    memcpy(&dst, tmp, len);
    if(n%2) n++; /* pad to even for checksum */
    check_sum = checksum(buf, n);
    if(check_sum){
        fprintf(stderr, "Received packet with malformed checksum: 0x%.04hx\n", (int)raw_ip->checksum);
        return (ip *)0;
    }
    kind = (raw_ip->protocol == 1) ? L4icmp : unassigned;
    if(kind != L4icmp){
        fprintf(stderr, "Unsupported packet type received: 0x%.04hx\n", (int)raw_ip->protocol);
        return (ip *)0;
    }
    ip_pkt = mkip(kind, src, dst, id, 0);
    n = n - sizeof(rawip);
    if(!n){
        ip_pkt->payload = (icmp *)0;
        return ip_pkt;
    }
    raw_icmp = (rawicmp *)(buf + sizeof(rawip)); /* advance past IP header to find ICMP */
    if((raw_icmp->Type==8) && !raw_icmp->code)  icmpkind = echo;
    else if(!raw_icmp->Type && !raw_icmp->code) icmpkind = echoreply;
    else                                         icmpkind = unassigned;
    /* if unassigned, return null - recvip() no longer has a socket to retry with.
       Caller (recv_frame) decides whether to call again. */
    if(icmpkind == unassigned) return (ip *)0;
    icmp_checksum = checksum((uint8_t *)raw_icmp, n);
    if(icmp_checksum){
        fprintf(stderr, "ICMP checksum failed: 0x%.04hx\n", (int)raw_icmp->checksum);
        return (ip *)0;
    }
    n = n - sizeof(rawicmp);
    uint8_t *payload = NULL;
    if(n > 0){
        payload = malloc(n);
        memset(payload, 0, n);
        memcpy(payload, raw_icmp->data, n);
    }
    icmp_pkt = mkicmp(icmpkind, payload, n, ntohs(raw_icmp->identifier), ntohs(raw_icmp->seq_num));
    if(!icmp_pkt) return ip_pkt;
    else          ip_pkt->payload = icmp_pkt;
    return ip_pkt;
}

/* recv_arp - listens for an ARP reply and extracts the sender's MAC address.
   The gateway sends a reply with its MAC in the sha (sender hardware address) field.
   Returns a zeroed mac struct on failure - zero is not a valid real MAC address,
   so it serves as a sentinel that main() can check. */
mac recv_arp(uint32_t socket){
    arp *arp_reply;
    uint8_t buf[1600];
    rawether *raw_ether;
    signed int ret;
    mac gateway_mac;
    memset(&gateway_mac, 0, sizeof(mac)); /* zero = error sentinel */
    ret = recvfrom((int)socket, &buf, 1599, 0, 0, 0);
    if(ret < 0) return gateway_mac;
    raw_ether = (rawether *)buf;
    if(raw_ether->type != htons(tARP)) return gateway_mac; /* not an ARP frame - ignore */
    arp_reply = (arp *)(buf + sizeof(rawether)); /* advance past Ethernet header to ARP payload */
    /* sha = sender hardware address - the gateway's MAC, which is what we're after.
       tha would be our own MAC echoed back, not what we want. */
    if(arp_reply->op == htons(2)) gateway_mac = arp_reply->sha; /* op=2 means reply */
    return gateway_mac;
}

/* recv_frame - receives a raw Ethernet frame and passes the IP payload to recvip().
   With AF_PACKET the socket delivers complete Ethernet frames - the Ethernet header
   arrives first in the buffer before the IP header. recv_frame() strips it off and
   passes just the IP bytes to recvip(), which doesn't touch the socket at all.
   Returns NULL for non-IP frames rather than recursing - unbounded recursion risks
   stack overflow if a flood of non-IP frames arrives. Caller decides whether to retry. */
ether *recv_frame(uint32_t s){
    uint8_t buf[1600];
    signed int ret;
    uint16_t n;
    rawether *raw_ether;
    ether *e;
    if(!s) return (ether *)0;

    memset(&buf, 0, 1600);
    ret = recvfrom((int)s, &buf, 1599, 0, 0, 0);
    if(ret<0) return (ether *)0;
    else n = (uint16_t)ret;
    raw_ether = (rawether *)&buf;

    if(raw_ether->type != htons(tIP)) return NULL; /* drop non-IP frames */

    /* build logical ether struct from wire header fields */
    e = mkether(raw_ether->type, &raw_ether->src, &raw_ether->dst);

    n = n - sizeof(rawether); /* subtract Ethernet header - n now = IP+ICMP bytes only */
    if(!n){
        e->payload = (ip *)0;
    }
    
    /* buf + sizeof(rawether): skip past the Ethernet header to where IP starts.
       Same pointer arithmetic as recvip() uses to skip past the IP header to find ICMP. */
    e->payload = recvip(buf + sizeof(rawether), n);
    return e;
}

int main(){
    /* TODO: Phase 8 main() - wire everything together:
       1. setup() - open AF_PACKET socket
       2. get our own MAC and IP (needed for ARP sender fields)
       3. send_arp() - broadcast ARP request for gateway (10.0.2.2)
       4. recv_arp() - receive gateway MAC
       5. mkicmp() + mkip() + mkether() - build full packet chain
       6. sendframe() - send complete Ethernet frame
       7. recv_frame() - receive echo reply
       8. show_ether() - display result
       9. free_ether() - clean up */
    icmp *pkt   = mkicmp(echo, "hello world", strlen("hello world"), 1, 1);
    ip *packet  = mkip(L4icmp, "0.0.0.0", "8.8.8.8", 1, NULL);
    packet->payload = pkt;
    uint32_t s  = setup();
    /* sendip and recvip(s) removed - replaced by sendframe() and recv_frame() */
}