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

#define packed __attribute__((packed))


typedef enum{
    unassigned = 0,
    echo,
    echoreply,
    L4icmp,
    L4tcp,
    L4udp
} type;

//logical struct-
typedef struct s_icmp{
    type kind:3;
    uint16_t identifier;
    uint16_t seq_num;
    uint16_t size;
    uint8_t *data;

}packed icmp;

//raw struct
typedef struct s_rawicmp{
    uint8_t Type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t seq_num;
    uint8_t data[];

}packed rawicmp;

typedef struct s_ip{
    type kind:3;
    uint32_t src;
    uint32_t dst;
    uint16_t id;
    icmp *payload;
} packed ip;

typedef struct s_rawip{
    uint8_t ihl:4;
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

uint16_t checksum(uint8_t *data, int length){
    uint32_t sum = 0;// need 32 bits to hold the running sum because adding multiple 16-bit values can exceed 16 bits.


    for(int i = 0; i < length; i += 2){
        uint16_t chunk = *(uint16_t *)(data + i);  // read 2 bytes as-is from memory
        sum += chunk;
    }


    while(sum>>16)//if bits above lower 16 bits exist, overflow occured
    {
        sum = (sum>>16) + (sum & 0xFFFF);
    }
    return ~sum;
}

//constructor for logical ip struct

/*takes everything needed to describe an IP packet in convenient form - the protocol kind, 
source address, destination address, and an identifier - and produces a heap-allocated ip 
struct with all those values stored.*/
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

//catches invalid destination addresses since inet_addr() returns 0 for "0.0.0.0" which is an invalid destination for a real ping.    
    if(!pkt->dst){
        free(pkt);
        return (ip *)0;
    }

    return pkt; 
}

//mk_icmp populates the logical struct
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

//eval_icmp
uint8_t *eval_icmp(icmp *pkt){

    rawicmp raw = {0};//create raw struct on stack, zeroed
    rawicmp *rawptr;

    if(!pkt || !pkt->data) return NULL;

    //fill raw fields from pkt
    switch(pkt->kind){
        case echo:
            raw.Type = 8;
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
    raw.identifier = htons(pkt->identifier);//16 bit fields going onto the wire- byte conversion is needed
    raw.seq_num = htons(pkt->seq_num);

    raw.checksum = 0;

    uint16_t size = sizeof(rawicmp) + pkt->size;
    if(size%2)size++;
    
    //allocate buffer on heap
    uint8_t *buf = calloc(size, 1);
    uint8_t *ret = buf;
    assert(buf);

    //copy raw wire struct into buffer (header)
    memcpy(buf, &raw, sizeof(rawicmp));

    //copy payload after header
    buf = buf + sizeof(rawicmp);//buf moves forward
    memcpy(buf, pkt->data, pkt->size);

    uint16_t check = checksum(ret, size);

    rawptr = (rawicmp *)ret;
    rawptr->checksum = check;

    return ret;
}

uint8_t *evalip(ip *pkt){
    rawip rawpkt;
    rawip *rawptr;
    uint16_t check;
    uint8_t *p, *ret;
    uint8_t protocol;
    uint16_t length_le;//total packet size;
    uint16_t length_be;
    uint8_t *icmp_ptr;
    uint16_t size;

    if(!pkt) return (uint8_t *)0;

    protocol = 0;
    switch(pkt->kind){
        case L4icmp:
            protocol = 1;
            break;

        default:
            return (uint8_t *)0;
            break;
    }

    rawpkt.checksum = 0;
    rawpkt.dscp = 0;
    rawpkt.ecn = 0;

    rawpkt.dst = pkt->dst;
    rawpkt.flags = 0;
    rawpkt.id = htons(pkt->id);

/*  ihl is the IP header length in 32-bit words - dividing sizeof(rawip) 
    by 4 gives that count automatically rather than hardcoding it*/
    rawpkt.ihl = (sizeof(rawip)/4);

    length_le = 0;
    if(pkt->payload){
        
        /*Total packet size = IP header bytes + ICMP header bytes + ICMP payload bytes. 
          This value goes into the IP length field after byte-swapping with htons().*/
        
        length_le = (rawpkt.ihl * 4) + pkt->payload->size + sizeof(rawicmp);
        length_be = htons(length_le);
        rawpkt.length = length_be;
    
    } else{
        length_le = rawpkt.length = (rawpkt.ihl * 4);
    }

    rawpkt.offset = 0;
    rawpkt.protocol = protocol;
    rawpkt.src = pkt->src;
    rawpkt.ttl = 250;
    rawpkt.version = 4;

    if(length_le%2) length_le++;

    size = sizeof(rawip);
    p = (uint8_t *)malloc(length_le);
    ret = p;
    assert(p);
    memset(p, 0, length_le);
    memcpy(p, &rawpkt, size);//copy IP header
    p+=size;                //advance past IP header
    icmp_ptr = eval_icmp(pkt->payload);//serialize icmp

    if(icmp_ptr){
        memcpy(p, icmp_ptr, sizeof(rawicmp) + pkt->payload->size);//copy ICMP
        free(icmp_ptr);
    }

    check = checksum(ret, length_le);
    rawptr = (rawip *)ret;
    rawptr->checksum = check;

    return ret;
}

void show_icmp(uint8_t *id, icmp *pkt){
    if(!pkt) return;

    printf("(icmp *)%s = {\n", (char *)id);

    printf(" kind:\t %s\n size:\t %d bytes of payload\n}\npayload:\n",
        (pkt->kind == echo) ? "echo" : "echo reply",
        pkt->size);

    if(pkt->data){
        if((pkt->kind==echo) || (pkt->kind==echoreply)) {
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
        n = sizeof(rawicmp) + sizeof(rawip)+ pkt->payload->size;
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

    if (pkt->payload)
        show_icmp("payload", pkt->payload);

    return;
}

void free_ip(ip *pkt){
    free(pkt);
}

/*a convenience function that creates and configures the raw socket, 
returning the socket file descriptor. Everything that needs to happen 
once before packets can be sent or received lives here.*/
uint32_t setup(){
   uint32_t s, one;
   signed int tmp;
   struct timeval tv;

   tv.tv_sec = 2;
   tv.tv_usec = 0;

   one = (uint32_t)1;

   //1 passed to socket() is IPPROTO_ICMP as a raw number
   tmp = socket(AF_INET, SOCK_RAW, 1);
   
   if(tmp>2) s = (uint32_t)tmp;
   else s = (uint32_t)0;

/*SOL_IP means the option applies at the IP layer. 
IP_HDRINCL with value 1 tells the kernel - 
"I'm providing the complete IP header myself, don't add one." 
Without this, the OS would prepend its own IP header on top of 
the one in evalip(), producing a malformed double-header packet.*/   
   setsockopt( (int)s, SOL_IP, IP_HDRINCL, (unsigned int *)&one, sizeof(uint32_t) );

   setsockopt( (int)s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval) );

   return s;
}

bool sendip(uint32_t s, ip *pkt){
    uint8_t *raw;
    uint16_t n;
    signed int ret;
    struct sockaddr_in sock;

    if(!s || !pkt) return false;

/*  Zeroes the sockaddr_in struct before filling it in. This is important because uninitialized 
    struct fields contain garbage - the OS might misinterpret them when routing the packet.*/
    memset(&sock, 0 , sizeof(sock));

/* evalip() takes the logical ip struct - which contains a pointer to a logical icmp struct - 
   and produces a single flat byte buffer containing the complete wire-format packet: 
   IP header, then ICMP header, then ICMP payload, all contiguous. 
   raw now points to those bytes, ready to hand directly to sendto().*/    
    raw = evalip(pkt);

    n = sizeof(rawip) + sizeof(rawicmp) + pkt->payload->size;

    sock.sin_addr.s_addr = (in_addr_t)pkt->dst;

    ret = sendto( (int)s, raw, (int)n, 0 /*MSG_DONTWAIT*/, (const struct sockaddr *)&sock, sizeof(sock) );
    free(raw);

    if(ret<0)return false;
    else return true;
}

ip *recvip(uint32_t s){
    uint8_t buf[1600];
    ip *ip_pkt;
    rawip *raw_ip;
    signed int ret;
    uint16_t n;
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
    
    if(!s) return (ip *)0;

    //setting up the receive buffer
    memset(&buf, 0, 1600);
    ret = recvfrom((int)s, &buf, 1599, 0, 0, 0);

    if(ret<0)return (ip *)0;
    else n = (uint16_t)ret;

    //cast to rawip* to read IP header fields
    raw_ip = (rawip *)&buf;
    id = ntohs(raw_ip->id);

    //Extracting source and destination addresses
    memset(&src, 0 ,16);
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

    //verifying IP checksum
    if(n%2)n++;

    check_sum = checksum(buf, n);
    if(check_sum){
        fprintf(stderr, "Received packet with malformed checksum: 0x%.04hx\n", (int)raw_ip->checksum);
        return(ip *)0;
    }

    //Determining the protocol
    kind = (raw_ip->protocol == 1) ? L4icmp : unassigned;

    if(kind != L4icmp){
        fprintf(stderr, "Unsupported packet type received: 0x%.04hx\n", (int)raw_ip->protocol);
        return(ip *)0;
    }

    //Build logical ip struct with mkip()
    ip_pkt = mkip(kind, src, dst, id, 0);
    n = n - sizeof(rawip);
    if(!n){
        ip_pkt->payload = (icmp *)0;
        return ip_pkt;
    } 

    //Advancing past the IP header to find ICMP
    raw_icmp = (rawicmp *)(buf + sizeof(rawip));
    
    //Determining ICMP type
    if((raw_icmp->Type==8) && !raw_icmp->code) icmpkind = echo;
    else if(!raw_icmp->Type && !raw_icmp->code) icmpkind = echoreply;
    else icmpkind = unassigned;

    if(icmpkind == unassigned) return recvip(s);//keep receiving until you get something meaningful

    //Verifying the ICMP checksum
    icmp_checksum = checksum((uint8_t *) raw_icmp, n);
    if(icmp_checksum){
        fprintf(stderr, "ICMP checksum failed: 0x%.04hx\n", (int) raw_icmp->checksum);
        return (ip *)0;
    }
    
    //Extracting the ICMP payload and building the logical ICMP struct
    n = n-sizeof(rawicmp);
    uint8_t *payload = NULL;
    if(n > 0){
        payload = malloc(n);
        memset(payload, 0, n);
        memcpy(payload, raw_icmp->data, n);
    }

    icmp_pkt = mkicmp(icmpkind, payload, n, ntohs(raw_icmp->identifier), ntohs(raw_icmp->seq_num));

    //Attaching the payload and returning
    if(!icmp_pkt) return ip_pkt;
    else ip_pkt->payload = icmp_pkt;

    return ip_pkt;
}

int main(){
    icmp *pkt = mkicmp(echo, "hello world", strlen("hello world"), 1, 1);
    ip *packet = mkip(L4icmp, "0.0.0.0", "8.8.8.8", 1, NULL);
    packet->payload = pkt;

    uint32_t s = setup();
    sendip(s, packet);

    ip *reply = recvip(s);
    if(reply){
        showip("Received", reply);
        free_ip(reply);
    }
}