#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

/*takes everything needed to describe an IP packet in convenient form — the protocol kind, 
source address, destination address, and an identifier — and produces a heap-allocated ip 
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

/*  ihl is the IP header length in 32-bit words — dividing sizeof(rawip) by 4 
    gives you that count automatically rather than hardcoding it*/
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

int main(){
    icmp *pkt = mkicmp(echo, "hello world", strlen("hello world"), 1, 1);
    ip *packet = mkip(L4icmp, "0.0.0.0", "8.8.8.8", 1, NULL);
    packet->payload = pkt;
    showip("ip packet", packet);
    free_icmp(pkt);
    free_ip(packet);
}