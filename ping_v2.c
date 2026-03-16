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
    echoreply
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

int main(){
    icmp *pkt = mkicmp(echo, "hello world", strlen("hello world"), 1, 1);
    show_icmp("pkt", pkt);
    free_icmp(pkt);
}