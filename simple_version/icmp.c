#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>


//__attribute ((packed)) tells the compiler - don't add any padding,
//pack every field as tightly as possible, exactly as declared:


typedef struct __attribute__((packed)) packet{//as per icmp spec
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t seq_num;
    uint8_t data[56];
} packet;


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


int main(){
    packet Packet = {0};


    Packet.type = 8;
    Packet.code = 0;
    Packet.identifier = htons(1);


    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);



    if(sockfd<0){
        perror("socket");
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = 1;//1 second
    tv.tv_usec = 0;//0 microseconds

    //configure the sockets(set timeout)
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr("8.8.8.8");

    uint16_t seq = 1;

    while(1){//outer loop- 1 ping per second

//build packet, send, record start time
        Packet.checksum = 0;//reset checksum to 0
        Packet.seq_num = htons(seq);

        Packet.checksum = checksum((uint8_t *)&Packet, sizeof(Packet));

        struct timespec start;
        clock_gettime(CLOCK_MONOTONIC, &start); 


        int sent = sendto(sockfd, &Packet, sizeof(Packet), 0,
            (struct sockaddr *)&dest, sizeof(dest));


        if(sent < 0){
            perror("sendto");
            return 1;
        }


        uint8_t buffer[128];
    
        struct sockaddr_in sender;
    
        socklen_t sender_len = sizeof(sender);


        while(1){
            int received = recvfrom(sockfd, buffer, 128, 0,
                                (struct sockaddr *)&sender, &sender_len);
            if(received < 0){
                    if(errno==EAGAIN){
                        printf("Request timeout for icmp_seq=%d\n", seq);
                        break;  // break inner loop, continue outer loop
                    } else {
                        perror("recvfrom");
                        return 1;
                    }
                }

                //To get just the bottom 4 bits we mask with 0x0F which is 00001111
                uint8_t ihl = buffer[0] & 0x0F;

                //ihl is measured in 32-bit words (4 bytes each)
                int ip_header_length = ihl * 4;

                //Once we have ip_header_length, the ICMP data starts at exactly that offset into the buffer
                uint8_t *icmp = buffer + ip_header_length;


                printf("got type: %d from: %s\n", icmp[0], inet_ntoa(sender.sin_addr));


                if(icmp[0] == 0){
                    struct timespec end;
                    clock_gettime(CLOCK_MONOTONIC, &end);

                    double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                                (end.tv_nsec - start.tv_nsec) / 1000000.0;
                    printf("RTT: %.3f ms\n", rtt);
                    printf("ICMP reply received!\n");
                    printf("from: %s\n", inet_ntoa(sender.sin_addr));
                    break;
                }
        }
        
        seq++;
        sleep(1);
    }
        
}