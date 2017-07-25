#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

    struct ether_header{
        u_char dst[6];
        u_char src[6];
        u_char type[2];
    };

    struct sniff_ip {
    #define IP_RF 0x8000
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff
        struct in_addr ip_src,ip_dst; //source and dest address
    };

    struct tcp_header{
        u_short tcp_src;
        u_short tcp_dst;
    };


int main(int argc, char *argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr header;
    int idx = 0;
    char filter_exp[] = "port 80";		// filter
    struct bpf_program fp;			//filter
    bpf_u_int32 mask;			//sub mask
    bpf_u_int32 net;			//ip

    struct ether_header ether;
    struct sniff_ip *ip;
    struct tcp_header *tcp;

    u_char *data;

    dev = pcap_lookupdev(errbuf);
    //dev = "dum0";

    if(dev == NULL){
        printf("Can't search device\n");
        return 0;
    }
    printf("device : %s\n",dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        printf("Can't open device\n");
        return 0;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s not support\n", dev);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Can't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Can't filtering %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    while(1){
    packet = pcap_next(handle,&header);
    printf("****************************************\n");
    for(int i=0;i<header.len;i++){
        if(i<6){
            if(idx == 0)
                printf("dst mac : ");
            printf("%02x",*packet);
            ether.dst[idx++] = *packet++;
            if(idx != 6) printf("::");
            if(idx == 6) {
                idx = 0;
                printf("\n");
            }
        }
        else if(i<12){
            if(idx == 0)
                printf("src mac : ");
            printf("%02x",*packet);
            ether.src[idx++] = *packet++;
            if(idx != 6) printf("::");
            if(idx == 6){
                idx = 0;
                printf("\n");
            }
        }
        else if(i<14){
            ether.type[idx++] = *packet++;
            if(idx == 2){
                idx = 0;
                printf("\n");
            }
        }
        else if(i<34){
            ip = (struct sniff_ip*)(packet);
            printf("src ip : %s\n",inet_ntoa(ip->ip_src));
            printf("dst ip : %s\n",inet_ntoa(ip->ip_dst));
            i = 34;
            packet += 20;
            printf("\n");
        }
        else if(i<54){
            tcp = (struct tcp_header*)(packet);
            printf("tcp src port : %d\n",ntohs(tcp->tcp_src));
            printf("tcp dst port : %d\n",ntohs(tcp->tcp_dst));
            i = 54;
        }
        else if(i >= 54){
            data = (u_char *)(packet+20);
            printf("\nData area\n");
            printf("%s\n",data);
            break;
        }
    }
    }


    return 0;
}

