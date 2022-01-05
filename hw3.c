#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdlib.h>

typedef struct pcap_pkthdr pcap_pkthdr;
typedef struct ether_header ether_header;
typedef struct tcphdr tcphdr;
typedef struct udphdr udphdr;
typedef struct ip ip;

int main(int argc, char **argv)
{
    if(argc==2)
    {
        char *filename;
        filename=strdup(argv[argc-1]);

        char errbuff[PCAP_ERRBUF_SIZE]= "\0";
        pcap_t *handler= pcap_open_offline(filename, errbuff);
        if (NULL==handler)
        {
            printf("%s can't be open\n", filename);
            exit(1);
        }

        int packet_cnt=0;
        while(1)
        {
            pcap_pkthdr *packet_header;
            ether_header *eth_header;
            tcphdr *tcp_header;
            udphdr *udp_header;
            time_t time_t_tmp;

            u_char *packet;
            int res=pcap_next_ex(handler, &packet_header, (const u_char **)&packet);
            if(res==0) continue;
            else if(res==-2) break;
            else if(res==-1)
            {
                printf("pcap_next_ex ERROR\n");
                exit(1);
            }

            printf("\n*************** Packet : %d ***************\n", ++packet_cnt);
            printf("\n");

            // 1. 那個封包擷取的時間戳記
            time_t_tmp= packet_header->ts.tv_sec;
            struct tm ts= *localtime(&time_t_tmp);
            char str_time[50];
            strftime(str_time, sizeof(str_time),"%a %Y-%m-%d %H:%M:%S", &ts);
            printf("Time : %s\n", str_time);
            printf("\n");

            // 2. 來源MAC位址、目的MAC位址、Ethernet type欄位
            printf("MAC Sourse address      : ");           // sourse address: byte 6~11
            for(int i=6; i<12; i++)
            {
                printf("%02x", packet[i]);
                if(i==11) printf("\n");
                else printf(":");
            }
            printf("MAC Destination address : ");           // destination address: byte 0~5
            for(int i=0; i<6; i++)
            {
                printf("%02x", packet[i]);
                if(i==5) printf("\n");
                else printf(":");
            }
            printf("Ethernet type           : ");           // type: byte 12, 13
            printf("%02x%02x\n",packet[12],packet[13]);
            printf("\n");

            eth_header = (ether_header *)packet;
            unsigned short type = ntohs(eth_header->ether_type); //ntohs()將16位網路字符順序轉換為主機字符順序
            ip *ip_header = (ip *)(packet + ETHER_HDR_LEN);
        
            // 3. 如果那個封包是IP封包，則再多顯示來源IP位址與目的地IP位址
            if(type==ETHERTYPE_IP)
            {
                // IP (0800)
                char ip_src_add[INET_ADDRSTRLEN], ip_dst_add[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ip_header->ip_src), ip_src_add, sizeof(ip_src_add)); // inet_ntop的用法
                inet_ntop(AF_INET, &(ip_header->ip_dst), ip_dst_add, sizeof(ip_dst_add)); // https://www.itread01.com/content/1547156002.html
                printf("IP Sourse address      : %s \n", ip_src_add);
                printf("IP Destination address : %s \n", ip_dst_add);
                printf("\n");

                // 4. 如果那個封包是TCP或UDP封包，則再多顯示來源port號碼與目的port號碼
                // UDP
                if(ip_header->ip_p==IPPROTO_UDP)
                {
                    udp_header = (udphdr*)(packet+ ETHER_HDR_LEN+ ip_header->ip_hl *4);
                    printf("Protocol         : UDP\n"); 
                    printf("Sourse Port      : %d\n", ntohs(udp_header->uh_sport));
                    printf("Destination Port : %d\n", ntohs(udp_header->uh_dport));
                    printf("\n");
                }
                // TCP
                else if(ip_header->ip_p==IPPROTO_TCP)
                {
                    tcp_header = (tcphdr*)(packet+ ETHER_HDR_LEN+ ip_header->ip_hl *4);
                    printf("Protocol         : TCP\n");       
                    printf("Sourse Port      : %d\n", ntohs(tcp_header->th_sport));
                    printf("Destination Port : %d\n", ntohs(tcp_header->th_dport));
                    printf("\n");
                }
            }
        }
    }
    return 0;
}