#define _DEFAULT_SOURCE
#include <stdio.h>
#include <sys/types.h> 
#include "config.h"
#include <sys/types.h>
#include<pcap.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

// These definations are for ip header parsing
#define IP_V(ip) (((ip)->ip_vhl) >> 4)
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0F)

// Thes defination is used to calculate the the header length of the tcp packet
#define TH_OFF(th) (((th)->th_offx2 & 0xF0) >> 4)

struct sniff_ethernet {
    unsigned char ether_dhost[ETHER_ADDR_LEN]; /* Destination MAC */
    unsigned char ether_shost[ETHER_ADDR_LEN]; /* Source MAC */
    unsigned short ether_type;                 /* Protocol (IPv4, ARP, etc.) for ex 0x0800 → IPv4 : 0x0806 → ARP : 0x86DD → IPv6 */ 
};

struct sniff_ip{
    unsigned char ip_vhl;  // version << 4 | header length >> 2
    unsigned char ip_tos;  // type of service
    unsigned short ip_len; // total length
    unsigned short ip_id;  // identification
    unsigned short ip_off; // fragment offset
    unsigned char ip_ttl;  // time to live
    unsigned char ip_p;    // protocol
    unsigned short ip_sum; // checksum
    struct in_addr ip_src; // source IP
    struct in_addr ip_dst; // destination IP
};

struct sniff_tcp{
    unsigned short th_sport; // source port
    unsigned short th_dport; // destination port
    unsigned int th_seq;     // sequence number
    unsigned int th_ack;     // acknowledgement number
    unsigned char th_offx2;  // data offset (upper 4 bits)
    unsigned char th_flags;  // TCP flags
    unsigned short th_win;   // window
    unsigned short th_sum;   // checksum
    unsigned short th_urp;   // urgent pointer
};

struct sniff_udp{
    unsigned short uh_sport; // source port
    unsigned short uh_dport; // destination port
    unsigned short uh_len;   // UDP length (header + data)
    unsigned short uh_sum;   // checksum
};

struct sniff_dns{
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

void print_mac(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

void decode_dns_name(const unsigned char *payload, int *offset){
    int len;

    while ((len = payload[*offset]) != 0){
        (*offset)++;

        for (int i = 0; i < len; i++){
            printf("%c", payload[*offset]);
            (*offset)++;
        }
        printf(".");
    }

    (*offset)++; // skip the null byte
}

void print_http_payload(const unsigned char *payload, int payload_len){
    for (int i = 0; i < payload_len; i++){
        if (isprint(payload[i]) || payload[i] == '\r' || payload[i] == '\n')
            putchar(payload[i]);
        else
            putchar('.');
    }
    printf("\n");
}

void buildFilter(char *filter, size_t size, const Config *cfg) {
    filter[0] = '\0';

    // Protocol filters
    if (cfg->icmp) {
        strncat(filter, "icmp or icmp6", size - strlen(filter) - 1);
    } 
    else if (cfg->tcp) {
        strncat(filter, "tcp", size - strlen(filter) - 1);
    } 
    else if (cfg->udp) {
        strncat(filter, "udp", size - strlen(filter) - 1);
    }

    // Port filter
    if (cfg->port > 0) {
        if (filter[0] != '\0')
            strncat(filter, " and ", size - strlen(filter) - 1);

        char portbuf[32];
        snprintf(portbuf, sizeof(portbuf), "port %d", cfg->port);
        strncat(filter, portbuf, size - strlen(filter) - 1);
    }

    // Source IP
    if (cfg->src_ip[0]) {
        if (filter[0] != '\0')
            strncat(filter, " and ", size - strlen(filter) - 1);

        strncat(filter, "src host ", size - strlen(filter) - 1);
        strncat(filter, cfg->src_ip, size - strlen(filter) - 1);
    }

    // Destination IP
    if (cfg->dst_ip[0]) {
        if (filter[0] != '\0')
            strncat(filter, " and ", size - strlen(filter) - 1);

        strncat(filter, "dst host ", size - strlen(filter) - 1);
        strncat(filter, cfg->dst_ip, size - strlen(filter) - 1);
    }
}


void got_packet(unsigned char *args,const struct pcap_pkthdr *header,const unsigned char *packet){
    const struct sniff_ethernet *ethernet;

    ethernet = (struct sniff_ethernet *)packet;

    // Print the info about the ethernet header
    printf("\n....Ethernet Header....\n");

    printf("Source Mac : ");
    print_mac(ethernet->ether_shost);
    printf("\n");

    printf("Destination Mac : ");
    print_mac(ethernet->ether_dhost);
    printf("\n");

    unsigned short type = ntohs(ethernet->ether_type);

    printf("Ethernet type : 0x%04x",type);

    if (type == 0x0800)
        printf(" (IPv4)");
    else if (type == 0x0806)
        printf(" (ARP)");
    else if (type == 0x86DD)
        printf(" (IPv6)");
    else
        printf(" (Unknown)");

    printf("\n");

    printf("Captured Length : %d bytes\n", header->caplen);

    // Now information related to ip headers
    const struct sniff_ip *ip;
    unsigned int size_ip;

    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    if (size_ip < 20) {
        printf("Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    printf("...IP Header...\n");

    printf("Version: %d\n",IP_V(ip));
    printf("Header Length: %d\n",size_ip);
    printf("TTL: %d\n",ip->ip_ttl);

    printf("Protocol: ");
    switch (ip->ip_p) {
        case 1:  printf("ICMP\n"); break;
        case 6:  printf("TCP\n");  break;
        case 17: printf("UDP\n");  break;
        default: printf("Other (%d)\n", ip->ip_p);
    }

    printf("Source IP      : %s\n", inet_ntoa(ip->ip_src));
    printf("Destination IP : %s\n", inet_ntoa(ip->ip_dst));

    switch (ip->ip_p){
        case 6:
            // If it is a tcp packet
            const struct sniff_tcp *tcp;
            unsigned int size_tcp;

            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp) * 4;

            if(size_tcp < 20){
                printf("Invalid tcp header length\n");
            }

            printf("...TCP Header...\n");
            printf("Source Port: %u\n",ntohs(tcp->th_sport));
            printf("Destination Port: %u\n",ntohs(tcp->th_dport));
            printf("Sequence number: %u\n",ntohl(tcp->th_seq));
            printf("Acknowledgement number: %u\n",ntohl(tcp->th_ack));
            printf("Header length: %u\n",size_tcp);

            printf("Flags: ");
            if (tcp->th_flags & 0x02) printf("SYN ");
            if (tcp->th_flags & 0x10) printf("ACK ");
            if (tcp->th_flags & 0x01) printf("FIN ");
            if (tcp->th_flags & 0x04) printf("RST ");
            if (tcp->th_flags & 0x08) printf("PSH ");
            if (tcp->th_flags & 0x20) printf("URG ");
            printf("\n");

            const unsigned char *payload;
            payload = packet + SIZE_ETHERNET + size_ip + size_tcp;

            int payload_len = header->caplen - (SIZE_ETHERNET + size_ip + size_tcp);
            if (payload_len > 0) {
                printf("Payload Length   : %d bytes\n", payload_len);
            }else{
                printf("Invalid payload \n");
            }

            break;

        case 17:
            // If it is a udp packet
            const struct sniff_udp *udp;
            udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);

            printf("...UDP Header...\n");
            printf("Source Port : %u\n",ntohs(udp->uh_sport));
            printf("Destination Port : %u\n",ntohs(udp->uh_dport));
            printf("Length : %u\n",ntohs(udp->uh_len));

            // If it is a dns packet then decoding the dns header
            if(ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53){
                struct sniff_dns *dns =
                    (struct sniff_dns *)(packet +
                                        SIZE_ETHERNET +
                                        size_ip +
                                        sizeof(struct sniff_udp));

                if (header->caplen <
                    SIZE_ETHERNET + size_ip +
                    sizeof(struct sniff_udp) +
                    sizeof(struct sniff_dns)) {
                    return;
                }

                unsigned short flags = ntohs(dns->flags);

                int is_response = flags & 0x8000; // 1 = response, 0 = query
                if (is_response)
                    printf("DNS Response\n");
                else
                    printf("DNS Query\n");

                const unsigned char *dns_payload = packet + SIZE_ETHERNET + size_ip + sizeof(struct sniff_udp) + sizeof(struct sniff_dns);

                int offset = 0;

                printf("Domain Name: ");
                decode_dns_name(dns_payload, &offset);
                printf("\n");

                // Decoding dns payload it it contans 
                const unsigned char *payload = packet + SIZE_ETHERNET + size_ip + sizeof(struct sniff_udp);

                int payload_len = ntohs(udp->uh_len) - sizeof(struct sniff_udp);

                if (payload_len > 0) {
                    printf("UDP Payload Length : %d bytes\n", payload_len);
                } else {
                    printf("No UDP payload\n");
                }

            }else{
                int payload_len = ntohs(udp->uh_len) - sizeof(struct sniff_udp);

                if (payload_len > 0) {
                    printf("UDP Payload Length : %d bytes\n", payload_len);
                } else {
                    printf("No UDP payload\n");
                }
            }

            break;
            
        default:
            printf("not a tcp or udp packet\n");
    }
}

int startCapture(Config *cfg){
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;

    if(pcap_findalldevs(&alldevs,errbuf) == -1){
        fprintf(stderr,"Error in finding network device: %s",errbuf);
        return 1;
    }

    printf("Available devices: \n");
    for(d = alldevs;d != NULL;d = d->next){
        printf("%d. %s",++i,d->name);
        if(d->description){
            printf(" (%s)",d->description);
        }
        printf("\n");
    }

    printf("Enter you choice: ");
    int choice;
    scanf("%d", &choice);
    i = 0;
    d = alldevs;

    char *dev;
    while(d != NULL){
        if(++i == choice)
            break;
        d = d->next;
    }

    dev = d->name;
    printf("Your choice is %s\n",dev);

    pcap_t *handle;

    // Creating a session
    handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle == NULL){
        fprintf(stderr,"Error opening network device %s : %s \n",dev,errbuf);
        return 1;
    }

    printf("Opened %s successfully \n",dev);

    if(pcap_datalink(handle) != DLT_EN10MB){
        fprintf(stderr,"Device:%s doesn't support ethernet headers",dev);
        pcap_close(handle);
        return 2;
    }

    // Getting ip and subnet mask
    bpf_u_int32 mask;
    bpf_u_int32 net;
    if(pcap_lookupnet(dev,&net,&mask,errbuf) == -1){
        fprintf(stderr,"Error finding ip and subnetmask of the %s network device\n",dev);
        net = 0;
        mask = 0;
    }

    char filter_exp[256];
    buildFilter(filter_exp, sizeof(filter_exp), cfg);

    if (filter_exp[0] != '\0') {
        struct bpf_program fp;

        if (pcap_compile(handle, &fp, filter_exp, 1, mask) == -1) {
            fprintf(stderr, "Invalid filter '%s': %s\n",
                    filter_exp, pcap_geterr(handle));
            return 2;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Failed to apply filter '%s': %s\n",
                    filter_exp, pcap_geterr(handle));
            return 2;
        }

        pcap_freecode(&fp);
    }
    
    // Grabbing a packet
    struct pcap_pkthdr header; // The header that pcap gives us
    const unsigned char *packet; // the actual packet

    pcap_loop(handle,cfg->packet_limit,got_packet,NULL);

    pcap_close(handle);

    return 0;
}