#ifndef CONFIG_H
#define CONFIG_H

#define IP_LEN 16

typedef struct{
    int noArg;
    
    int tcp;
    int udp;
    int icmp;

    int stats;

    int port;
    char src_ip[IP_LEN];
    char dst_ip[IP_LEN];

    int packet_limit;
}Config;

void initConfig(Config *cfg);

#endif