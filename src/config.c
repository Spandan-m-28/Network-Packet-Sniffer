#include "config.h"
#include<string.h>

void initConfig(Config *cfg){
    
    cfg->tcp = 0;
    cfg->udp = 0;
    cfg->icmp = 0;

    cfg->stats = 0;

    cfg->port = -1;
    cfg->src_ip[0] = '\0';
    cfg->dst_ip[0] = '\0';

    cfg->packet_limit = -1;
}