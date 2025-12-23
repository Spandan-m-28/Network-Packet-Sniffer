#include <stdio.h>
#include "cli.h"
#include <string.h>
#include <stdlib.h>
#include "help.h"

int parseArguments(int argc,char *argv[],Config *cfg){
    if(argc == 1){
        cfg->noArg = 1;
        return 1;
    }
    for(int i = 1;i < argc;i++){
        if(strcmp(argv[i],"--help") == 0){
            printHelp();
            return 0;
        }else if(strcmp(argv[i],"--tcp") == 0){
            cfg->tcp = 1;
        }else if(strcmp(argv[i],"--udp") == 0){
            cfg->udp = 1;
        }else if(strcmp(argv[i],"--icmp") == 0){
            cfg->icmp = 1;
        }else if(strcmp(argv[i],"--stats") == 0){
            cfg->stats = 1;
        }else if(strcmp(argv[i],"--port") == 0 && i + 1 < argc){
            cfg->port = atoi(argv[++i]);
        }else if(strcmp(argv[i],"--src_ip") == 0 && i + 1 < argc){
            strcpy(cfg->src_ip,argv[++i]);
        }else if(strcmp(argv[i],"--dst_ip") == 0 && i + 1 < argc){
            strcpy(cfg->dst_ip,argv[++i]);
        }else if(strcmp(argv[i],"--count") == 0 && i + 1 < argc){
            cfg->packet_limit = atoi(argv[++i]);
        }else {
            printf("Invalid Option, Please check --help for more options\n");
            return -1;
        }
    }
    return 1;
}