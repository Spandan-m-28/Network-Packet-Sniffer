#include "stats.h"
#include <stdio.h>

void initializeStats(Stats *st) {
    st->totalPackets = 0;
    st->tcpPackets   = 0;
    st->udpPackets   = 0;
    st->icmpPackets  = 0;
    st->otherPackets = 0;
}

void printStats(Stats *st){
    printf("Total Packets Captured: %llu\n",st->totalPackets);
    printf("TCP Packets Captured:   %llu\n",st->tcpPackets);
    printf("UDP Packets Captured:   %llu\n",st->udpPackets);
    printf("ICMP Packets Captured:  %llu\n",st->icmpPackets);
    printf("Other Packets Captured: %llu\n",st->otherPackets);
}
