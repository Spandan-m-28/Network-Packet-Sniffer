#ifndef STATS_H
#define STATS_H

typedef struct {
    unsigned long long totalPackets;
    unsigned long long tcpPackets;
    unsigned long long udpPackets;
    unsigned long long icmpPackets;
    unsigned long long otherPackets;
} Stats;

void initializeStats(Stats *st);

void printStats(Stats *st);

#endif
