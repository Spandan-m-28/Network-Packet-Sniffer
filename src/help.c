#include<stdio.h>
#include "help.h"
#include "center.h"

void printHelp(){
    printCentered("Network Packet Sniffer Guide");
    printCentered("Welcome to the network packet sniffer which will help you sniff packets on your selected network device");

    printf("Usage:\n");
    printf("    sudo ./sniffer [options]\n\n");

    printf("Note: Make sure you run it with sudo to capture packets\n\n");

    printf(
        "Options:\n"
        "   --help              This will open up the guide\n"
        "   --tcp               Captures only TCP packets\n"
        "   --udp               Captures only UDP packets\n"
        "   --icmp              Captures only ICMP packets\n"
        "   --port <number>     Filters packets by port number\n"
        "   --src_ip <ip>       Filters packets by given source IP\n"
        "   --dst_ip <ip>       Filters packets by given destination IP\n"
        "   --stats             Displays traffic statistics\n"
        "   --count <number>    Stops capturing packets after n packets\n\n"

        "Note: If no arguments are passed all the packets will be captured\n\n"

        "Example:\n"
        "   sudo ./sniffer --udp"
        "   sudo ./sniffer --tcp --port 8080\n"

        "\n Made by Spandan\n"
    );
}