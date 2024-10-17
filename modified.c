#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h> // Changed `linux` to `netinet` for extended compatibility (macOS + Linux with Docker)

/**
 * This program reads a pcap file and prints the IP destination address of each packet.
*/
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header; // Changed `iphdr` to `ip` to reflect import change
    int packet_count = 0;
    
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {

        // Changed `ethhdr` to `ether_header` for compatibility, despite downward migration
        ip_header = (struct ip*)(packet + sizeof(struct ether_header)); 

        // Changed `daddr` to `ip_dst` to match `ip` struct
        // Removed unnecessary casting `*((struct in_addr*)`
        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(ip_header->ip_dst)); 
    }

    pcap_close(handle);
    return 0;
}
