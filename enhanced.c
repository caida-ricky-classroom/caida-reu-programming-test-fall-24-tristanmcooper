#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h> // Changed `linux` to `netinet` for extended compatibility (macOS + Linux with Docker)

/**
 * Enhanced version of the original pcap parser that counts the occurrences of 
 * the last octet of the destination IP address.
*/
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header; // Changed `iphdr` to `ip` to reflect import change

    // IPv4 octets are 8 bits, so there are 256 possible values for the last octet (2^8)
    int occurrences[256] = {0}; 

    // Ensure a pcap file is provided
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    // Open pcap file
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Loop through packets in pcap file
    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Get IP header from packet
        ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        // Convert address from NBO to HBO
        unsigned long dest_ip = ntohl(ip_header->ip_dst.s_addr);  

        // Get LSB of address with bitwise AND
        int last_octet = dest_ip & 0xFF;

        // Increment index storing count of occurrences of last octet
        occurrences[last_octet]++;
    }

    // Print occurrences
    for (int i = 0; i < 256; i++) {
        if (occurrences[i] > 0) {
            printf("Last octet %d: %d\n", i, occurrences[i]);
        }
    }

    // Close pcap file
    pcap_close(handle);
    return 0;
}