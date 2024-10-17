#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h> // Changed `linux` to `netinet` for extended compatibility (macOS + Linux with Docker)

// switching to unsigned int so cpu doesn't have to sign extend = better performance hopefully
static uint32_t occurrences[256] = {0}; // 

/**
 * Packet handler function.
 * Function call overhead reduced when comipled with -O3
 */
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const u_char *ip_header = packet + sizeof(struct ether_header);
    // uncomment section below for validation
    // uint8_t ip_header_length = (ip_header[0] & 0x0F) * 4;
    // if (ip_header_length < 20) return;
    const u_char *dest_ip = ip_header + 16;
    occurrences[dest_ip[3]]++;
}

/**
 * Hard to follow, but fastest runtime implementation I could get.
 */
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    // pcap_open_offline opens a pcap file for reading
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }
    // pcap_loop will call handle_packet function for each packet
    pcap_loop(handle, 0, handle_packet, NULL);

    for (int i = 0; i < 256; i++) {
        if (occurrences[i] > 0) {
            printf("Last octet %d: %u\n", i, occurrences[i]);
        }
    }

    pcap_close(handle);
    return 0;
}
