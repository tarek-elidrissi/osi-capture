/*
 * Full-Packet Sniffer for Linux
 *
 * Captures raw Ethernet frames using a raw socket.
 * Decodes multiple OSI layers:
 *   - Layer 2: Ethernet (Data Link)
 *   - Layer 3: IPv4 (Network)
 *   - Layer 4: TCP, UDP, ICMP (Transport)
 *
 * NOTE:
 *  - Must be run as root (SOCK_RAW requires privileges)
 *  - Tested on Linux only
 */

#include <stdio.h>              // printf, fprintf, perror
#include <stdlib.h>             // exit, malloc, free
#include <string.h>             // memset, memcpy
#include <unistd.h>             // close()
#include <arpa/inet.h>          // htons, ntohs, inet_ntoa
#include <netinet/ip.h>         // struct iphdr for IPv4 headers
#include <netinet/tcp.h>        // struct tcphdr for TCP headers
#include <netinet/udp.h>        // struct udphdr for UDP headers
#include <netinet/ip_icmp.h>    // struct icmphdr for ICMP
#include <net/ethernet.h>       // struct ethhdr for Ethernet headers
#include <netpacket/packet.h>   // sockaddr_ll for raw sockets
#include <net/if.h>             // if_nametoindex() converts "eth0" → index
#include <sys/socket.h>         // socket(), bind(), recvfrom()

#define MAX_PAYLOAD 64          // Limit printed payload size for clarity

// =====================================================================
//  Utility Functions
// =====================================================================

/*
 * Print a MAC address in standard readable format (e.g. 00:1A:2B:3C:4D:5E)
 * 'mac' is an array of 6 unsigned bytes.
 */
void print_mac(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * Print the first N bytes of packet payload.
 * Non-printable bytes are shown as '.'
 */
void print_payload(const unsigned char *data, int size) {
    printf("│ Payload (first %d bytes): ", size);
    for (int i = 0; i < size; i++) {
        unsigned char c = data[i];
        // Printable ASCII range: 32–126
        printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }
    printf("\n");
}

// =====================================================================
//  Layer 4: TCP / UDP / ICMP
// =====================================================================

/*
 * Decodes the Transport Layer depending on the protocol value from IP header.
 * protocol == 6 → TCP
 * protocol == 17 → UDP
 * protocol == 1 → ICMP
 */
void decode_tcp_udp(const unsigned char *data, int protocol, int size) {
    if (protocol == IPPROTO_TCP) {
        // Cast the payload pointer to a TCP header structure
        struct tcphdr *tcp = (struct tcphdr*)data;

        printf("┌─── Transport: TCP ───\n");
        printf("│ Src Port: %u\n", ntohs(tcp->source)); // convert from network byte order
        printf("│ Dst Port: %u\n", ntohs(tcp->dest));
        printf("│ Seq #: %u\n", ntohl(tcp->seq));        // sequence number
        printf("│ Ack #: %u\n", ntohl(tcp->ack_seq));    // acknowledgment number
        printf("│ Data Offset: %d bytes\n", tcp->doff * 4); // header length in 32-bit words

        // Print which TCP flags are set
        printf("│ Flags: ");
        if (tcp->urg) printf("URG ");
        if (tcp->ack) printf("ACK ");
        if (tcp->psh) printf("PSH ");
        if (tcp->rst) printf("RST ");
        if (tcp->syn) printf("SYN ");
        if (tcp->fin) printf("FIN ");
        printf("\n│ Window: %u\n", ntohs(tcp->window));
        printf("│ Checksum: 0x%x\n", ntohs(tcp->check));
        printf("│ Urgent Ptr: %u\n", ntohs(tcp->urg_ptr));
    }
    else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr*)data;

        printf("┌─── Transport: UDP ───\n");
        printf("│ Src Port: %u\n", ntohs(udp->source));
        printf("│ Dst Port: %u\n", ntohs(udp->dest));
        printf("│ Length: %u\n", ntohs(udp->len));
        printf("│ Checksum: 0x%x\n", ntohs(udp->check));
    }
    else if (protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr*)data;

        printf("┌─── Transport: ICMP ───\n");
        printf("│ Type: %d\n", icmp->type);
        printf("│ Code: %d\n", icmp->code);
        printf("│ Checksum: 0x%x\n", ntohs(icmp->checksum));
    }
    else {
        printf("┌─── Transport: Unknown Protocol (%d) ───\n", protocol);
    }
}

// =====================================================================
//  Layer 3: IPv4
// =====================================================================

/*
 * Decode an IPv4 packet. Handles nested IP-in-IP.
 * 'data' points to start of IP header inside Ethernet frame.
 */
void decode_ip(const unsigned char *data, int size) {
    if (size < sizeof(struct iphdr)) return; // safety check

    struct iphdr *ip = (struct iphdr*)data;  // cast to IP header
    struct sockaddr_in src, dest;            // used for printable IPs
    src.sin_addr.s_addr = ip->saddr;
    dest.sin_addr.s_addr = ip->daddr;

    printf("┌─── Network: IPv4 ───\n");
    printf("│ Version: %d\n", ip->version);                 // IPv4 = 4
    printf("│ Header Length: %d bytes\n", ip->ihl * 4);     // IHL field × 4
    printf("│ Type of Service: %d\n", ip->tos);
    printf("│ Total Length: %d\n", ntohs(ip->tot_len));     // full IP packet size
    printf("│ Identification: %d\n", ntohs(ip->id));        // packet ID
    printf("│ Flags+FragOffset: %d\n", ntohs(ip->frag_off));// fragmentation bits
    printf("│ TTL: %d\n", ip->ttl);                         // Time To Live
    printf("│ Protocol: %d\n", ip->protocol);               // 6=TCP,17=UDP,1=ICMP
    printf("│ Header Checksum: 0x%x\n", ntohs(ip->check));
    printf("│ Src IP: %s\n", inet_ntoa(src.sin_addr));
    printf("│ Dst IP: %s\n", inet_ntoa(dest.sin_addr));

    // Calculate start of the next layer (after IP header)
    int ip_header_len = ip->ihl * 4;
    const unsigned char *payload = data + ip_header_len;
    int payload_size = size - ip_header_len;

    // Handle IP-in-IP (protocol 4)
    if (ip->protocol == IPPROTO_IPIP) {
        printf("│ Encapsulated IP detected → Decoding inner packet:\n");
        decode_ip(payload, payload_size);
    } 
    else {
        decode_tcp_udp(payload, ip->protocol, payload_size);

        // Limit printed payload
        int show = (payload_size < MAX_PAYLOAD) ? payload_size : MAX_PAYLOAD;
        print_payload(payload, show);
    }
}

// =====================================================================
//  Layer 2: Ethernet
// =====================================================================

/*
 * Decode the Ethernet header at the Data Link layer.
 * Every Ethernet frame has:
 *   - 6 bytes destination MAC
 *   - 6 bytes source MAC
 *   - 2 bytes EtherType (defines next protocol)
 */
void decode_ethernet(const unsigned char *buffer, int size) {
    if (size < sizeof(struct ethhdr)) return;

    struct ethhdr *eth = (struct ethhdr*)buffer; // map bytes to Ethernet header

    printf("\n══════════════════════════════════════════════════════════════════\n");
    printf("┌─── Data Link: Ethernet ───\n");
    printf("│ Frame size: %d bytes\n", size);
    printf("│ Dst MAC: "); print_mac(eth->h_dest); printf("\n");
    printf("│ Src MAC: "); print_mac(eth->h_source); printf("\n");
    printf("│ EtherType: 0x%04x\n", ntohs(eth->h_proto)); // protocol field

    // Move pointer past Ethernet header
    const unsigned char *payload = buffer + sizeof(struct ethhdr);
    int payload_size = size - sizeof(struct ethhdr);

    // Dispatch based on EtherType
    switch (ntohs(eth->h_proto)) {
        case ETH_P_IP:      // 0x0800: IPv4
            decode_ip(payload, payload_size);
            break;
        case ETH_P_ARP:     // 0x0806: ARP
            printf("┌─── Network: ARP ───\n");
            printf("│ ARP packet detected\n");
            break;
        case ETH_P_IPV6:    // 0x86DD: IPv6
            printf("┌─── Network: IPv6 ───\n");
            printf("│ IPv6 packet detected (not decoded)\n");
            break;
        case 0x8100:        // VLAN tag
            printf("┌─── VLAN (802.1Q) ───\n");
            printf("│ VLAN tagged frame detected\n");
            break;
        default:
            printf("┌─── Unknown EtherType 0x%04x ───\n", ntohs(eth->h_proto));
            break;
    }
}

// =====================================================================
//  MAIN PROGRAM
// =====================================================================

int main(int argc, char *argv[]) {
    // Require interface name as command-line argument
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];   // store interface name (e.g. "eth0")
    unsigned char buffer[65536];   // 64KB buffer for entire Ethernet frame
    int sockfd;

    /*
     * Create a raw socket:
     *  AF_PACKET  = link-layer socket (captures entire Ethernet frame)
     *  SOCK_RAW   = receive raw packets (not filtered by kernel)
     *  ETH_P_ALL  = capture all Ethernet protocols
     */
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed (requires root privileges)");
        return 1;
    }

    /*
     * Prepare sockaddr_ll structure for binding to a specific interface
     */
    struct sockaddr_ll sll = {0};           // zero out memory
    sll.sll_family = AF_PACKET;             // address family for raw packets
    sll.sll_protocol = htons(ETH_P_ALL);    // receive all Ethernet protocols
    sll.sll_ifindex = if_nametoindex(iface);// convert interface name → index

    if (sll.sll_ifindex == 0) {
        perror("Invalid interface name");
        close(sockfd);
        return 1;
    }

    // Bind the raw socket to that specific interface
    if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return 1;
    }

    printf("=== OSI Capture Started ===\n");
    printf("Listening on interface: %s\n", iface);

    /*
     * Main capture loop:
     * recvfrom() reads one complete Ethernet frame into buffer[]
     * data_size = number of bytes captured
     */
    while (1) {
        int data_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) {
            perror("Ethernet frame reading failed");
            break;
        }

        // Decode the captured frame starting from Layer 2
        decode_ethernet(buffer, data_size);
    }

    // Cleanup when loop exits
    close(sockfd);
    return 0;
}
