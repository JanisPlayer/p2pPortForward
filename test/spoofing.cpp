#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <cstdlib>

// Pseudoheader für die Berechnung der Prüfziffer
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

// UDP-Header
struct udphdr_udp {
    u_int16_t source_port;
    u_int16_t dest_port;
    u_int16_t udp_length;
    u_int16_t udp_checksum;
};

// IP-Header
struct iphdr_ip {
    u_int8_t ip_hl:4, ip_v:4;
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_protocol;
    u_int16_t ip_checksum;
    u_int32_t ip_src;
    u_int32_t ip_dst;
};

unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    
    if (len == 1)
        sum += *(unsigned char *)buf;
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    
    return result;
}

int main(int argc, char *argv[]) {
    // Ausgabe aller übergebenen Argumente
    std::cout << "Übergebene Argumente:" << std::endl;
    for (int i = 0; i < argc; ++i) {
        std::cout << "Argument " << i << ": " << argv[i] << std::endl;
    }

    if (argc != 6) {
        std::cerr << "Benutzung: " << argv[0] << " <Quell-IP> <Quell-Port> <Ziel-IP> <Ziel-Port> <Paketinhalt>" << std::endl;
        return 1;
    }

    // Kommandozeilenargumente auslesen
    const char* source_ip = argv[1];
    int source_port = std::atoi(argv[2]);
    const char* target_ip = argv[3];
    int target_port = std::atoi(argv[4]);
    const char* data = argv[5];
    int data_len = strlen(data);

    // Erstellen eines rohen Sockets
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Fehler beim Erstellen des Sockets!" << std::endl;
        return 1;
    }

    // Setze das IP_HDRINCL-Flag
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cerr << "Fehler beim Setzen von IP_HDRINCL!" << std::endl;
        return 1;
    }

    // Die IP-Adresse des Zielhosts
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    dest.sin_addr.s_addr = inet_addr(target_ip);

    // Speicher für das gesamte Paket (IP-Header + UDP-Header + Daten)
    char packet[4096];
    memset(packet, 0, 4096);
    struct iphdr_ip *iph = (struct iphdr_ip *)packet;
    struct udphdr_udp *udph = (struct udphdr_udp *)(packet + sizeof(struct iphdr_ip));
    char *payload = packet + sizeof(struct iphdr_ip) + sizeof(struct udphdr_udp);

    // Kopiere die Nutzdaten ins Paket
    memcpy(payload, data, data_len);

    struct pseudo_header psh;

    // Fülle den IP-Header
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct iphdr_ip) + sizeof(struct udphdr_udp) + data_len);
    iph->ip_id = htonl(54321);  // Eine beliebige ID
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_protocol = IPPROTO_UDP;
    iph->ip_checksum = 0;  // Wird später berechnet
    iph->ip_src = inet_addr(source_ip);  // Quell-IP (Spoofed)
    iph->ip_dst = inet_addr(target_ip);  // Ziel-IP

    iph->ip_checksum = checksum((unsigned short *)packet, sizeof(struct iphdr_ip));

    // Fülle den UDP-Header
    udph->source_port = htons(source_port);  // Quellport
    udph->dest_port = htons(target_port);  // Zielport
    udph->udp_length = htons(sizeof(struct udphdr_udp) + data_len);
    udph->udp_checksum = 0;  // In diesem Beispiel lassen wir die Prüfziffer weg

    // Berechne die Prüfziffer
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = inet_addr(target_ip);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr_udp) + data_len);

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr_udp) + data_len;
    char *pseudogram = (char *)malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr_udp) + data_len);

    udph->udp_checksum = checksum((unsigned short *)pseudogram, psize);

    // Sende das Paket
    if (sendto(sock, packet, ntohs(iph->ip_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        std::cerr << "Fehler beim Senden des Pakets!" << std::endl;
        return 1;
    }

    std::cout << "UDP-Paket mit gefälschter Quell-IP und Nutzdaten gesendet!" << std::endl;

    close(sock);
    return 0;
}

