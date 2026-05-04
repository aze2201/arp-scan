#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <errno.h>

#define MAX_DEVICES 8192
#define REAPPEAR_TIMEOUT 30
#define SCAN_INTERVAL 20
#define MAX_SCAN_HOSTS 65536  // Limit for very large subnets

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    time_t last_seen;
} device_t;

device_t devices[MAX_DEVICES];
int device_count = 0;

uint8_t my_mac[6];
uint32_t my_ip;

/* ================= utils ================= */

void print_mac(uint8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           m[0], m[1], m[2], m[3], m[4], m[5]);
}

int mac_zero(uint8_t *m) {
    for (int i=0;i<6;i++) if (m[i]!=0) return 0;
    return 1;
}

/* ================= device table ================= */

void update_device(uint32_t ip, uint8_t *mac, int initial)
{
    time_t now = time(NULL);

    for (int i=0;i<device_count;i++) {
        if (devices[i].ip == ip &&
            memcmp(devices[i].mac, mac, 6)==0)
        {
            if (!initial &&
                now - devices[i].last_seen > REAPPEAR_TIMEOUT)
            {
                printf("[%ld] REAPPEAR: %s - ",
                       now, inet_ntoa(*(struct in_addr*)&ip));
                print_mac(mac);
                printf("\n");
            }

            devices[i].last_seen = now;
            return;
        }
    }

    if (device_count < MAX_DEVICES) {
        devices[device_count].ip = ip;
        memcpy(devices[device_count].mac, mac, 6);
        devices[device_count].last_seen = now;

        if (!initial) {
            printf("[%ld] NEW: %s - ",
                   now, inet_ntoa(*(struct in_addr*)&ip));
            print_mac(mac);
            printf("\n");
        }

        device_count++;
    }
}

/* ================= send ARP ================= */

void send_arp(int sock, int ifindex, uint32_t target_ip)
{
    uint8_t buf[42];

    struct ether_header *eth = (struct ether_header*)buf;
    memset(eth->ether_dhost, 0xff, 6);
    memcpy(eth->ether_shost, my_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);

    struct ether_arp *arp =
        (struct ether_arp*)(buf + sizeof(struct ether_header));

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op  = htons(ARPOP_REQUEST);

    memcpy(arp->arp_sha, my_mac, 6);
    memcpy(arp->arp_spa, &my_ip, 4);

    memset(arp->arp_tha, 0, 6);
    memcpy(arp->arp_tpa, &target_ip, 4);

    struct sockaddr_ll addr = {0};
    addr.sll_ifindex = ifindex;
    addr.sll_halen = ETH_ALEN;
    memset(addr.sll_addr, 0xff, 6);

    sendto(sock, buf, 42, 0,
           (struct sockaddr*)&addr, sizeof(addr));
}

/* ================= receive loop ================= */

void recv_arp(int sock, int initial)
{
    uint8_t buf[2048];

    int len = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
    if (len < 42) return;

    struct ether_header *eth = (struct ether_header*)buf;

    if (ntohs(eth->ether_type) != ETHERTYPE_ARP)
        return;

    struct ether_arp *arp =
        (struct ether_arp*)(buf + sizeof(struct ether_header));

    if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY)
        return;

    if (mac_zero(arp->arp_sha))
        return;

    uint32_t ip;
    memcpy(&ip, arp->arp_spa, 4);

    update_device(ip, arp->arp_sha, initial);
}

/* ================= auto-detect subnet ================= */

int get_network_info(const char *iface, uint32_t *network, uint32_t *mask, int *prefix, 
                      uint32_t *first_host, uint32_t *last_host, uint32_t *host_count) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    
    struct ifreq ifr;
    struct sockaddr_in *sin;
    
    // Get IP address
    strcpy(ifr.ifr_name, iface);
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    uint32_t ip = sin->sin_addr.s_addr;
    
    // Get netmask
    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
        close(sock);
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    *mask = sin->sin_addr.s_addr;
    
    // Calculate prefix length
    uint32_t m = ntohl(*mask);
    *prefix = 0;
    while (m) {
        (*prefix)++;
        m <<= 1;
    }
    
    // Calculate network address and broadcast
    *network = ip & *mask;
    uint32_t broadcast = *network | ~(*mask);
    
    // Calculate host range (original script's method)
    *first_host = ntohl(*network) + 1;
    *last_host = ntohl(broadcast) - 1;
    *host_count = (*last_host - *first_host + 1);
    
    close(sock);
    
    // Get MAC and own IP
    int sock2 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    strcpy(ifr.ifr_name, iface);
    ioctl(sock2, SIOCGIFHWADDR, &ifr);
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
    my_ip = ip;
    close(sock2);
    
    return 0;
}

/* ================= main ================= */

int main(int argc, char *argv[])
{
    char *iface;
    uint32_t network, mask, first_host, last_host, host_count;
    int prefix;
    
    // Get interface from command line
    if (argc < 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        printf("Example: %s eth0\n", argv[0]);
        printf("Auto-detects subnet from interface\n");
        return 1;
    }
    
    iface = argv[1];
    
    // Auto-detect network information
    if (get_network_info(iface, &network, &mask, &prefix, &first_host, &last_host, &host_count) < 0) {
        printf("Failed to get network info for interface %s\n", iface);
        return 1;
    }
    
    printf("My IP: %s\n", inet_ntoa(*(struct in_addr*)&my_ip));
    printf("My MAC: ");
    print_mac(my_mac);
    printf("\n");
    printf("Network: %s/%d\n", inet_ntoa(*(struct in_addr*)&network), prefix);
    printf("Host range: %u - %u (%u hosts)\n", first_host, last_host, host_count);
    
    // Limit if too large
    if (host_count > MAX_SCAN_HOSTS) {
        printf("Warning: Large subnet, limiting scan to %d hosts\n", MAX_SCAN_HOSTS);
        last_host = first_host + MAX_SCAN_HOSTS - 1;
        host_count = MAX_SCAN_HOSTS;
    }
    
    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    struct ifreq ifr;
    strcpy(ifr.ifr_name, iface);
    ioctl(sock, SIOCGIFINDEX, &ifr);
    int ifindex = ifr.ifr_ifindex;
    
    /* ===== initial scan - EXACT same as original ===== */
    printf("\n=== Initial scan ===\n");
    
    int initial = 1;
    
    // 3 passes like original
    for (int pass=0; pass<3; pass++) {
        for (uint32_t i=first_host; i<=last_host; i++) {
            uint32_t target = htonl(i);
            send_arp(sock, ifindex, target);
            
            for (int j=0;j<5;j++)
                recv_arp(sock, initial);
            
            usleep(1000);
        }
    }
    
    /* receive tail - EXACT same as original (5 seconds) */
    time_t start = time(NULL);
    while (time(NULL)-start < 5) {
        recv_arp(sock, initial);
    }
    
    // Print discovered devices
    for (int i=0;i<device_count;i++) {
        printf("%s - ",
               inet_ntoa(*(struct in_addr*)&devices[i].ip));
        print_mac(devices[i].mac);
        printf("\n");
    }
    
    /* ===== listening mode - EXACT same as original ===== */
    printf("=== Listening mode ===\n");
    
    initial = 0;
    time_t last_scan = 0;
    
    while (1) {
        recv_arp(sock, initial);
        
        if (time(NULL)-last_scan > SCAN_INTERVAL) {
            for (uint32_t i=first_host; i<=last_host; i++) {
                uint32_t target = htonl(i);
                send_arp(sock, ifindex, target);
                usleep(1000);
            }
            last_scan = time(NULL);
        }
    }
    
    return 0;
}
