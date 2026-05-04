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

#define MAX_DEVICES 8192
#define REAPPEAR_TIMEOUT 30
#define SCAN_INTERVAL 20

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

/* ================= main ================= */

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Usage: %s <iface> <CIDR>\n", argv[0]);
        return 1;
    }

    char *iface = argv[1];
    char *cidr  = argv[2];

    char ip_str[32];
    int prefix;

    sscanf(cidr, "%[^/]/%d", ip_str, &prefix);

    uint32_t base_ip = inet_addr(ip_str);
    uint32_t mask = htonl(0xFFFFFFFF << (32-prefix));

    uint32_t net = ntohl(base_ip & mask);
    uint32_t hosts = (1 << (32-prefix));

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    struct ifreq ifr;
    strcpy(ifr.ifr_name, iface);

    ioctl(sock, SIOCGIFINDEX, &ifr);
    int ifindex = ifr.ifr_ifindex;

    ioctl(sock, SIOCGIFHWADDR, &ifr);
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    ioctl(sock, SIOCGIFADDR, &ifr);
    my_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

    printf("My IP: %s\n", inet_ntoa(*(struct in_addr*)&my_ip));
    printf("My MAC: ");
    print_mac(my_mac);
    printf("\n");

    /* ===== initial scan ===== */

    printf("=== Initial scan ===\n");

    int initial = 1;

    for (int pass=0; pass<3; pass++) {
        for (uint32_t i=1;i<hosts-1;i++) {

            uint32_t target = htonl(net + i);
            send_arp(sock, ifindex, target);

            for (int j=0;j<5;j++)
                recv_arp(sock, initial);

            usleep(1000);
        }
    }

    /* receive tail */
    time_t start = time(NULL);
    while (time(NULL)-start < 5) {
        recv_arp(sock, initial);
    }

    for (int i=0;i<device_count;i++) {
        printf("%s - ",
               inet_ntoa(*(struct in_addr*)&devices[i].ip));
        print_mac(devices[i].mac);
        printf("\n");
    }

    printf("=== Listening mode ===\n");

    initial = 0;
    time_t last_scan = 0;

    while (1) {
        recv_arp(sock, initial);

        if (time(NULL)-last_scan > SCAN_INTERVAL) {
            for (uint32_t i=1;i<hosts-1;i++) {
                uint32_t target = htonl(net + i);
                send_arp(sock, ifindex, target);
                usleep(1000);
            }
            last_scan = time(NULL);
        }
    }

    return 0;
}
