#ifndef ETHER_H
#define ETHER_H

#include <stdint.h>

struct ether_header {
    uint8_t ether_dhost[6]; // Destination MAC address
    uint8_t ether_shost[6]; // Source MAC address
    uint16_t ether_type;    // EtherType field
};

// EtherType field for IPv4 packets
#define ETH_P_IP 0x0800
// EtherType field for ARP packets
#define ETH_P_ARP 0x0806
// EtherType field for IPv6 packets
#define ETH_P_IPV6 0x86DD

#endif // ETHER_H
