// general C++ stuff
#include <iostream>

// general C stuff
#include <sys/types.h>
#include <stdlib.h>
#include <cstring>

// network stuff
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define IPV4_ALEN 4
#define IPV6_ALEN 16

struct __attribute__((__packed__)) ARPHeader
{
    arphdr arpHdr;

    unsigned char ar_sha[ETH_ALEN];
    unsigned char ar_sip[IPV4_ALEN];
    unsigned char ar_tha[ETH_ALEN];
    unsigned char ar_tip[IPV4_ALEN];
};


int main()
{
    // SRC INFO
    const char* srcMACStr = "08:00:27:af:1f:f8";
    const char* srcIPStr = "10.0.2.15";

    ether_addr srcMAC;
    ether_aton_r(srcMACStr, &srcMAC);

    in_addr srcIP;
    inet_pton(AF_INET, srcIPStr, &srcIP);
    ////////////////////

    // DEST INFO
    const char* dstMACStr = "ff:ff:ff:ff:ff:ff";
    const char* dstIPStr = "10.0.2.15";

    ether_addr dstMAC;
    ether_aton_r(dstMACStr, &dstMAC);

    in_addr dstIP;
    inet_pton(AF_INET, dstIPStr, &dstIP);
    ////////////////////

    void* packet;

    ether_header ethHeader;
    memcpy(ethHeader.ether_shost, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(ethHeader.ether_dhost, dstMAC.ether_addr_octet, ETH_ALEN);
    ethHeader.ether_type = htons(ETH_P_ARP);

    ARPHeader arpHeader;
    arpHeader.arpHdr.ar_hrd = htons(ARPHRD_ETHER);
    arpHeader.arpHdr.ar_pro = htons(ETH_P_IP);
    arpHeader.arpHdr.ar_hln = ETH_ALEN;
    arpHeader.arpHdr.ar_pln = IPV4_ALEN;
    arpHeader.arpHdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(arpHeader.ar_sha, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader.ar_sip, &srcIP.s_addr, IPV4_ALEN);
    memcpy(arpHeader.ar_tha, dstMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader.ar_tip, &dstIP.s_addr, IPV4_ALEN);

    packet = malloc(sizeof(ether_header) + sizeof(ARPHeader));
    memcpy(packet, &ethHeader, sizeof(ether_header));
    memcpy((uint8_t*)packet + sizeof(ether_header), &arpHeader, sizeof(ARPHeader));

    int mySocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(mySocket < 0)
    {
        std::cerr << "socket() error!" << std::endl;
    }

    sockaddr_ll sockAddr;
    sockAddr.sll_family = PF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_ARP);
    sockAddr.sll_ifindex = 2;
    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    sockAddr.sll_halen = ETH_ALEN;

    int bytesSent{};
    int packetSize = sizeof(ether_header) + sizeof(ARPHeader);
    bytesSent = sendto(mySocket, packet, packetSize, 0, (sockaddr*)&sockAddr, sizeof(sockAddr));
    if(bytesSent != packetSize)
    {
        std::cerr << "sendto() error!" << std::endl;
    }

    free(packet);

    return 0;
}

