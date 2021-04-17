#ifndef PC_ARP_H
#define PC_ARP_H

#include "PCTypes.h"
#include "Packet.h"

#include <net/if.h> 


struct __attribute__((__packed__)) ARPHeader
{
    arphdr arpHdr;

    unsigned char ar_sha[ETH_ALEN];
    unsigned char ar_sip[IPV4_ALEN];
    unsigned char ar_tha[ETH_ALEN];
    unsigned char ar_tip[IPV4_ALEN];
};

enum class ARPType
{
    ARP_REQUEST,
    ARP_REPLY
};

namespace PacketCraft
{
    class ARPPacket : public Packet
    {
        public:
        ARPPacket();
        ~ARPPacket();

        int Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, ARPType type);
        int Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, ARPType type);
        int Send(const int socket, const char* interfaceName) const;
        int PrintPacketData() const;

        int ProcessReceivedPacket(uint8_t* packet, unsigned short nextHeader) override;

        ether_header* ethHeader;
        ARPHeader* arpHeader;
    };
}

#endif