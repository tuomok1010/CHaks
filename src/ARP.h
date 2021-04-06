#ifndef PC_ARP_H
#define PC_ARP_H

#include "PCTypes.h"
#include "Packet.h"

struct __attribute__((__packed__)) ARPHeader
{
    arphdr arpHdr;

    unsigned char ar_sha[ETH_ALEN];
    unsigned char ar_sip[IPV4_ALEN];
    unsigned char ar_tha[ETH_ALEN];
    unsigned char ar_tip[IPV4_ALEN];
};

namespace PacketCraft
{
    class ARPPacket : public Packet
    {
        public:
        ARPPacket();
        ~ARPPacket();

        int Create();

        ether_header* ethHeader;
        ARPHeader* arpHeader;

    };
}

#endif