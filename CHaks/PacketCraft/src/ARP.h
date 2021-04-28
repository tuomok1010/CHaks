#ifndef PC_ARP_H
#define PC_ARP_H

#include "PCTypes.h"
#include "Packet.h"

#include <netinet/if_ether.h>


struct __attribute__((__packed__)) ARPHeader
{
    uint16_t ar_hrd;		    /* Format of hardware address.  */
    uint16_t ar_pro;            /* Format of protocol address.  */
    uint8_t ar_hln;		        /* Length of hardware address.  */
    uint8_t ar_pln;		        /* Length of protocol address.  */
    uint16_t ar_op;		        /* ARP opcode (command).  */

    uint8_t ar_sha[ETH_ALEN];   /* Source hardware address */
    uint8_t ar_sip[IPV4_ALEN];  /* Source ipv4 address */
    uint8_t ar_tha[ETH_ALEN];   /* Target hardware address */
    uint8_t ar_tip[IPV4_ALEN];  /* Target ipv4 address */
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

        int Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, ARPType type);
        int Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, ARPType type);
        int Send(const int socket, const char* interfaceName) const;
        void ResetPacketBuffer();
        int PrintPacketData() const;

        int ProcessReceivedPacket(uint8_t* packet, unsigned short nextHeader) override;
        void FreePacket() override;

        ether_header* ethHeader;
        ARPHeader* arpHeader;
    };
}

#endif