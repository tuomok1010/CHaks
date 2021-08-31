#ifndef PC_IPV4PING_H
#define PC_IPV4PING_H

#include "PCTypes.h"
#include "PCHeaders.h"
#include "Packet.h"

namespace PacketCraft
{
    class IPv4PingPacket : public Packet
    {
        public:
        IPv4PingPacket();
        ~IPv4PingPacket();

        int Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, PingType type);
        int Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, PingType type);

        int Send(const int socket, const char* interfaceName) const;
        void ResetPacketBuffer();
        int PrintPacketData() const;

        int ProcessReceivedPacket(uint8_t* packet, int layerSize = 0, unsigned short protocol = PC_PROTO_ETH) override;
        void FreePacket() override;

        EthHeader* ethHeader;
        IPv4Header* ipv4Header;
        ICMPv4Header* icmpv4Header;
    };
}

#endif