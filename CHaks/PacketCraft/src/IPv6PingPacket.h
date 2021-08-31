#ifndef PC_IPV6PING_H
#define PC_IPV6PING_H

#include "PCTypes.h"
#include "PCHeaders.h"
#include "Packet.h"

namespace PacketCraft
{
    class IPv6PingPacket : public Packet
    {
        public:
        IPv6PingPacket();
        ~IPv6PingPacket();

        int Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in6& srcIP, const sockaddr_in6& dstIP, PingType type);
        int Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, PingType type);

        int Send(const int socket, const char* interfaceName) const;
        void ResetPacketBuffer();

        int ProcessReceivedPacket(uint8_t* packet, int layerSize = 0, unsigned short protocol = PC_PROTO_ETH) override;
        void FreePacket() override;

        EthHeader* ethHeader;
        IPv6Header* ipv6Header;
        ICMPv6Header* icmpv6Header;
    };
}

#endif