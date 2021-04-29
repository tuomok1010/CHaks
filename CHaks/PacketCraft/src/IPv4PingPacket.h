#ifndef PC_ICMPV4_H
#define PC_ICMPV4_H

#include "PCTypes.h"
#include "Packet.h"

namespace PacketCraft
{
    class IPv4PingPacket : public Packet
    {
        public:
        IPv4PingPacket();
        ~IPv4PingPacket();

        int Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, 
            const uint32_t ipHeaderLenInBytes, const uint32_t icmpv4HeaderLenInBytes, uint8_t icmpv4Type);

        int Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, 
            const uint32_t ipHeaderLenInBytes, const uint32_t icmpv4HeaderLenInBytes, uint8_t icmpv4Type);

        uint16_t CalculateIPv4Checksum(void* ipv4Header, size_t ipv4HeaderSizeInBytes);
        bool32 VerifyIPv4Checksum(void* ipv4Header, size_t ipv4HeaderSizeInBytes);

        int Send(const int socket, const char* interfaceName) const;
        void ResetPacketBuffer();
        int PrintPacketData() const;

        int ProcessReceivedPacket(uint8_t* packet, unsigned short nextHeader) override;
        void FreePacket() override;

        ether_header* ethHeader;
        ip* ipv4Header;
        icmphdr* icmpv4Header;
    };
}

#endif