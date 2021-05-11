#ifndef PC_ICMPV4_H
#define PC_ICMPV4_H

#include "PCTypes.h"
#include "PCHeaders.h"
#include "Packet.h"

enum class PingType
{
    ECHO_REQUEST,
    ECHO_REPLY
};

namespace PacketCraft
{
    class IPv4PingPacket : public Packet
    {
        public:
        IPv4PingPacket();
        ~IPv4PingPacket();

        int Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, PingType type);

        int Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, PingType type);

        uint16_t CalculateIPv4Checksum(void* ipv4Header, size_t ipv4HeaderSizeInBytes);
        bool32 VerifyIPv4Checksum(void* ipv4Header, size_t ipv4HeaderSizeInBytes) const;

        int Send(const int socket, const char* interfaceName) const;
        void ResetPacketBuffer();
        int PrintPacketData() const;

        int ProcessReceivedPacket(uint8_t* packet, unsigned short protocol) override;
        void FreePacket() override;

        EthHeader* ethHeader;
        IPv4Header* ipv4Header;
        icmphdr* icmpv4Header;
    };
}

#endif