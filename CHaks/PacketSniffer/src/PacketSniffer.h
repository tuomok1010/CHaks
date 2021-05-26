#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"
#include <stdarg.h>
#include <unordered_map>

#define N_PROTOCOLS_SUPPORTED   3
#define PROTOCOL_NAME_SIZE      10

namespace PacketSniff
{
    const static std::unordered_map<const char*, unsigned int> supportedProtocols
    {
        {"ETHERNET", PC_ETHER_II},
        {"ARP", PC_ARP},
        {"IPV4", PC_IPV4},
        {"ICMPV4", PC_ICMPV4}
    };

    class PacketSniffer
    {
        public:
        PacketSniffer();
        ~PacketSniffer();

        int Init(...);
        int ReceivePackets();

        static bool32 IsProtocolSupported(const char* protocol);

        private:
        int ReceivePacket(const int socketFd);

        const char* protocolsSupplied[N_PROTOCOLS_SUPPORTED][PROTOCOL_NAME_SIZE]{};
        int socketFds[N_PROTOCOLS_SUPPORTED]{};
        int nSocketsUsed{};
    };
}

#endif