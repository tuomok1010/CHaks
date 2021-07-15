#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"
#include <unordered_map>

#define N_PROTOCOLS_SUPPORTED   4
#define PROTOCOL_NAME_SIZE      10

namespace PacketSniff
{
    const static std::unordered_map<const char*, uint32_t> supportedProtocols
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

        int Init(const char* interfaceName);
        int Sniff();

        bool32 IsProtocolSupported(const char* protocol) const;
        bool32 IsProtocolSupported(uint32_t protocol) const;


        char protocolsSupplied[N_PROTOCOLS_SUPPORTED][PROTOCOL_NAME_SIZE]{};
        int socketFd;

        private:
        int ReceivePacket(const int socketFd);
        void CloseSocket();
    };
}

#endif