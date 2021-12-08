#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"
#include <unordered_map>

#define N_PROTOCOLS_SUPPORTED   11
#define PROTOCOL_NAME_SIZE      20
#define PATH_MAX_SIZE           500

namespace CHaks
{
    const static std::unordered_map<const char*, uint32_t> supportedProtocols
    {
        {"ETHERNET", PC_ETHER_II},
        {"ARP", PC_ARP},
        {"IPV4", PC_IPV4},
        {"IPV6", PC_IPV6},
        {"ICMPV4", PC_ICMPV4},
        {"ICMPV6", PC_ICMPV6},
        {"TCP", PC_TCP},
        {"UDP", PC_UDP},
        {"HTTP_REQUEST", PC_HTTP_REQUEST},
        {"HTTP_RESPONSE", PC_HTTP_RESPONSE},
        {"DNS_REQUEST", PC_DNS_REQUEST},
        {"DNS_RESPONSE", PC_DNS_RESPONSE}
    };

    class PacketSniffer
    {
        public:
        PacketSniffer();
        ~PacketSniffer();

        int Init(const char* interfaceName);
        int Sniff();

        char protocolsSupplied[N_PROTOCOLS_SUPPORTED][PROTOCOL_NAME_SIZE]{};
        int socketFd;
        bool32 saveToFile;

        private:
        int ReceivePacket(const int socketFd);
        void CloseSocket();
        bool32 IsProtocolSupported(const char* protocol) const;
        bool32 IsProtocolSupported(uint32_t protocol) const;
        int GetFullFilePath(const PacketCraft::Packet& packet, char* fullPathBuffer); // will append the packet name into the savePath string

        char savePath[PATH_MAX_SIZE]; // this the filepath where the packet is to be saved. Will be initialized in Init()
        unsigned long long packetNumber;
    };
}

#endif