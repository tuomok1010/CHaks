#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

#define N_PROTOCOLS_SUPPORTED   3
#define PROTOCOL_NAME_SIZE      10

namespace PacketSniff
{
    static char supportedProtocols[N_PROTOCOLS_SUPPORTED][PROTOCOL_NAME_SIZE]
    {
        "ARP", "IPV4", "ICMPV4"
    };

    class PacketSniffer
    {
        public:
        PacketSniffer();
        ~PacketSniffer();

        int Init(char protocols[N_PROTOCOLS_SUPPORTED][PROTOCOL_NAME_SIZE]);
        int ReceivePackets();

        static bool32 IsProtocolSupported(const char* protocol);

        private:
        int ReceivePacket(const int socketFd);

        int socketFds[N_PROTOCOLS_SUPPORTED]{};
        int nSocketsUsed{};
    };
}

#endif