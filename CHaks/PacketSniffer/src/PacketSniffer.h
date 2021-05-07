#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

#define N_PROTOCOLS_SUPPORTED   3
#define PROTOCOL_NAME_SIZE      10

namespace PacketSniff
{
    static char supportedProtocols[N_PROTOCOLS_SUPPORTED][PROTOCOL_NAME_SIZE]
    {
        "ALL", "ARP", "ICMPV4"
    };

    class PacketSniffer
    {
        public:
        PacketSniffer();
        ~PacketSniffer();

        static bool32 IsProtocolSupported(const char* protocol);

        private:

    };
}

#endif