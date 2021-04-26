#ifndef IPV4_SCANNER_H
#define IPV4_SCANNER_H

#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

namespace IPv4Scan
{
    class IPv4Scanner
    {
        public:
        IPv4Scanner();
        ~IPv4Scanner();

        int SendARPPackets(const char* interfaceName, const int socketFd, const sockaddr_in& srcIP, const ether_addr& srcMAC,
            const sockaddr_in& networkAddr, const sockaddr_in& broadcastAddr, bool32& running);

        int ReceiveARPPackets(const char* interfaceName, const int socketFd, bool32& running);

        int ProcessReceivedPacket(const char* interfaceName, const int socketFd);

        void PrintARPTableContents(const char* interfaceName, const int socketFd);
    };
}

#endif