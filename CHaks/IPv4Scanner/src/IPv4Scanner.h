#ifndef IPV4_SCANNER_H
#define IPV4_SCANNER_H

#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

namespace CHaks
{
    class IPv4Scanner
    {
        public:
        IPv4Scanner();
        ~IPv4Scanner();

        int SendARPPackets(const char* interfaceName, const int socketFd, const sockaddr_in& srcIP, const ether_addr& srcMAC,
            const sockaddr_in& networkAddr, const sockaddr_in& broadcastAddr, bool32& running);

        int ReceiveARPPackets(const char* interfaceName, const int socketFd, bool32& running);

        private:
        int ProcessReceivedPacket(const char* interfaceName, const int socketFd, bool32 printHeader);
        int PrintResult(const ether_addr& macAddr, const sockaddr_in& ipAddr, bool32 printHeader);
    };
}

#endif