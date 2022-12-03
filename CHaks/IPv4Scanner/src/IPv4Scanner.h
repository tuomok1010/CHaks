#ifndef IPV4_SCANNER_H
#define IPV4_SCANNER_H

#include "../../../../PacketCraft/PacketCraft/src/include/PCInclude.h"

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

        int CreateARPRequest(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP,
            PacketCraft::Packet& packet);
        int CreateARPRequest(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr,
            PacketCraft::Packet& packet);
    };
}

#endif