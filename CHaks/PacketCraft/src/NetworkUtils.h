#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <unordered_map>

#include "PCTypes.h"

namespace PacketCraft
{
    const static std::unordered_map<uint32_t, const char*> networkProtocols
    {
        {PC_ETHER_II, "ETHERNET"},
        {PC_ARP, "ARP"},
        {PC_IPV4, "IPV4"},
        {PC_IPV6, "IPV6"},
        {PC_ICMPV4, "ICMPV4"},
        {PC_ICMPV6, "ICMPV6"}
    };

    const char* ProtoUint32ToStr(uint32_t protocol);
    uint32_t ProtoStrToUint32(const char* protocol);

    int GetMACAddr(ether_addr& ethAddr, const char* interfaceName, const int socketFd);
    int GetMACAddr(ether_addr& ethAddr, const int interfaceIndex, const int socketFd);
    int GetMACAddr(char* ethAddrStr, const char* interfaceName, const int socketFd);
    int GetMACAddr(char* ethAddrStr, const int interfaceIndex, const int socketFd);

    int GetIPAddr(sockaddr_in& addr, const char* interfaceName);
    int GetIPAddr(sockaddr_in6& addr, const char* interfaceName);
    int GetIPAddr(sockaddr_storage& addr, const char* interfaceName);
    int GetIPAddr(char* ipAddrStr, const char* interfaceName, const int af);

    int GetNetworkMask(sockaddr_in& mask, const char* interfaceName, const int socketFd);
    int GetNetworkMask(sockaddr_in& mask, const int interfaceIndex, const int socketFd);

    int GetBroadcastAddr(sockaddr_in& broadcastAddr, const char* interfaceName, const int socketFd);
    int GetBroadcastAddr(sockaddr_in& broadcastAddr, const int interfaceIndex, const int socketFd);

    int GetNetworkAddr(sockaddr_in& networkAddr, const sockaddr_in& broadcastAddr, const int nHostBits);
    int GetNetworkAddr(sockaddr_in& networkAddr, const char* interfaceName, const int socketFd);
    int GetNetworkAddr(sockaddr_in& networkAddr, const int interfaceIndex, const int socketFd);

    int GetARPTableMACAddr(const int socketFd, const char* interfaceName, const sockaddr_in& ipAddr, ether_addr& macAddr);
    int GetARPTableMACAddr(const int socketFd, const char* interfaceName, const char* ipAddrStr, char* macAddrStr);

    int GetNumHostBits(const sockaddr_in& networkMask);
    int GetNumHostBits(int& nBits, const char* interfaceName, const int socketFd);

    int AddAddrToARPTable(const int socketFd, const char* interfaceName, const sockaddr_in& ipAddr, const ether_addr& macAddr);
    int AddAddrToARPTable(const int socketFd, const char* interfaceName, const char* ipAddrStr, const char* macAddrStr);

    int RemoveAddrFromARPTable(const int socketFd, const char* interfaceName, const sockaddr_in& ipToRemove);
    int RemoveAddrFromARPTable(const int socketFd, const char* interfaceName, const char* ipToRemoveStr);

    int SetMACAddr(const int socketFd, const char* interfaceName, const ether_addr& newMACAddr);
    int SetMACAddr(const int socketFd, const char* interfaceName, const char* newMACAddrStr);

    int EnablePortForwarding();
    int DisablePortForwarding();

    uint16_t CalculateIPv4Checksum(void* ipv4Header, size_t ipv4HeaderSizeInBytes);
    uint16_t CalculateICMPv4Checksum(void* icmpv4Header, size_t icmpvHeaderSizeInBytes);
    bool32 VerifyIPv4Checksum(void* ipv4Header, size_t ipv4HeaderSizeInBytes);
    bool32 VerifyICMPv4Checksum(void* icmpv4Header, size_t icmpvHeaderSizeInBytes);

    int PrintIPAddr(const sockaddr_storage& addr, const char* prefix = "", const char* suffix = "");
    int PrintIPAddr(const sockaddr_in& addr, const char* prefix = "", const char* suffix = "");
    int PrintIPAddr(const sockaddr_in6& addr, const char* prefix = "", const char* suffix = "");
    int PrintMACAddr(const ether_addr& addr, const char* prefix = "", const char* suffix = "");

    int PrintEthernetLayer(EthHeader* ethHeader);
    int PrintARPLayer(ARPHeader* arpHeader);
    int PrintIPv4Layer(IPv4Header* ipv4Header);
    int PrintIPv6Layer(IPv6Header* ipv6Header);
    int PrintICMPv4Layer(ICMPv4Header* icmpv4Header, size_t dataSize = 0);
    int PrintICMPv6Layer(ICMPv6Header* icmpv6Header, size_t dataSize = 0);

    void PrintLayerTypeStr(const uint32_t layerType, const char* prefix = "", const char* suffix = "");
}

#endif