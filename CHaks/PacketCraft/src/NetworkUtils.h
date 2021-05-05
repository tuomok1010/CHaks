#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include "PCTypes.h"

namespace PacketCraft
{
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

    int PrintIPAddr(const sockaddr_storage& addr, const char* prefix = "", const char* suffix = "");
    int PrintIPAddr(const sockaddr_in& addr, const char* prefix = "", const char* suffix = "");
    int PrintIPAddr(const sockaddr_in6& addr, const char* prefix = "", const char* suffix = "");
    int PrintMACAddr(const ether_addr& addr, const char* prefix = "", const char* suffix = "");
}

#endif