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

    int GetARPTableMACAddr(const int socketFd, const char* interfaceName, const sockaddr_in& ipAddr, ether_addr& macAddr);
    int GetARPTableMACAddr(const int socketFd, const char* interfaceName, const char* ipAddrStr, char* macAddrStr);

    int AddAddrToARPTable(const int socketFd, const char* interfaceName, const sockaddr_in& ipAddr, const ether_addr& macAddr);
    int AddAddrToARPTable(const int socketFd, const char* interfaceName, const char* ipAddrStr, const char* macAddrStr);

    int EnablePortForwarding();
    int DisablePortForwarding();

    int PrintIPAddr(const sockaddr_storage& addr, const char* prefix = "", const char* suffix = "");
    int PrintIPAddr(const sockaddr_in& addr, const char* prefix = "", const char* suffix = "");
    int PrintIPAddr(const sockaddr_in6& addr, const char* prefix = "", const char* suffix = "");
    int PrintMACAddr(const ether_addr& addr, const char* prefix = "", const char* suffix = "");
}

#endif