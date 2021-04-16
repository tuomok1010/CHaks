#include "NetworkUtils.h"
#include "Utils.h"

#include <iostream>
#include <cstring>              // memcpy
#include <sys/socket.h>         // socket()
#include <netinet/ether.h>      // ether_addr
#include <sys/ioctl.h>          // ioctl()
#include <net/if.h>             // struct ifreq
#include <netinet/in.h>         // struct sockaddr_in / struct sockaddr_in6
#include <ifaddrs.h>            // getifaddrs() / freeifaddrs()
#include <arpa/inet.h>          // inet_pton() / inet_ntop()  

int PacketCraft::GetMACAddr(ether_addr& ethAddr, const char* interfaceName, const int socketFd)
{
    ifreq ifr{};
    CopyStr(ifr.ifr_name, sizeof(ifr.ifr_name), interfaceName);

    int result{};
    result = ioctl(socketFd, SIOCGIFHWADDR, &ifr);
    if(result >= 0)
    {
        memcpy(ethAddr.ether_addr_octet, ifr.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::GetMACAddr(ether_addr& ethAddr, const int interfaceIndex, const int socketFd)
{
    char ifName[IFNAMSIZ];
    char* result = if_indextoname(interfaceIndex, ifName);

    if(result != NULL)
    {
        return GetMACAddr(ethAddr, ifName, socketFd);
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "if_indextoname() error!");
        return APPLICATION_ERROR;
    }
}

// TODO: finish/test
int PacketCraft::GetIPAddr(sockaddr_in& addr, const char* interfaceName)
{
    ifaddrs* ifAddrs{};

    int result = getifaddrs(&ifAddrs);
    if(result == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "getifaddrs() error!");
        return APPLICATION_ERROR;
    }

    for(ifaddrs* ifa = ifAddrs; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if(ifa == nullptr)
            continue;

        if(CompareStr(interfaceName, ifa->ifa_name) == TRUE && ifa->ifa_addr->sa_family == AF_INET)
        {
            memcpy(&addr, (sockaddr_in*)ifa->ifa_addr, sizeof(sockaddr_in));
            break;
        }
    }

    freeifaddrs(ifAddrs);

    return NO_ERROR;
}

int PacketCraft::GetIPAddr(sockaddr_in6& addr, const char* interfaceName)
{
    ifaddrs* ifAddrs{};

    int result = getifaddrs(&ifAddrs);
    if(result == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "getifaddrs() error!");
        return APPLICATION_ERROR;
    }

    for(ifaddrs* ifa = ifAddrs; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if(ifa == nullptr)
            continue;

        if(CompareStr(interfaceName, ifa->ifa_name) == TRUE && ifa->ifa_addr->sa_family == AF_INET6)
        {
            memcpy(&addr, (sockaddr_in6*)ifa->ifa_addr, sizeof(sockaddr_in6));
            break;
        }
    }

    freeifaddrs(ifAddrs);

    return NO_ERROR;
}

// TODO: TEST!! Make sure the cast to sockaddr_in/sockaddr_in6 works since the GetIPAddr funcs take references instead
// of pointers!!!
int PacketCraft::GetIPAddr(sockaddr_storage& addr, const char* interfaceName)
{
    int result{APPLICATION_ERROR};

    if(addr.ss_family == AF_INET)
        result = GetIPAddr(*(sockaddr_in*)&addr, interfaceName);
    else if(addr.ss_family == AF_INET6)
        result = GetIPAddr(*(sockaddr_in6*)&addr, interfaceName);
    else
        LOG_ERROR(APPLICATION_ERROR, "Unknown address family");

    return result;
}

int PacketCraft::GetARPTableMACAddr(const int socketFd, const char* interfaceName, const sockaddr_in& ipAddr, ether_addr& macAddr)
{
    arpreq arpEntry{};
    arpEntry.arp_pa.sa_family = AF_INET;
    memcpy(arpEntry.arp_pa.sa_data, ((sockaddr*)&ipAddr)->sa_data, sizeof(arpEntry.arp_pa.sa_data));
    arpEntry.arp_ha.sa_family = ARPHRD_ETHER;
    PacketCraft::CopyStr(arpEntry.arp_dev, sizeof(arpEntry.arp_dev), interfaceName);
    arpEntry.arp_flags = ATF_COM;   // TODO: is this needed? remove if not

    int res = ioctl(socketFd, SIOCGARP, &arpEntry);
    if(res < 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
        return APPLICATION_ERROR;
    }
    
    memcpy(macAddr.ether_addr_octet, arpEntry.arp_ha.sa_data, ETH_ALEN);
    return NO_ERROR;
}

int PacketCraft::GetARPTableMACAddr(const int socketFd, const char* interfaceName, const char* ipAddrStr, ether_addr& macAddr)
{
    sockaddr_in ipAddr{};
    if(inet_pton(AF_INET, ipAddrStr, &ipAddr.sin_addr) <= 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    return GetARPTableMACAddr(socketFd, interfaceName, ipAddr, macAddr);
}

int PacketCraft::AddAddrToARPTable(const int socketFd, const char* interfaceName, const sockaddr_in& ipAddr, const ether_addr& macAddr)
{
    arpreq arpEntry{};
    arpEntry.arp_pa.sa_family = AF_INET;
    memcpy(arpEntry.arp_pa.sa_data, ((sockaddr*)&ipAddr)->sa_data, sizeof(arpEntry.arp_pa.sa_data));
    memcpy(arpEntry.arp_ha.sa_data, macAddr.ether_addr_octet, ETH_ALEN);
    arpEntry.arp_ha.sa_family = ARPHRD_ETHER;
    PacketCraft::CopyStr(arpEntry.arp_dev, sizeof(arpEntry.arp_dev), interfaceName);

    int res = ioctl(socketFd, SIOCSARP, &arpEntry);
    if(res < 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

int PacketCraft::AddAddrToARPTable(const int socketFd, const char* interfaceName, const char* ipAddrStr, const char* macAddrStr)
{
    sockaddr_in ipAddr{};
    ether_addr macAddr{};

    if(inet_pton(AF_INET, ipAddrStr, &ipAddr.sin_addr) <= 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    if(ether_aton_r(macAddrStr, &macAddr) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    return AddAddrToARPTable(socketFd, interfaceName, ipAddr, macAddr);
}

int PacketCraft::EnablePortForwarding()
{
    int status{};
    status = system("echo 1 > /proc/sys/net/ipv4/ip_forward");

    if(status != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() failed!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

int PacketCraft::DisablePortForwarding()
{
    int status{};
    status = system("echo 0 > /proc/sys/net/ipv4/ip_forward");

    if(status != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() failed!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

int PacketCraft::PrintIPAddr(const sockaddr_storage& addr, const char* prefix, const char* suffix)
{
    int result{APPLICATION_ERROR};

    if(addr.ss_family == AF_INET)
        result = PrintIPAddr(*(sockaddr_in*)&addr, prefix, suffix);
    else if(addr.ss_family == AF_INET6)
        result = PrintIPAddr(*(sockaddr_in6*)&addr, prefix, suffix);
    else
        LOG_ERROR(APPLICATION_ERROR, "Unknown address family!");

    return result;
}

int PacketCraft::PrintIPAddr(const sockaddr_in& addr, const char* prefix, const char* suffix)
{
    char addrStr[INET_ADDRSTRLEN]{};
    const char* res = inet_ntop(AF_INET, &addr.sin_addr.s_addr, addrStr, INET_ADDRSTRLEN);
    if(res != nullptr)
    {
        std::cout << prefix << addrStr << suffix << std::flush;
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::PrintIPAddr(const sockaddr_in6& addr, const char* prefix, const char* suffix)
{
    char addrStr[INET6_ADDRSTRLEN]{};
    const char* res = inet_ntop(AF_INET6, &addr.sin6_addr.__in6_u, addrStr, INET6_ADDRSTRLEN);
    if(res != nullptr)
    {
        std::cout << prefix << addrStr << suffix << std::flush;
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::PrintMACAddr(const ether_addr& addr, const char* prefix, const char* suffix)
{
    char addrStr[ETH_ADDR_STR_LEN]{};
    const char* res = ether_ntoa_r(&addr, addrStr);
    if(res != nullptr)
    {
        std::cout << prefix << addrStr << suffix << std::flush;
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }
}