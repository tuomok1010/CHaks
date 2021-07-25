#include "NetworkUtils.h"
#include "Utils.h"
#include "PCHeaders.h"

#include <iostream>
#include <cstring>              // memcpy
#include <sys/socket.h>         // socket()
#include <netinet/ether.h>      // ether_addr
#include <sys/ioctl.h>          // ioctl()
#include <net/if.h>             // struct ifreq
#include <netinet/in.h>         // struct sockaddr_in / struct sockaddr_in6
#include <ifaddrs.h>            // getifaddrs() / freeifaddrs()
#include <arpa/inet.h>          // inet_pton() / inet_ntop()  
#include <netinet/ip.h>

const char* PacketCraft::ProtoUint32ToStr(uint32_t protocol)
{
    return networkProtocols.at(protocol);
}

uint32_t PacketCraft::ProtoStrToUint32(const char* protocol)
{
    for(const std::pair<uint32_t, const char*>& e : networkProtocols)
    {
        if(CompareStr(e.second, protocol) == TRUE)
            return e.first;
    }

    return PC_NONE;
}

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
        // LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
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
        // LOG_ERROR(APPLICATION_ERROR, "if_indextoname() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::GetMACAddr(char* ethAddrStr, const char* interfaceName, const int socketFd)
{
    ether_addr ethAddr{};
    if(GetMACAddr(ethAddr, interfaceName, socketFd) == APPLICATION_ERROR)
    {
        // LOG_ERROR(APPLICATION_ERROR, "GetMACAddr() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r(&ethAddr, ethAddrStr) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

int PacketCraft::GetMACAddr(char* ethAddrStr, const int interfaceIndex, const int socketFd)
{
    char ifName[IFNAMSIZ];
    if(if_indextoname(interfaceIndex, ifName) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "if_indextoname() error!");
        return APPLICATION_ERROR;
    }

    return GetMACAddr(ethAddrStr, ifName, socketFd);
}

// TODO: finish/test
int PacketCraft::GetIPAddr(sockaddr_in& addr, const char* interfaceName)
{
    ifaddrs* ifAddrs{};

    int result = getifaddrs(&ifAddrs);
    if(result == -1)
    {
        // LOG_ERROR(APPLICATION_ERROR, "getifaddrs() error!");
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
        // LOG_ERROR(APPLICATION_ERROR, "getifaddrs() error!");
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

int PacketCraft::GetIPAddr(sockaddr_storage& addr, const char* interfaceName)
{
    int result{APPLICATION_ERROR};

    if(addr.ss_family == AF_INET)
        result = GetIPAddr(*(sockaddr_in*)&addr, interfaceName);
    else if(addr.ss_family == AF_INET6)
        result = GetIPAddr(*(sockaddr_in6*)&addr, interfaceName);
    else
    {
        // LOG_ERROR(APPLICATION_ERROR, "Unknown address family");
    }

    return result;
}

int PacketCraft::GetIPAddr(char* ipAddrStr, const char* interfaceName, const int af)
{
    sockaddr_storage ipAddr;
    ipAddr.ss_family = af;

    if(GetIPAddr(ipAddr, interfaceName) == APPLICATION_ERROR)
    {
        // LOG_ERROR(APPLICATION_ERROR, "GetIPAddr() error!");
        return APPLICATION_ERROR;
    }

    if(af == AF_INET)
    {
        if(inet_ntop(AF_INET, &((sockaddr_in*)&ipAddr)->sin_addr, ipAddrStr, INET_ADDRSTRLEN) == nullptr)
        {
            // LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
            return APPLICATION_ERROR;
        }
    }
    else if(af == AF_INET6)
    {
        if(inet_ntop(AF_INET6, &((sockaddr_in6*)&ipAddr)->sin6_addr, ipAddrStr, INET6_ADDRSTRLEN) == nullptr)
        {
            // LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
            return APPLICATION_ERROR;
        }
    }

    return NO_ERROR;
}

int PacketCraft::GetNetworkMask(sockaddr_in& mask, const char* interfaceName, const int socketFd)
{
    ifreq ifr{};
    CopyStr(ifr.ifr_name, sizeof(ifr.ifr_name), interfaceName);

    int result{};
    result = ioctl(socketFd, SIOCGIFNETMASK, &ifr);
    if(result >= 0)
    {
        memcpy(&mask.sin_addr, &((sockaddr_in*)&ifr.ifr_ifru.ifru_netmask)->sin_addr, sizeof(mask.sin_addr));
        return NO_ERROR;
    }
    else
    {
        // LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::GetNetworkMask(sockaddr_in& mask, const int interfaceIndex, const int socketFd)
{
    char ifName[IFNAMSIZ];
    if(if_indextoname(interfaceIndex, ifName) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "if_indextoname() error!");
        return APPLICATION_ERROR;
    }

    return GetNetworkMask(mask, ifName, socketFd);
}

int PacketCraft::GetBroadcastAddr(sockaddr_in& broadcastAddr, const char* interfaceName, const int socketFd)
{
    ifreq ifr{};
    CopyStr(ifr.ifr_name, sizeof(ifr.ifr_name), interfaceName);

    int result{};
    result = ioctl(socketFd, SIOCGIFBRDADDR, &ifr);
    if(result >= 0)
    {
        memcpy(&broadcastAddr.sin_addr, &((sockaddr_in*)&ifr.ifr_ifru.ifru_broadaddr)->sin_addr, sizeof(broadcastAddr.sin_addr));
        return NO_ERROR;
    }
    else
    {
        // LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::GetBroadcastAddr(sockaddr_in& broadcastAddr, const int interfaceIndex, const int socketFd)
{
    char ifName[IFNAMSIZ];
    if(if_indextoname(interfaceIndex, ifName) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "if_indextoname() error!");
        return APPLICATION_ERROR;
    }

    return GetBroadcastAddr(broadcastAddr, ifName, socketFd);
}

int PacketCraft::GetNetworkAddr(sockaddr_in& networkAddr, const sockaddr_in& broadcastAddr, const int nHostBits)
{
    uint32_t broadcast32 = ntohl(broadcastAddr.sin_addr.s_addr);
    networkAddr.sin_addr.s_addr = htonl((broadcast32 >> nHostBits) << nHostBits);

    return NO_ERROR;
}

int PacketCraft::GetNetworkAddr(sockaddr_in& networkAddr, const char* interfaceName, const int socketFd)
{
    int nHostBits{};
    if(GetNumHostBits(nHostBits, interfaceName, socketFd) == APPLICATION_ERROR)
    {
        // LOG_ERROR(APPLICATION_ERROR, "GetNumHostBits() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_in broadcastAddr{};
    if(GetBroadcastAddr(broadcastAddr, interfaceName, socketFd) == APPLICATION_ERROR)
    {
        // LOG_ERROR(APPLICATION_ERROR, "GetBroadcastAddr() error!");
        return APPLICATION_ERROR;
    }

    return GetNetworkAddr(networkAddr, broadcastAddr, nHostBits);
}

int PacketCraft::GetNetworkAddr(sockaddr_in& networkAddr, const int interfaceIndex, const int socketFd)
{
    char ifName[IFNAMSIZ];
    if(if_indextoname(interfaceIndex, ifName) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "if_indextoname() error!");
        return APPLICATION_ERROR;
    }

    return GetNetworkAddr(networkAddr, ifName, socketFd);
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
        // LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
        return APPLICATION_ERROR;
    }
    
    memcpy(macAddr.ether_addr_octet, arpEntry.arp_ha.sa_data, ETH_ALEN);
    return NO_ERROR;
}

int PacketCraft::GetARPTableMACAddr(const int socketFd, const char* interfaceName, const char* ipAddrStr, char*  macAddrStr)
{
    sockaddr_in ipAddr{};
    if(inet_pton(AF_INET, ipAddrStr, &ipAddr.sin_addr) <= 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    ether_addr macAddr{};
    if(GetARPTableMACAddr(socketFd, interfaceName, ipAddr, macAddr) == APPLICATION_ERROR)
    {
        // LOG_ERROR(APPLICATION_ERROR, "GetARPTableMACAddr() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r(&macAddr, macAddrStr) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

int PacketCraft::GetNumHostBits(const sockaddr_in& networkMask)
{
    uint32_t mask32 = ntohl(networkMask.sin_addr.s_addr);

    for(int i = 0; i < IPV4_ALEN * 8; ++i)
    {
        uint32_t result = ((mask32 >> i) & 1);
        if(result == 1)
        {
            return i;
        }
    }

    return 0;
}

int PacketCraft::GetNumHostBits(int& nBits, const char* interfaceName, const int socketFd)
{
    ifreq ifr{};
    CopyStr(ifr.ifr_name, sizeof(ifr.ifr_name), interfaceName);

    sockaddr_in mask{};

    int result{};
    result = ioctl(socketFd, SIOCGIFNETMASK, &ifr);
    if(result >= 0)
    {
        memcpy(&mask.sin_addr, &((sockaddr_in*)&ifr.ifr_ifru.ifru_netmask)->sin_addr, sizeof(mask.sin_addr));
        nBits = GetNumHostBits(mask);
        return NO_ERROR;
    }
    else
    {
        // LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::AddAddrToARPTable(const int socketFd, const char* interfaceName, const sockaddr_in& ipAddr, const ether_addr& macAddr)
{
    arpreq arpEntry{};
    arpEntry.arp_pa.sa_family = AF_INET;
    memcpy(arpEntry.arp_pa.sa_data, ((sockaddr*)&ipAddr)->sa_data, sizeof(arpEntry.arp_pa.sa_data));
    memcpy(arpEntry.arp_ha.sa_data, macAddr.ether_addr_octet, ETH_ALEN);
    arpEntry.arp_ha.sa_family = ARPHRD_ETHER;
    PacketCraft::CopyStr(arpEntry.arp_dev, sizeof(arpEntry.arp_dev), interfaceName);
    arpEntry.arp_flags = ATF_COM;

    int res = ioctl(socketFd, SIOCSARP, &arpEntry);
    if(res < 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
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
        // LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    if(ether_aton_r(macAddrStr, &macAddr) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    return AddAddrToARPTable(socketFd, interfaceName, ipAddr, macAddr);
}

int PacketCraft::RemoveAddrFromARPTable(const int socketFd, const char* interfaceName, const sockaddr_in& ipToRemove)
{
    arpreq arpEntry{};
    arpEntry.arp_pa.sa_family = AF_INET;
    memcpy(arpEntry.arp_pa.sa_data, ((sockaddr*)&ipToRemove)->sa_data, sizeof(arpEntry.arp_pa.sa_data));
    PacketCraft::CopyStr(arpEntry.arp_dev, sizeof(arpEntry.arp_dev), interfaceName);

    int res = ioctl(socketFd, SIOCDARP, &arpEntry);
    if(res < 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

int PacketCraft::RemoveAddrFromARPTable(const int socketFd, const char* interfaceName, const char* ipToRemoveStr)
{
    sockaddr_in ipToRemove{};
    ipToRemove.sin_family = AF_INET;
    if(inet_pton(AF_INET, ipToRemoveStr, &ipToRemove.sin_addr) == -1)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    return RemoveAddrFromARPTable(socketFd, interfaceName, ipToRemove);
}

int PacketCraft::SetMACAddr(const int socketFd, const char* interfaceName, const ether_addr& newMACAddr)
{
    ifreq ifr{};
    memcpy(ifr.ifr_ifru.ifru_hwaddr.sa_data, newMACAddr.ether_addr_octet, ETH_ALEN);
    memcpy(ifr.ifr_ifrn.ifrn_name, interfaceName, GetStrLen(interfaceName));
    ifr.ifr_ifru.ifru_hwaddr.sa_family = ARPHRD_ETHER;

    int res = ioctl(socketFd, SIOCSIFHWADDR, &ifr);
    if(res < 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;  
}

int PacketCraft::SetMACAddr(const int socketFd, const char* interfaceName, const char* newMACAddrStr)
{
    ether_addr macAddr{};

    if(ether_aton_r(newMACAddrStr, &macAddr) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    return SetMACAddr(socketFd, interfaceName, macAddr);
}

int PacketCraft::EnablePortForwarding()
{
    int status{};
    status = system("echo 1 > /proc/sys/net/ipv4/ip_forward");

    if(status != 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "system() failed!");
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
        // LOG_ERROR(APPLICATION_ERROR, "system() failed!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

uint16_t PacketCraft::CalculateChecksum(void* data, size_t sizeInBytes)
{
    uint16_t* dataPtr16 = (uint16_t*)data;
    uint32_t sum = 0;

    while(sizeInBytes > 1)  
    {
        sum += *dataPtr16++;
        sizeInBytes -= 2;
    }

    if(sizeInBytes > 0)
        sum += *(uint8_t*)dataPtr16;

    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~(uint16_t)sum;
}

bool32 PacketCraft::VerifyChecksum(void* data, size_t sizeInBytes)
{
    uint16_t* dataPtr16 = (uint16_t*)data;
    uint32_t sum = 0;
    while(sizeInBytes > 1)  
    {
        sum += *dataPtr16++;
        sizeInBytes -= 2;
    }

    if(sizeInBytes > 0)
        sum += *(uint8_t*)dataPtr16;

    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    if((uint16_t)sum == 0xffff)
        return TRUE;
    else
        return FALSE;
}

/*
uint16_t PacketCraft::CalculateIPv4Checksum(void* ipv4Header, size_t ipv4HeaderAndOptionsSizeInBytes)
{
    uint16_t* header16 = (uint16_t*)ipv4Header;
    uint32_t sum = 0;
    while(ipv4HeaderAndOptionsSizeInBytes > 1)  
    {
        sum += *header16++;
        ipv4HeaderAndOptionsSizeInBytes -= 2;
    }

    if(ipv4HeaderAndOptionsSizeInBytes > 0)
        sum += *(uint8_t*)header16;

    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~(uint16_t)sum;
}

bool32 PacketCraft::VerifyIPv4Checksum(void* ipv4Header, size_t ipv4HeaderAndOptionsSizeInBytes)
{
    uint16_t* header16 = (uint16_t*)ipv4Header;
    uint32_t sum = 0;
    while(ipv4HeaderAndOptionsSizeInBytes > 1)  
    {
        sum += *header16++;
        ipv4HeaderAndOptionsSizeInBytes -= 2;
    }

    if(ipv4HeaderAndOptionsSizeInBytes > 0)
        sum += *(uint8_t*)header16;

    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    if((uint16_t)sum == 0xffff)
        return TRUE;
    else
        return FALSE;
}

uint16_t PacketCraft::CalculateICMPv4Checksum(void* icmpv4Header, size_t icmpvHeaderAndDataSizeInBytes)
{
    return CalculateIPv4Checksum(icmpv4Header, icmpvHeaderAndDataSizeInBytes);
}

bool32 PacketCraft::VerifyICMPv4Checksum(void* icmpv4Header, size_t icmpvHeaderAndDataSizeInBytes)
{
    return VerifyIPv4Checksum(icmpv4Header, icmpvHeaderAndDataSizeInBytes);
}

uint16_t PacketCraft::CalculateICMPv6Checksum(void* ipv6Header, void* icmpv6Header, size_t icmpv6HeaderAndDataSizeInBytes)
{
    // construct a pseudoheader
    ICMPv6PseudoHeader pseudoHeader;
    IPv6Header* ipv6HeaderPtr = (IPv6Header*)ipv6Header;
    memcpy(&pseudoHeader.ip6_src, &ipv6HeaderPtr->ip6_src, IPV6_ALEN);
    memcpy(&pseudoHeader.ip6_dst, &ipv6HeaderPtr->ip6_dst, IPV6_ALEN);
    pseudoHeader.payloadLength = ipv6HeaderPtr->ip6_ctlun.ip6_un1.ip6_un1_plen;
    memset(pseudoHeader.zeroes, 0, 3);
    pseudoHeader.nextHeader = ipv6HeaderPtr->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    size_t dataSize = sizeof(pseudoHeader) + icmpv6HeaderAndDataSizeInBytes;
    uint8_t* data = (uint8_t*)malloc(dataSize);
    memcpy(data, &pseudoHeader, sizeof(pseudoHeader));
    memcpy(data + sizeof(pseudoHeader), icmpv6Header, icmpv6HeaderAndDataSizeInBytes);

    uint16_t sum = CalculateIPv4Checksum(data, dataSize);
    free(data);
    return sum;
}

bool32 PacketCraft::VerifyICMPv6Checksum(void* ipv6Header, void* icmpv6Header, size_t icmpv6HeaderAndDataSizeInBytes)
{
    // construct a pseudoheader
    ICMPv6PseudoHeader pseudoHeader;
    IPv6Header* ipv6HeaderPtr = (IPv6Header*)ipv6Header;
    memcpy(&pseudoHeader.ip6_src, &ipv6HeaderPtr->ip6_src, IPV6_ALEN);
    memcpy(&pseudoHeader.ip6_dst, &ipv6HeaderPtr->ip6_dst, IPV6_ALEN);
    pseudoHeader.payloadLength = ipv6HeaderPtr->ip6_ctlun.ip6_un1.ip6_un1_plen;
    memset(pseudoHeader.zeroes, 0, 3);
    pseudoHeader.nextHeader = ipv6HeaderPtr->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    size_t dataSize = sizeof(pseudoHeader) + icmpv6HeaderAndDataSizeInBytes;
    uint8_t* data = (uint8_t*)malloc(dataSize);
    memcpy(data, &pseudoHeader, sizeof(pseudoHeader));
    memcpy(data + sizeof(pseudoHeader), icmpv6Header, icmpv6HeaderAndDataSizeInBytes);

    bool32 result = VerifyICMPv4Checksum(data, dataSize);
    free(data);
    return result;
}

uint16_t PacketCraft::CalculateTCPv4Checksum(void* ipv4Header, void* tcpHeader, size_t tcpHeaderAndDataSizeInBytes)
{
    // construct a pseudoheader
    TCPv4PseudoHeader pseudoHeader;
    IPv4Header* ipv4HeaderPtr = (IPv4Header*)ipv4Header;
    memcpy(&pseudoHeader.ip_src, &ipv4HeaderPtr->ip_src, IPV4_ALEN);
    memcpy(&pseudoHeader.ip_dst, &ipv4HeaderPtr->ip_dst, IPV4_ALEN);
    pseudoHeader.proto = ipv4HeaderPtr->ip_p;
    pseudoHeader.zeroes = 0;
    pseudoHeader.tcpLen = tcpHeaderAndDataSizeInBytes;

    size_t totalSize = sizeof(pseudoHeader) + tcpHeaderAndDataSizeInBytes;
    uint8_t* data = (uint8_t*)malloc(totalSize);
    memcpy(data, &pseudoHeader, sizeof(pseudoHeader));
    memcpy(data + sizeof(pseudoHeader), tcpHeader, tcpHeaderAndDataSizeInBytes);

    uint16_t sum = CalculateIPv4Checksum(data, totalSize);
    free(data);
    return sum;
}

bool32 PacketCraft::VerifyTCPv4Checksum(void* ipv4Header, void* tcpHeader, size_t tcpHeaderAndDataSizeInBytes)
{
    // construct a pseudoheader
    TCPv4PseudoHeader pseudoHeader;
    IPv4Header* ipv4HeaderPtr = (IPv4Header*)ipv4Header;
    memcpy(&pseudoHeader.ip_src, &ipv4HeaderPtr->ip_src, IPV4_ALEN);
    memcpy(&pseudoHeader.ip_dst, &ipv4HeaderPtr->ip_dst, IPV4_ALEN);
    pseudoHeader.proto = ipv4HeaderPtr->ip_p;
    pseudoHeader.zeroes = 0;
    pseudoHeader.tcpLen = tcpHeaderAndDataSizeInBytes;

    size_t totalSize = sizeof(pseudoHeader) + tcpHeaderAndDataSizeInBytes;
    uint8_t* data = (uint8_t*)malloc(totalSize);
    memcpy(data, &pseudoHeader, sizeof(pseudoHeader));
    memcpy(data + sizeof(pseudoHeader), tcpHeader, tcpHeaderAndDataSizeInBytes);

    bool32 result = VerifyICMPv4Checksum(data, totalSize);
    free(data);
    return result;
}
*/

int PacketCraft::PrintIPAddr(const sockaddr_storage& addr, const char* prefix, const char* suffix)
{
    int result{APPLICATION_ERROR};

    if(addr.ss_family == AF_INET)
        result = PrintIPAddr(*(sockaddr_in*)&addr, prefix, suffix);
    else if(addr.ss_family == AF_INET6)
        result = PrintIPAddr(*(sockaddr_in6*)&addr, prefix, suffix);
    else
    {
        // LOG_ERROR(APPLICATION_ERROR, "Unknown address family!");
    }

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
        // LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
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
        // LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
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
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::PrintEthernetLayer(EthHeader* ethHeader)
{
    char ethDstAddr[ETH_ADDR_STR_LEN]{};    /* destination eth addr	*/
    char ethSrcAddr[ETH_ADDR_STR_LEN]{};    /* source ether addr	*/

    if(ether_ntoa_r((ether_addr*)ethHeader->ether_dhost, ethDstAddr) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r((ether_addr*)ethHeader->ether_shost, ethSrcAddr) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    std::cout
        << "[ETHERNET]:\n"
        << "destination: "    << ethDstAddr << "\n"
        << "source: "         << ethSrcAddr << "\n"
        << "type: 0x"         << std::hex << ntohs(ethHeader->ether_type) << "(" << std::dec << ntohs(ethHeader->ether_type) << ")\n"
        << " . . . . . . . . . . " << std::endl;

    return NO_ERROR;
}

int PacketCraft::PrintARPLayer(ARPHeader* arpHeader)
{
    char ar_sha[ETH_ADDR_STR_LEN]{};    /* Sender hardware address.  */
    char ar_sip[INET_ADDRSTRLEN]{};     /* Sender IP address.  */
    char ar_tha[ETH_ADDR_STR_LEN]{};    /* Target hardware address.  */
    char ar_tip[INET_ADDRSTRLEN]{};     /* Target IP address.  */

    if(inet_ntop(AF_INET, arpHeader->ar_sip, ar_sip, INET_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    if(inet_ntop(AF_INET, arpHeader->ar_tip, ar_tip, INET_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r((ether_addr*)arpHeader->ar_sha, ar_sha) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r((ether_addr*)arpHeader->ar_tha, ar_tha) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    std::cout
        << "[ARP]:\n"
        << "hardware type: "        << ntohs(arpHeader->ar_hrd) << "\n"
        << "protocol type: "        << ntohs(arpHeader->ar_pro) << "\n"
        << "hardware size: "        << (uint16_t)arpHeader->ar_hln << "\n"
        << "protocol size: "        << (uint16_t)arpHeader->ar_pln << "\n"
        << "op code: "              << ntohs(arpHeader->ar_op) << " (" << (ntohs(arpHeader->ar_op) == 1 ? "request" : "reply") << ")\n"
        << "sender MAC address: "   << ar_sha << "\n"
        << "sender IP address: "    << ar_sip << "\n"
        << "target MAC address: "   << ar_tha << "\n"
        << "target IP address: "    << ar_tip << "\n"
        << " . . . . . . . . . . " << std::endl;

    return NO_ERROR;
}

int PacketCraft::PrintIPv4Layer(IPv4Header* ipv4Header)
{
    char srcIPStr[INET_ADDRSTRLEN]{};
    char dstIPStr[INET_ADDRSTRLEN]{};

    if(inet_ntop(AF_INET, &ipv4Header->ip_src, srcIPStr, INET_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    if(inet_ntop(AF_INET, &ipv4Header->ip_dst, dstIPStr, INET_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    const char* ipv4ChecksumVerified = VerifyChecksum(ipv4Header, ipv4Header->ip_hl) == TRUE ? "verified" : "unverified";
    bool32 flagDFSet = ((ntohs(ipv4Header->ip_off)) & (IP_DF)) != 0;
    bool32 flagMFSet = ((ntohs(ipv4Header->ip_off)) & (IP_MF)) != 0;

    // TODO: test
    bool32 hasIpv4Options = ipv4Header->ip_hl > 5 ? TRUE : FALSE;
    uint32_t ipv4OptionsSize = ipv4Header->ip_hl - 5;

    std::cout
        << "[IPv4]:\n"
        << "ip version: "     << ipv4Header->ip_v << "\n"
        << "header length: "  << ipv4Header->ip_hl << "\n"
        << "ToS: 0x"          << std::hex << (uint16_t)ipv4Header->ip_tos << std::dec << "\n"  // TODO: print DSCP and ECN separately
        << "total length: "   << ntohs(ipv4Header->ip_len) << "\n"
        << "identification: " << ntohs(ipv4Header->ip_id) << "\n"
        << "flags: 0x"        << std::hex << ntohs(ipv4Header->ip_off) << std::dec << "(" << ntohs(ipv4Header->ip_off) << ")\n"
        << "\t bit 1(DF): "   << flagDFSet << " bit 2(MF): " << flagMFSet << "\n"
        << "time to live: "   << (uint16_t)ipv4Header->ip_ttl << "\n"
        << "protocol: "       << (uint16_t)ipv4Header->ip_p << "\n"
        << "checksum: "       << ntohs(ipv4Header->ip_sum) << "(" << ipv4ChecksumVerified << ")" << "\n"
        << "source: "         << srcIPStr << " " << "destination: " << dstIPStr;

    if(hasIpv4Options == TRUE)
    {
        int newLineAt = 7;
        for(unsigned int i = 0; i < ipv4OptionsSize; ++i)
        {
            if(i == 0)
                std::cout << "\noptions:\n";

            std::cout << std::hex << ipv4Header->options[i];
            if(i % newLineAt == 0)
                std::cout << "\n";
        }
    }

    std::cout << std::dec << "\n . . . . . . . . . . " << std::endl;

    return NO_ERROR;
}

int PacketCraft::PrintIPv6Layer(IPv6Header* ipv6Header)
{
    char srcIPStr[INET6_ADDRSTRLEN]{};
    char dstIPStr[INET6_ADDRSTRLEN]{};

    if(inet_ntop(AF_INET6, &ipv6Header->ip6_src, srcIPStr, INET6_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    if(inet_ntop(AF_INET6, &ipv6Header->ip6_dst, dstIPStr, INET6_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    uint32_t version =      ((ntohl(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xf0000000) >> 28);
    uint32_t trafficClass = ((ntohl(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20);   // NOTE: not tested
    uint32_t dscp =         ((ntohl(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0fc00000) >> 22);   // NOTE: not tested
    uint32_t ecn =          ((ntohl(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x00300000) >> 20);   // NOTE: not tested
    uint32_t flowLabel =    ntohl(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000fffff;

    std::cout
        << "[IPv6]:\n"
        << "version: "          << version  << "\n"
        << "traffic class: "    << std::hex << "0x" << trafficClass << std::dec << "(dscp: " << dscp << " ecn: " << ecn << ")" << "\n"
        << "flow label: "       << std::hex << "0x" << flowLabel    << std::dec << "\n"
        << "payload length: "   << ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen) << "\n"
        << "next header: "      << (uint16_t)ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt << "\n"
        << "hop limit: "        << (uint16_t)ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_hlim << "\n"
        << "source: "           << srcIPStr << " " << "destination: " << dstIPStr;

    std::cout << std::dec << "\n . . . . . . . . . . " << std::endl;

    return NO_ERROR;
}

int PacketCraft::PrintICMPv4Layer(ICMPv4Header* icmpv4Header, size_t dataSize)
{
    const char* icmpv4ChecksumVerified = VerifyChecksum(icmpv4Header, sizeof(ICMPv4Header) + dataSize) == TRUE ? "verified" : "unverified";

    std::cout
        << "[ICMPv4]:\n"
        << "type: "           << (uint16_t)icmpv4Header->type << "\n"
        << "code: "           << (uint16_t)icmpv4Header->code << "\n"
        << "checksum: "       << ntohs(icmpv4Header->checksum) << "(" << icmpv4ChecksumVerified << ")" << "\n"
        << "id: "             << ntohs(icmpv4Header->un.echo.id) << " sequence: " << ntohs(icmpv4Header->un.echo.sequence);

    int newLineAt = 15;
    unsigned char* dataPtr = (unsigned char*)icmpv4Header->data;

    for(unsigned int i = 0; i < dataSize; ++i)
    {
        if(i == 0)
            std::cout << "\ndata:\n";

        std::cout << *dataPtr++;
        if(i % newLineAt == 0)
        {
            std::cout << "\n";
        }
    }

    std::cout << "\n . . . . . . . . . . " << std::endl;

    return NO_ERROR;
}

int PacketCraft::PrintICMPv6Layer(ICMPv6Header* icmpv6Header, size_t dataSize)
{
    std::cout
        << "[ICMPv6]:\n"
        << "type: "     << (uint16_t)icmpv6Header->icmp6_type << "\n"
        << "code: "     << (uint16_t)icmpv6Header->icmp6_code << "\n"
        << "checksum: " << ntohs(icmpv6Header->icmp6_cksum);

    int newLineAt = 15;
    unsigned char* dataPtr = (unsigned char*)icmpv6Header->data;

    for(unsigned int i = 0; i < dataSize; ++i)
    {
        if(i == 0)
            std::cout << "\ndata:\n";

        std::cout << *dataPtr++;
        if(i % newLineAt == 0)
        {
            std::cout << "\n";
        }
    }

    std::cout << "\n . . . . . . . . . . " << std::endl;

    return NO_ERROR;
}

int PacketCraft::PrintTCPLayer(TCPHeader* tcpHeader, size_t dataSize)
{
    std::cout 
        << "[TCP]:\n"
        << "source port: "              << ntohs(tcpHeader->source) << " destination port: " << ntohs(tcpHeader->dest) << "\n"
        << "sequence number: "          << ntohl(tcpHeader->seq) << "\n"
        << "acknowledgement number: "   << ntohl(tcpHeader->ack_seq) << "\n"
        << "data offset: "              << tcpHeader->doff << "\n"

        << "flags 0x" << std::hex << (uint16_t)tcpHeader->th_flags << std::dec << ": \n"                    
        << "FIN(" << tcpHeader->fin << "), " << "SYN(" << tcpHeader->syn << "), " 
        << "RST(" << tcpHeader->rst << "), " << "PSH(" << tcpHeader->psh << "), " 
        << "ACK(" << tcpHeader->ack << "), " << "URG(" << tcpHeader->urg << ")\n"

        << "window size: "              << ntohs(tcpHeader->window) << "\n"
        << "checksum: "                 << ntohs(tcpHeader->check) << "\n"
        << "urgent pointer: "           << ntohs(tcpHeader->urg_ptr) << "\n";

    uint8_t* optionsPtr = tcpHeader->optionsAndData;
    int newLineAt = 15;

    // options field is present, TODO: verify!
    if(tcpHeader->doff > 5)
    {
        uint16_t optLen = (uint16_t)*optionsPtr + 1;

        std::cout << "options:\n" << "option kind: " << (uint16_t)*optionsPtr << "\n";
        ++optionsPtr;
        std::cout << "option length: "    << (uint16_t)*optionsPtr << "\n";
        ++optionsPtr;

        for(int i = 0; i < optLen - 2; ++i)
        {
            if(i == 0)
                std::cout << "option data:\n";

            std::cout << (unsigned char)*optionsPtr;
            ++optionsPtr;

            if(i % newLineAt == 0)
            {
                std::cout << "\n";
            }
        }
    }

    // print data
    for(unsigned int i = 0; i < dataSize; ++i)
    {
        if(i == 0)
            std::cout << "\ndata:\n";

        std::cout << (unsigned char)*optionsPtr;
        ++optionsPtr;

        if(i % newLineAt == 0)
        {
            std::cout << "\n";
        }
    }

    std::cout << "\n . . . . . . . . . . " << std::endl;

    return NO_ERROR;
}

void PacketCraft::PrintLayerTypeStr(const uint32_t layerType, const char* prefix, const char* suffix)
{
    std::cout << prefix << networkProtocols.at(layerType) << suffix << std::flush;
}