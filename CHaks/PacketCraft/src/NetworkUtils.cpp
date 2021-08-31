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

uint32_t PacketCraft::NetworkProtoToPacketCraftProto(unsigned short networkProtocol)
{
    switch(networkProtocol)
    {
        case ETH_P_ARP:
            return PC_ARP;
        case ETH_P_IP:
            return PC_IPV4;
        case ETH_P_IPV6:
            return PC_IPV6;
        case IPPROTO_ICMP:
            return PC_ICMPV4;
        case IPPROTO_ICMPV6:
            return PC_ICMPV6;
        case IPPROTO_TCP:
            return PC_TCP;
        case IPPROTO_UDP:
            return PC_UDP;
        default:
            return PC_NONE;
    }
}

uint32_t PacketCraft::GetTCPDataProtocol(TCPHeader* tcpHeader, size_t dataSize)
{
    if(dataSize <= 0)
        return PC_NONE;

    // check for HTTP
    char* buffer = (char*)malloc(dataSize);
    CopyUntil(buffer, dataSize, (char*)tcpHeader + (tcpHeader->doff * 32 / 8), '\n');
    int res = FindInStr(buffer, "HTTP");

    if(res != -1)
    {
        free(buffer);
        return PC_HTTP;
    }
    /////////////////

    free(buffer);
    return PC_NONE;
}

uint32_t PacketCraft::GetUDPDataProtocol(UDPHeader* udpHeader)
{
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

uint32_t PacketCraft::CalculateICMPv4DataSize(IPv4Header* ipv4Header, ICMPv4Header* icmpv4Header)
{
    return (ntohs(ipv4Header->ip_len) - (ipv4Header->ip_hl * 32 / 8)) - sizeof(ICMPv4Header);
}

uint32_t PacketCraft::CalculateICMPv6DataSize(IPv6Header* ipv6Header, ICMPv6Header* icmpv6Header)
{
    // TODO: take ipv6 extension headers into account!!!
    if(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6)
    {
        return (ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen)) - sizeof(ICMPv6Header);
    }

    return 0;
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

// old checksum functions
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
    char* buffer = (char*)malloc(PC_ETH_MAX_STR_SIZE);
    if(ConvertEthLayerToString(buffer, PC_ETH_MAX_STR_SIZE, ethHeader) == APPLICATION_ERROR)
    {
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "ConvertEthLayerToString() error!");
        return APPLICATION_ERROR;
    }

    std::cout << buffer << std::flush;

    free(buffer);

    return NO_ERROR;
}

int PacketCraft::PrintARPLayer(ARPHeader* arpHeader)
{
    char* buffer = (char*)malloc(PC_ARP_MAX_STR_SIZE);
    if(ConvertARPLayerToString(buffer, PC_ARP_MAX_STR_SIZE, arpHeader) == APPLICATION_ERROR)
    {
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "ConvertEthLayerToString() error!");
        return APPLICATION_ERROR;
    }

    std::cout << buffer << std::flush;

    free(buffer);

    return NO_ERROR;
}

int PacketCraft::PrintIPv4Layer(IPv4Header* ipv4Header)
{
    char* buffer = (char*)malloc(PC_IPV4_MAX_STR_SIZE);
    if(ConvertIPv4LayerToString(buffer, PC_IPV4_MAX_STR_SIZE, ipv4Header) == APPLICATION_ERROR)
    {
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "ConvertEthLayerToString() error!");
        return APPLICATION_ERROR;
    }

    std::cout << buffer << std::flush;

    free(buffer);

    return NO_ERROR;
}

int PacketCraft::PrintIPv6Layer(IPv6Header* ipv6Header)
{
    char* buffer = (char*)malloc(PC_IPV6_MAX_STR_SIZE);
    if(ConvertIPv6LayerToString(buffer, PC_IPV6_MAX_STR_SIZE, ipv6Header) == APPLICATION_ERROR)
    {
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "ConvertEthLayerToString() error!");
        return APPLICATION_ERROR;
    }

    std::cout << buffer << std::flush;

    free(buffer);

    return NO_ERROR;
}

int PacketCraft::PrintICMPv4Layer(ICMPv4Header* icmpv4Header, size_t dataSize)
{
    char* buffer = (char*)malloc(PC_ICMPV4_MAX_STR_SIZE);
    if(ConvertICMPv4LayerToString(buffer, PC_ICMPV4_MAX_STR_SIZE, icmpv4Header, dataSize)== APPLICATION_ERROR)
    {
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "ConvertEthLayerToString() error!");
        return APPLICATION_ERROR;
    }

    std::cout << buffer << std::flush;

    free(buffer);

    return NO_ERROR;
}

int PacketCraft::PrintICMPv6Layer(ICMPv6Header* icmpv6Header, size_t dataSize)
{
    char* buffer = (char*)malloc(PC_ICMPV6_MAX_STR_SIZE);
    if(ConvertICMPv6LayerToString(buffer, PC_ICMPV6_MAX_STR_SIZE, icmpv6Header, dataSize)== APPLICATION_ERROR)
    {
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "ConvertEthLayerToString() error!");
        return APPLICATION_ERROR;
    }

    std::cout << buffer << std::flush;

    free(buffer);

    return NO_ERROR;
}

int PacketCraft::PrintTCPLayer(TCPHeader* tcpHeader, size_t dataSize)
{
    char* buffer = (char*)malloc(PC_TCP_MAX_STR_SIZE);
    if(ConvertTCPLayerToString(buffer, PC_TCP_MAX_STR_SIZE, tcpHeader, dataSize) == APPLICATION_ERROR)
    {
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "ConvertEthLayerToString() error!");
        return APPLICATION_ERROR;
    }

    std::cout << buffer << std::flush;

    free(buffer);

    return NO_ERROR;
}

int PacketCraft::PrintUDPLayer(UDPHeader* udpLayer)
{
    char* buffer = (char*)malloc(PC_UDP_MAX_STR_SIZE);
    if(ConvertUDPLayerToString(buffer, PC_UDP_MAX_STR_SIZE, udpLayer) == APPLICATION_ERROR)
    {
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "ConvertUDPLayerToString() error!");
        return APPLICATION_ERROR;
    }

    std::cout << buffer << std::flush;

    free(buffer);

    return NO_ERROR;
}

void PacketCraft::PrintLayerTypeStr(const uint32_t layerType, const char* prefix, const char* suffix)
{
    std::cout << prefix << networkProtocols.at(layerType) << suffix << std::flush;
}

int PacketCraft::ConvertEthLayerToString(char* buffer, size_t bufferSize, EthHeader* ethHeader)
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

    int res = snprintf(buffer, bufferSize, "[ETHERNET]:\ndestination: %s\nsource: %s\ntype: 0x%x(%u)\n. . . . . . . . . . \n", 
        ethDstAddr, ethSrcAddr, ntohs(ethHeader->ether_type), ntohs(ethHeader->ether_type));
    
    if(res > -1 && res < (int)bufferSize)
    {
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "snprintf() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::ConvertARPLayerToString(char* buffer, size_t bufferSize, ARPHeader* arpHeader)
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

    int res = snprintf(buffer, bufferSize, "[ARP]:\nhardware type: %u\nprotocol type: %u\nhardware size: %u\nprotocol size: %u\nop code: %u(%s)\n\
source MAC: %s\nsource IP: %s\ndestination MAC: %s\ndestination IP: %s\n . . . . . . . . . . \n", ntohs(arpHeader->ar_hrd), ntohs(arpHeader->ar_pro), 
(uint16_t)arpHeader->ar_hln, (uint16_t)arpHeader->ar_pln, ntohs(arpHeader->ar_op), 
(ntohs(arpHeader->ar_op) == 1 ? "request" : "reply"), ar_sha, ar_sip, ar_tha, ar_tip);
    
    if(res > -1 && res < (int)bufferSize)
    {
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "snprintf() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::ConvertIPv4LayerToString(char* buffer, size_t bufferSize, IPv4Header* ipv4Header)
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

    // TODO: test/improve options printing
    bool32 hasIpv4Options = ipv4Header->ip_hl > 5 ? TRUE : FALSE;
    uint32_t ipv4OptionsSize = ipv4Header->ip_hl - 5;

    char options[PC_IPV4_MAX_OPTIONS_STR_SIZE]{};
    char* optionsPtr = options;
    uint32_t newLineAt = 15;

    for(unsigned int i = 0; i < ipv4OptionsSize; ++i)
    {
        int len = snprintf(NULL, 0, "%x ", (uint16_t)ipv4Header->options[i]);
        snprintf(optionsPtr, len + 1, "%x ", (uint16_t)ipv4Header->options[i]);
        optionsPtr += len;

        if(i != 0 && i % newLineAt == 0)
        {
            *optionsPtr++ = '\n';
        }
    }

    *optionsPtr = '\0';

    int res = snprintf(buffer, bufferSize, "[IPv4]:\nip version: %u\nheader length: %u\nToS: 0x%x\ntotal length: %u\nidentification: %u\n\
flags: 0x%x(%u)\n\tbit 1(DF): %d bit 2(MF): %d\ntime to live: %u\nprotocol: %u\nchecksum: %u, 0x%x(%s)\nsource: %s\ndestination: %s\n\n\
[options](%u bytes):\n%s\n . . . . . . . . . . \n",
ipv4Header->ip_v, ipv4Header->ip_hl, (uint16_t)ipv4Header->ip_tos, ntohs(ipv4Header->ip_len), ntohs(ipv4Header->ip_id), ntohs(ipv4Header->ip_off), 
ntohs(ipv4Header->ip_off), flagDFSet, flagMFSet, (uint16_t)ipv4Header->ip_ttl, (uint16_t)ipv4Header->ip_p, ntohs(ipv4Header->ip_sum), ntohs(ipv4Header->ip_sum),
ipv4ChecksumVerified, srcIPStr, dstIPStr, (uint32_t)ipv4OptionsSize, (hasIpv4Options == TRUE ? options : "NONE FOUND"));

    if(res > -1 && res < (int)bufferSize)
    {
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "snprintf() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::ConvertIPv6LayerToString(char* buffer, size_t bufferSize, IPv6Header* ipv6Header)
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

    int res = snprintf(buffer, bufferSize, "[IPv6]:\nversion: %u\ntraffic class: 0x%x(dscp: %u ecn: %u)\nflow label: 0x%x\npayload length: %u\n\
next header: %u\nhop limit: %u\nsource: %s\ndestination: %s\n . . . . . . . . . . \n", version, trafficClass, dscp, ecn, flowLabel,
ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen), (uint16_t)ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt, (uint16_t)ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_hlim,
srcIPStr, dstIPStr);

    if(res > -1 && res < (int)bufferSize)
    {
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "snprintf() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::ConvertICMPv4LayerToString(char* buffer, size_t bufferSize, ICMPv4Header* icmpv4Header, size_t icmpv4DataSize)
{
    const char* icmpv4ChecksumVerified = VerifyChecksum(icmpv4Header, sizeof(ICMPv4Header) + icmpv4DataSize) == TRUE ? "verified" : "unverified";

    char data[PC_ICMPV4_MAX_DATA_STR_SIZE]{};
    char* dataPtr = data;
    uint32_t newLineAt = 15;

    // TODO: test/improve data printing
    for(unsigned int i = 0; i < icmpv4DataSize; ++i)
    {
        int len = snprintf(NULL, 0, "%x ", (uint16_t)icmpv4Header->data[i]);
        snprintf(dataPtr, len + 1, "%x ", (uint16_t)icmpv4Header->data[i]);
        dataPtr += len;

        if(i != 0 && i % newLineAt == 0)
        {
            *dataPtr++ = '\n';
        }
    }

    *dataPtr = '\0';

    int res = snprintf(buffer, bufferSize, "[ICMPv4]:\ntype: %u\ncode: %u\nchecksum: %u(%s)\nid: %u sequence: %u\n\n[data](%u bytes):\n%s\n . . . . . . . . . . \n",
    (uint16_t)icmpv4Header->type, (uint16_t)icmpv4Header->code, ntohs(icmpv4Header->checksum), icmpv4ChecksumVerified, ntohs(icmpv4Header->un.echo.id),
    ntohs(icmpv4Header->un.echo.sequence), (uint32_t)icmpv4DataSize, (icmpv4DataSize > 0 ? data : "NONE FOUND"));

    if(res > -1 && res < (int)bufferSize)
    {
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "snprintf() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::ConvertICMPv6LayerToString(char* buffer, size_t bufferSize, ICMPv6Header* icmpv6Header, size_t icmpv6DataSize)
{
    char data[PC_ICMPV6_MAX_DATA_STR_SIZE]{};
    char* dataPtr = data;
    uint32_t newLineAt = 15;

    // TODO: test/improve data printing
    for(unsigned int i = 0; i < icmpv6DataSize; ++i)
    {
        int len = snprintf(NULL, 0, "%x ", (uint16_t)icmpv6Header->data[i]);
        snprintf(dataPtr, len + 1, "%x ", (uint16_t)icmpv6Header->data[i]);
        dataPtr += len;

        if(i != 0 && i % newLineAt == 0)
        {
            *dataPtr++ = '\n';
        }
    }

    *dataPtr = '\0';

    int res = snprintf(buffer, bufferSize, "[ICMPv6]:\ntype: %u\ncode: %u\nchecksum: %u\n\n[data](%u bytes):\n%s\n . . . . . . . . . . \n",
    (uint16_t)icmpv6Header->icmp6_type, (uint16_t)icmpv6Header->icmp6_code, ntohs(icmpv6Header->icmp6_cksum), (uint32_t)icmpv6DataSize, 
    (icmpv6DataSize > 0 ? data : "NONE FOUND"));

    if(res > -1 && res < (int)bufferSize)
    {
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "snprintf() error!");
        return APPLICATION_ERROR;
    }
}

int PacketCraft::ConvertTCPLayerToString(char* buffer, size_t bufferSize, TCPHeader* tcpHeader, size_t tcpDataSize)
{
    char options[PC_TCP_MAX_OPTIONS_STR_SIZE]{};
    char* optionsStrPtr = options;

    uint8_t* optionsAndDataPtr = tcpHeader->optionsAndData;
    int newLineAt = 15;

    bool32 hasOptions = (tcpHeader->doff > 5) ? TRUE : FALSE;
    uint32_t optionsTotalLength = 0;

    if(hasOptions == TRUE && tcpHeader->doff != 0)
        optionsTotalLength = (tcpHeader->doff * 32 / 8) - sizeof(TCPHeader);

    if(hasOptions)
    {
        uint16_t optionKind = (uint16_t)*optionsAndDataPtr++;
        uint16_t optionLength = (uint16_t)*optionsAndDataPtr++;

        int len = snprintf(NULL, 0, "option kind: %u\noption length: %u\n", optionKind, optionLength);
        snprintf(optionsStrPtr, len + 1, "option kind: %u\noption length: %u\n", optionKind, optionLength);
        optionsStrPtr += len;

        for(unsigned int i = 0; i < optionsTotalLength - 2; ++i)
        {
            len = snprintf(NULL, 0, "%x\t", (uint16_t)*optionsAndDataPtr);
            snprintf(optionsStrPtr, len + 1, "%x\t", (uint16_t)*optionsAndDataPtr);
            ++optionsAndDataPtr;
            optionsStrPtr += len;

            if(i != 0 && i % newLineAt == 0)
            {
                *optionsStrPtr++ = '\n';
            }
        }

        *optionsStrPtr = '\0';
    }

    // TODO: is there a way to do this with a single buffer?
    char data[PC_TCP_MAX_DATA_STR_SIZE]{};
    char dataAsChars[PC_TCP_MAX_DATA_STR_SIZE]{};
    char* dataPtr = data;
    char* dataAsCharsPtr = dataAsChars;

    for(unsigned int i = 0; i < tcpDataSize; ++i)
    {
        int dataLen = snprintf(NULL, 0, "%x\t", (uint16_t)*optionsAndDataPtr);
        snprintf(dataPtr, dataLen + 1, "%x\t", (uint16_t)*optionsAndDataPtr);

        int dataAsCharsLen = snprintf(NULL, 0, "%c ", (unsigned char)*optionsAndDataPtr);
        snprintf(dataAsCharsPtr, dataAsCharsLen + 1, "%c ", (unsigned char)*optionsAndDataPtr);

        ++optionsAndDataPtr;
        dataPtr += dataLen;
        dataAsCharsPtr += dataAsCharsLen;

        if(i != 0 && i % newLineAt == 0)
        {
            *dataPtr++ = '\n';
        }
    }

    *dataPtr = '\0';
    *dataAsCharsPtr = '\0';

    int res = snprintf(buffer, bufferSize, "[TCP]:\nsource port: %u destination port: %u\nsequence number: %u\nacknowledgement number: %u\n\
data offset: %u\nflags: 0x%x\nFIN(%u), SYN(%u), RST(%u), PSH(%u), ACK(%u), URG(%u)\nwindow size: %u\nchecksum: %u\nurgent pointer: %u\n\n\
[options](%u bytes):\n%s\n\n[data]:\n%s\n\n[data as chars]:\n%s\n . . . . . . . . . . \n", ntohs(tcpHeader->source), ntohs(tcpHeader->dest), ntohl(tcpHeader->seq), 
ntohl(tcpHeader->ack_seq), tcpHeader->doff, (uint16_t)tcpHeader->th_flags, tcpHeader->fin, tcpHeader->syn, tcpHeader->rst, tcpHeader->psh, tcpHeader->ack, 
tcpHeader->urg, ntohs(tcpHeader->window), ntohs(tcpHeader->check), ntohs(tcpHeader->urg_ptr), optionsTotalLength, 
(hasOptions == TRUE ? options : "NONE FOUND\n"), (tcpDataSize > 0 ? data : "NONE FOUND\n"), (tcpDataSize > 0 ? dataAsChars : "NONE FOUND"));

    if(res > -1 && res < (int)bufferSize)
    {
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "snprintf() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

int PacketCraft::ConvertUDPLayerToString(char* buffer, size_t bufferSize, UDPHeader* udpHeader)
{
    uint32_t dataSize = udpHeader->len - sizeof(UDPHeader);
    char data[PC_UDP_MAX_DATA_STR_SIZE]{};
    char* dataPtr = data;
    uint32_t newLineAt = 15;

    bool32 hasData = dataSize > 0 ? TRUE : FALSE;

    for(unsigned int i = 0; i < dataSize; ++i)
    {
        int len = snprintf(NULL, 0, "%x ", (uint16_t)udpHeader->data[i]);
        snprintf(dataPtr, len + 1, "%x ", (uint16_t)udpHeader->data[i]);
        dataPtr += len;

        
        if(i != 0 && i % newLineAt == 0)
        {
            *dataPtr++ = '\n';
        }
    }

    *dataPtr = '\0';

    int res = snprintf(buffer, bufferSize, "[UDP]:\nsource port: %u\ndestination port: %u\nlength: %u\nchecksum: %u, %x\n\n[data](%u bytes):\n%s\n . . . . . . . . . . \n", 
    ntohs(udpHeader->source), ntohs(udpHeader->dest), ntohs(udpHeader->len), ntohs(udpHeader->check), ntohs(udpHeader->check), dataSize, 
    (hasData == TRUE ? data : "NONE FOUND\n"));

    if(res > -1 && res < (int)bufferSize)
    {
        return NO_ERROR;
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "snprintf() error!");
        return APPLICATION_ERROR;
    }
}