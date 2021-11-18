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

uint32_t PacketCraft::NetworkProtoToPacketCraftProto(unsigned short networkProtocolInHostByteOrder)
{
    switch(networkProtocolInHostByteOrder)
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

// TODO: finish and test
uint32_t PacketCraft::GetTCPDataProtocol(TCPHeader* tcpHeader)
{
    // check for HTTP
    if(ntohs(tcpHeader->source) == 80 || ntohs(tcpHeader->dest) == 80)
        return PC_HTTP;

    // check for DNS
    if(ntohs(tcpHeader->source) == 53 || ntohs(tcpHeader->dest) == 53)
        return PC_DNS;

    return PC_NONE;
}

uint32_t PacketCraft::GetUDPDataProtocol(UDPHeader* udpHeader)
{
    if(ntohs(udpHeader->dest) == 53 || ntohs(udpHeader->source == 53))
        return PC_DNS;

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

// converts a dns name with labels to a domain format
int PacketCraft::DNSNameToDomain(const char* dnsName, char* domainName)
{
    while(true)
    {
        uint32_t labelLength = (uint32_t)*dnsName; // first byte is the length of the first label
        ++dnsName; // increment pointer to the start of the name.
        memcpy(domainName, dnsName, labelLength); // copy label into the domainName buffer
        dnsName += labelLength; // will now point to the next label length
        domainName += labelLength;

        // append a '.' after each label
        *domainName = '.';
        ++domainName;

        // if length of next label is 0, we have reached the end of the dnsName string.
        if((uint32_t)*dnsName == 0)
        {
            --domainName; // move pointer back because we want the last '.' character to be replaced with a '\0'
            break;
        }
    }

    *domainName = '\0';
    return NO_ERROR;
}

// converts a domain to a dns name with labels
int PacketCraft::DomainToDNSName(const char* domainName, char* dnsName)
{
    uint32_t domainNameLen = GetStrLen(domainName);
    if(domainNameLen >= FQDN_MAX_STR_LEN)
    {
        LOG_ERROR(APPLICATION_ERROR, "DomainToDNSName() error");
        return APPLICATION_ERROR;
    }

    for(unsigned int i = 0; i < domainNameLen; ++i)
    {
        int labelLength = FindInStr(domainName, "."); // find the index of the '.' char. This is also the length of the label
        if(labelLength == -1) // we are at the final label
        {
            labelLength = GetStrLen(domainName);
            *dnsName++ = labelLength;
            memcpy(dnsName, domainName, labelLength);
            dnsName += labelLength;
            *dnsName = '\0';
            break;
        }

        *dnsName++ = labelLength; // add label length to the dnsName and increment dnsName pointer
        memcpy(dnsName, domainName, labelLength); // copy label to dnsName
        dnsName += labelLength; // increment dns name pointer, it now points to the next label length
        domainName += labelLength + 1;
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
    if(ConvertTCPLayerToString(buffer, PC_TCP_MAX_STR_SIZE, tcpHeader) == APPLICATION_ERROR)
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
    uint32_t ipv4OptionsSize = (ipv4Header->ip_hl * 32 / 8) - (20); // header without options is 20 bytes

    char options[PC_IPV4_MAX_OPTIONS_STR_SIZE]{};
    char* optionsPtr = options;
    uint32_t newLineAt = 15;

    for(unsigned int i = 0; i < ipv4OptionsSize; ++i)
    {
        int len = snprintf(NULL, 0, "%x ", (uint16_t)ipv4Header->options[i]);
        snprintf(optionsPtr, len + 1, "%x ", (uint16_t)ipv4Header->options[i]); // NOTE: +1 because snprintf appends null terminating char at the end
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
        snprintf(dataPtr, len + 1, "%x ", (uint16_t)icmpv4Header->data[i]); // NOTE: +1 because snprintf appends null terminating char at the end
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
        snprintf(dataPtr, len + 1, "%x ", (uint16_t)icmpv6Header->data[i]); // NOTE: +1 because snprintf appends null terminating char at the end
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

int PacketCraft::ConvertTCPLayerToString(char* buffer, size_t bufferSize, TCPHeader* tcpHeader)
{
    char options[PC_TCP_MAX_OPTIONS_STR_SIZE]{}; // TODO: should we put this in the heap?
    char* optionsStrPtr = options;

    uint8_t* optionsPtr = tcpHeader->options;
    int newLineAt = 15;

    bool32 hasOptions = (tcpHeader->doff > 5) ? TRUE : FALSE;
    int optionsTotalLength = 0; // NOTE: changed to int for testing, TODO: change back to uint32?

    if(hasOptions == TRUE)
        optionsTotalLength = (tcpHeader->doff * 32 / 8) - sizeof(TCPHeader);

    if(hasOptions == TRUE)
    {
        uint16_t optionKind = (uint16_t)*optionsPtr++;
        uint16_t optionLength = (uint16_t)*optionsPtr++;

        int len = snprintf(NULL, 0, "option kind: %u\noption length: %u\n", optionKind, optionLength);
        snprintf(optionsStrPtr, len + 1, "option kind: %u\noption length: %u\n", optionKind, optionLength); // NOTE: +1 because snprintf appends null terminating char at the end
        optionsStrPtr += len;

        for(int i = 0; i < optionsTotalLength - 2; ++i) // NOTE: -2 because we already grapped optionKind and optionLength
        {
            len = snprintf(NULL, 0, "%x\t", (uint16_t)*optionsPtr);
            snprintf(optionsStrPtr, len + 1, "%x\t", (uint16_t)*optionsPtr);
            ++optionsPtr;
            optionsStrPtr += len;

            if(i != 0 && i % newLineAt == 0)
            {
                *optionsStrPtr++ = '\n';
            }
        }

        *optionsStrPtr = '\0';
    }

    int res = snprintf(buffer, bufferSize, "[TCP]:\nsource port: %u destination port: %u\nsequence number: %u\nacknowledgement number: %u\n\
data offset: %u\nflags(0x%x):\n\tFIN(%u), SYN(%u), RST(%u), PSH(%u), ACK(%u), URG(%u)\nwindow size: %u\nchecksum: %u\nurgent pointer: %u\n\n\
[options](%u bytes):\n%s\n . . . . . . . . . . \n", ntohs(tcpHeader->source), ntohs(tcpHeader->dest), ntohl(tcpHeader->seq), 
ntohl(tcpHeader->ack_seq), tcpHeader->doff, (uint16_t)tcpHeader->th_flags, tcpHeader->fin, tcpHeader->syn, tcpHeader->rst, tcpHeader->psh, tcpHeader->ack, 
tcpHeader->urg, ntohs(tcpHeader->window), ntohs(tcpHeader->check), ntohs(tcpHeader->urg_ptr), optionsTotalLength, 
(hasOptions == TRUE ? options : "NONE FOUND\n"));

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

int PacketCraft::ConvertUDPLayerToString(char* buffer, size_t bufferSize, UDPHeader* udpHeader)
{
    int res = snprintf(buffer, bufferSize, "[UDP]:\nsource port: %u\ndestination port: %u\nlength: %u\nchecksum: %u, 0x%x\n . . . . . . . . . . \n", 
    ntohs(udpHeader->source), ntohs(udpHeader->dest), ntohs(udpHeader->len), ntohs(udpHeader->check), ntohs(udpHeader->check));

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

// TODO: improve!
int PacketCraft::ConvertHTTPLayerToString(char* buffer, size_t bufferSize, uint8_t* data, size_t dataSize)
{
    uint8_t* dataPtr = data;

    // TODO: is there a way to do this with a single buffer? Also should we allocate buffers in the heap?
    char dataStr[PC_TCP_MAX_DATA_STR_SIZE]{};
    char dataAsCharsStr[PC_TCP_MAX_DATA_STR_SIZE]{};
    char* dataStrPtr = dataStr;
    char* dataAsCharsPtr = dataAsCharsStr;
    uint32_t newLineAt = 15;

    for(unsigned int i = 0; i < dataSize; ++i)
    {
        int dataLen = snprintf(NULL, 0, "%x\t", (uint16_t)*dataPtr);
        snprintf(dataStrPtr, dataLen + 1, "%x\t", (uint16_t)*dataPtr);

        int dataAsCharsLen = snprintf(NULL, 0, "%c", (unsigned char)*dataPtr);
        snprintf(dataAsCharsPtr, dataAsCharsLen + 1, "%c", (unsigned char)*dataPtr);

        ++dataPtr;
        dataStrPtr += dataLen;
        dataAsCharsPtr += dataAsCharsLen;

        if(i != 0 && i % newLineAt == 0)
        {
            *dataStrPtr++ = '\n';
        }
    }

    *dataStrPtr = '\0';
    *dataAsCharsPtr = '\0';

    int res = snprintf(buffer, bufferSize, "[HTTP]:\nData:\n%s\n\nData as text:\n%s\n . . . . . . . . . . \n", dataStr, dataAsCharsStr);

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

// TODO: put the while(true) loops into a function or something
int PacketCraft::ConvertDNSLayerToString(char* buffer, size_t bufferSize, uint8_t* data, size_t dataSize)
{
    DNSHeader* dnsHeader = (DNSHeader*)data;
    uint8_t* querySection = dnsHeader->querySection;

    char dnsQuestionsDataStr[PC_DNS_MAX_DATA_STR_SIZE]{};
    char* dnsQuestionsDataStrPtr = dnsQuestionsDataStr;
    // converts all questions into strings and puts them in dnsQuestionsDataStr
    for(unsigned int i = 0; i < ntohs(dnsHeader->qcount); ++i)
    {
        char qName[255]{};
        char* qNamePtr = qName;

        uint32_t numLabels = 0;
        uint32_t nameLength = 0;
        while(true) // fills the qName buffer with a domain name
        {
            uint32_t labelLength = (uint32_t)*querySection; // first byte is the length of the first label
            ++querySection; // increment pointer to the start of the qname.
            memcpy(qNamePtr, querySection, labelLength); // copy label into the qName buffer
            querySection += labelLength; // will now point to the next label
            qNamePtr += labelLength;

            // append a '.' after each label
            *qNamePtr = '.';
            ++qNamePtr;

            ++numLabels;
            nameLength += labelLength;

            // if length of next label is 0, we have reached the end of the qname string. We increment the pointer to point to the QTYPE value.
            if((uint32_t)*querySection == 0)
            {
                --qNamePtr; // move pointer back because we want the last '.' character to be replaced with a '\0'
                ++querySection;
                break;
            }
        }

        
        *qNamePtr = '\0';

        uint16_t qType = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        uint16_t qClass = ntohs(*(uint16_t*)querySection);
        querySection += 2; // ptr now points to the answers section. Used when converting answers into string

        int len = snprintf(NULL, 0, "name: %s\nname length: %u\nnum labels: %u\nqtype: 0x%x\nqclass: 0x%x\n\n", qName, nameLength, numLabels, qType, qClass);
        snprintf(dnsQuestionsDataStrPtr, len + 1, "name: %s\nname length: %u\nnum labels: %u\nqtype: 0x%x\nqclass: 0x%x\n\n", qName, nameLength, numLabels, qType, qClass);

        dnsQuestionsDataStrPtr += len;
    }

    *dnsQuestionsDataStrPtr = '\0';

    char dnsAnswersDataStr[PC_DNS_MAX_DATA_STR_SIZE]{};
    char* dnsAnswersDataStrPtr = dnsAnswersDataStr;
    // converts all answers into strings and puts them in dnsAnswersDataStr
    for(unsigned int i = 0; i < ntohs(dnsHeader->ancount); ++i)
    {
        char aName[255]{};
        char* aNamePtr = aName;

        uint32_t numLabels = 0;
        uint32_t nameLength = 0;
        while(true) // fills the qName buffer with a domain name
        {
            uint32_t labelLength = *querySection; // first byte is the length of the first label
            ++querySection; // increment pointer to the start of the aname.
            memcpy(aNamePtr, querySection, labelLength); // copy label into the aName buffer
            querySection += labelLength; // will now point to the next label size
            aNamePtr += labelLength;

            // append a '.' after each label
            *aNamePtr = '.';
            ++aNamePtr;

            ++numLabels;
            nameLength += labelLength;

            // if length of next label is 0, we have reached the end of the aname string. We increment the pointer to point to the TYPE value.
            if((uint32_t)*querySection == 0)
            {
                --aNamePtr; // move pointer back because we want the last '.' character to be replaced with a '\0'
                ++querySection;
                break;
            }
        }

        *aNamePtr = '\0';

        uint16_t aType = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        uint16_t aClass = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        uint32_t timeToLive = ntohl(*(uint32_t*)querySection);
        querySection += 4;
        uint16_t rLength = ntohs(*(uint16_t*)querySection);
        querySection += 2;

        char* rData = (char*)malloc(rLength + 1);
        memcpy(rData, querySection, rLength);
        memset(rData + rLength, '\0', 1);
        querySection += rLength;

        int len = snprintf(NULL, 0, "name: %s\nname length: %u\nnum labels: %u\ntype: 0x%x\nclass: 0x%x\ntime to live: %u\ndata length: %u\ndata: %s\n\n",
            aName, nameLength, numLabels, aType, aClass, timeToLive, rLength, rData);

        snprintf(dnsAnswersDataStrPtr, len + 1, "name: %s\nname length: %u\nnum labels: %u\ntype: 0x%x\nclass: 0x%x\ntime to live: %u\ndata length: %u\ndata: %s\n\n",
            aName, nameLength, numLabels, aType, aClass, timeToLive, rLength, rData);

        dnsAnswersDataStrPtr += len;
        free(rData);
    }

    *dnsAnswersDataStrPtr = '\0';


    int res = snprintf(buffer, bufferSize, "[DNS]:\nidentification: 0x%x\nflags(0x%x):\n\tQR: %u, OPCODE: %u, AA: %u, TC: %u, RD: %u, RA: %u, Z: %u,\
RCODE: %u\n\nquestions: %u\nanswers: %u\nnumber of authority resource records: %u\nnumber of additional authority resource records: %u\n\n\
questions:\n%s\n\nanswers:\n%s\n . . . . . . . . . . \n", ntohs(dnsHeader->id), ntohs(dnsHeader->flags), dnsHeader->qr, dnsHeader->opcode, dnsHeader->aa, 
dnsHeader->tc, dnsHeader->rd, dnsHeader->ra, dnsHeader->zero, dnsHeader->rcode, ntohs(dnsHeader->qcount), ntohs(dnsHeader->ancount), 
ntohs(dnsHeader->nscount), ntohs(dnsHeader->adcount), dnsQuestionsDataStr, dnsAnswersDataStr);

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