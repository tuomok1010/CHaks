#include "IPv6PingPacket.h"
#include "Utils.h"
#include "NetworkUtils.h"

#include <iomanip>
#include <iostream>
#include <cstring>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>

PacketCraft::IPv6PingPacket::IPv6PingPacket() :
    ethHeader(nullptr),
    ipv6Header(nullptr),
    icmpv6Header(nullptr)
{

}

PacketCraft::IPv6PingPacket::~IPv6PingPacket()
{

}

int PacketCraft::IPv6PingPacket::Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in6& srcIP, const sockaddr_in6& dstIP, PingType type)
{
    AddLayer(PC_ETHER_II, sizeof(*ethHeader));
    ethHeader = (EthHeader*)GetLayerStart(0);
    memcpy(ethHeader->ether_shost, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(ethHeader->ether_dhost, dstMAC.ether_addr_octet, ETH_ALEN);
    ethHeader->ether_type = htons(ETH_P_IPV6);

    AddLayer(PC_IPV6, sizeof(*ipv6Header));
    ipv6Header = (IPv6Header*)GetLayerStart(1);
    ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
    ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(*icmpv6Header) + 4);
    ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt = 58;
    ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;
    ipv6Header->ip6_src = srcIP.sin6_addr;
    ipv6Header->ip6_dst = dstIP.sin6_addr;

    AddLayer(PC_ICMPV6, sizeof(*icmpv6Header) + 4);
    icmpv6Header = (ICMPv6Header*)GetLayerStart(2);
    icmpv6Header->icmp6_type = type == PingType::ECHO_REQUEST ? ICMP6_ECHO_REQUEST : ICMP6_ECHO_REPLY;
    icmpv6Header->icmp6_code = 0;

    // NOTE: these are the identifier and sequence 
    uint16_t* dataPtr16 = (uint16_t*)icmpv6Header->data;
    *dataPtr16 = htons(0x0000);
    ++dataPtr16;
    *dataPtr16 = htons(0x1);

    icmpv6Header->icmp6_cksum = 0;
    icmpv6Header->icmp6_cksum = CalculateICMPv6Checksum(ipv6Header, icmpv6Header, sizeof(*icmpv6Header) + 4);

    return NO_ERROR;
}

int PacketCraft::IPv6PingPacket::Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, PingType type)
{
    ether_addr srcMAC{};
    ether_addr dstMAC{};
    sockaddr_in6 srcIP{};
    sockaddr_in6 dstIP{};

    if(ether_aton_r(srcMACStr, &srcMAC) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_aton_r(dstMACStr, &dstMAC) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    if(inet_pton(AF_INET6, srcIPStr, &srcIP.sin6_addr) <= 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    if(inet_pton(AF_INET6, dstIPStr, &dstIP.sin6_addr) <= 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    return Create(srcMAC, dstMAC, srcIP, dstIP, type);
}

int PacketCraft::IPv6PingPacket::Send(const int socket, const char* interfaceName) const
{
    int ifIndex = if_nametoindex(interfaceName);
    if(ifIndex == 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "if_nametoindex() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_ll sockAddr{};
    sockAddr.sll_family = PF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_IPV6);
    sockAddr.sll_ifindex = ifIndex;
    sockAddr.sll_halen = ETH_ALEN;
    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    memcpy(sockAddr.sll_addr, ethHeader->ether_shost, ETH_ALEN);

    return Packet::Send(socket, 0, (sockaddr*)&sockAddr, sizeof(sockAddr));
}

void PacketCraft::IPv6PingPacket::ResetPacketBuffer()
{
    PacketCraft::Packet::ResetPacketBuffer();
    ethHeader = nullptr;
    ipv6Header = nullptr;
    icmpv6Header = nullptr;
}

int PacketCraft::IPv6PingPacket::ProcessReceivedPacket(uint8_t* packet, uint32_t layerSize, unsigned short protocol)
{
    switch(protocol)
    {
        case PC_PROTO_ETH:
        {
            AddLayer(PC_ETHER_II, ETH_HLEN);
            memcpy(GetData(), packet, ETH_HLEN);
            protocol = ntohs(((EthHeader*)packet)->ether_type);
            ethHeader = (EthHeader*)GetLayerStart(GetNLayers() - 1);
            packet += ETH_HLEN;
            break;
        }
        case ETH_P_IPV6:
        {
            IPv6Header* ipHeader = (IPv6Header*)packet;
            AddLayer(PC_IPV6, sizeof(IPv6Header));
            memcpy(GetLayerStart(GetNLayers() - 1), packet, sizeof(IPv6Header));
            protocol = ipHeader->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            ipv6Header = (IPv6Header*)GetLayerStart(GetNLayers() - 1);

            if(protocol == IPPROTO_ICMPV6)
                layerSize = ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen);

            packet += sizeof(IPv6Header);
            break;
        }
        case IPPROTO_ICMPV6:
        {
            AddLayer(PC_ICMPV6, layerSize);
            memcpy(GetLayerStart(GetNLayers() - 1), packet, layerSize);
            icmpv6Header = (ICMPv6Header*)GetLayerStart(GetNLayers() - 1);

            return NO_ERROR;
        }
        default:
        {
            ResetPacketBuffer();
            LOG_ERROR(APPLICATION_ERROR, "unsupported packet layer type received! Packet data cleared.");
            return APPLICATION_ERROR;
        }
    }

    return ProcessReceivedPacket(packet, layerSize, protocol);
}

void PacketCraft::IPv6PingPacket::FreePacket()
{
    // NOTE: are these necessary?  
    if(icmpv6Header->data != nullptr)
        free(icmpv6Header->data);
    //////////////////////////////

    PacketCraft::Packet::FreePacket();
    ethHeader = nullptr;
    ipv6Header = nullptr;
    icmpv6Header = nullptr;
}