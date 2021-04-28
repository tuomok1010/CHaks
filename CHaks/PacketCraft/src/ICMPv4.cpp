#include "ICMPv4.h"

#include <cstring>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ether.h>

PacketCraft::ICMPv4Packet::ICMPv4Packet();
{

}

PacketCraft::ICMPv4Packet::~ICMPv4Packet()
{

}

int PacketCraft::ICMPv4Packet::Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, 
    const uint32_t ipHeaderLenInBytes, const uint32_t icmpv4HeaderLenInBytes, uint8_t icmpv4Type, uint8_t icmpv4Code)
{
    AddLayer(PC_ETHER_II, ETH_HLEN);
    ethHeader = (ether_header*)GetLayerStart(0);
    memcpy(ethHeader->ether_shost, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(ethHeader->ether_dhost, dstMAC.ether_addr_octet, ETH_ALEN);
    ethHeader->ether_type = htons(ETH_P_IP);

    AddLayer(PC_IPV4, ipHeaderLenInBytes);
    ipv4Header = (ip*)GetLayerStart(1);
    ipv4Header->ip_hl = htonl(ipHeaderLenInBytes * 8 / 32);
    ipv4Header->ip_v = htonl(IPVERSION);
    ipv4Header->ip_tos = 0;
    ipv4Header->ip_len = htons(ETH_HLEN + ipHeaderLenInBytes + icmpv4HeaderLenInBytes);
    ipv4Header->ip_id = htons(0);
    ipv4Header->ip_off = htons(IP_DF);
    ipv4Header->ip_ttl = IPDEFTTL;
    ipv4Header->ip_p = IPPROTO_ICMP;
    ipv4Header->ip_sum = 0; // TODO: calculate!
    ipv4Header->ip_src = srcIP.sin_addr;
    ipv4Header->ip_dst = dstIP.sin_addr;

    AddLayer(PC_ICMPV4, icmpv4HeaderLenInBytes);
    icmpv4Header = (icmphdr*)GetLayerStart(2);
    icmpv4Header->type = icmpv4Type;
    icmpv4Header->code = icmpv4Code;
    icmpv4Header->checksum = 0; // TODO: calculate!
    icmpv4Header->un = 0;       // rest of the header - vary depending on the type and code. TODO: figure it out!
}

int PacketCraft::ICMPv4Packet::Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr,
    const uint32_t ipHeaderLenInBytes, const uint32_t icmpv4HeaderLenInBytes, uint8_t icmpv4Type, uint8_t icmpv4Code)
{

}

void PacketCraft::ICMPv4Packet::CalculateIPv4Checksum(void* ipv4Header, size_t ipv4HeaderSizeInBytes)
{

}

int PacketCraft::ICMPv4Packet::Send(const int socket, const char* interfaceName) const
{

}

void PacketCraft::ICMPv4Packet::ResetPacketBuffer()
{

}

int PacketCraft::ICMPv4Packet::PrintPacketData() const
{

}

int PacketCraft::ICMPv4Packet::ProcessReceivedPacket(uint8_t* packet, unsigned short nextHeader)
{

}

void PacketCraft::ICMPv4Packet::FreePacket()
{

}