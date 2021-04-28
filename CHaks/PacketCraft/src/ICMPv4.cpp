#include "ICMPv4.h"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>

PacketCraft::ICMPv4Packet::ICMPv4Packet();
{

}

PacketCraft::ICMPv4Packet::~ICMPv4Packet()
{

}

int PacketCraft::ICMPv4Packet::Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, 
    const int ipHeaderLenInBytes, const int icmpv4HeaderLenInBytes)
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
}

int PacketCraft::ICMPv4Packet::Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr,
    const int ipHeaderLenInBytes, const int icmpv4HeaderLenInBytes)
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