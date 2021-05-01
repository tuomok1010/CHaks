#include "IPv4PingPacket.h"
#include "Utils.h"

#include <iomanip>
#include <iostream>
#include <cstring>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>

PacketCraft::IPv4PingPacket::IPv4PingPacket() :
    ethHeader(nullptr),
    ipv4Header(nullptr),
    icmpv4Header(nullptr)
{

}

PacketCraft::IPv4PingPacket::~IPv4PingPacket()
{

}

int PacketCraft::IPv4PingPacket::Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, 
    const uint32_t ipHeaderLenInBytes, const uint32_t icmpv4HeaderLenInBytes, uint8_t icmpv4Type)
{
    AddLayer(PC_ETHER_II, ETH_HLEN);
    ethHeader = (ether_header*)GetLayerStart(0);
    memcpy(ethHeader->ether_shost, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(ethHeader->ether_dhost, dstMAC.ether_addr_octet, ETH_ALEN);
    ethHeader->ether_type = htons(ETH_P_IP);

    AddLayer(PC_IPV4, ipHeaderLenInBytes);
    ipv4Header = (ip*)GetLayerStart(1);
    ipv4Header->ip_hl = ipHeaderLenInBytes * 8 / 32;    // NOTE: this is a 4 bit bitfield value (check the struct declaration), not a 32bit unsigned int!
    ipv4Header->ip_v = IPVERSION;                       // NOTE: this is a 4 bit bitfield value (check the struct declaration), not a 32bit unsigned int!
    ipv4Header->ip_tos = IPTOS_CLASS_CS0;
    ipv4Header->ip_len = htons(ETH_HLEN + ipHeaderLenInBytes + icmpv4HeaderLenInBytes);
    ipv4Header->ip_id = htons(0);
    ipv4Header->ip_off = htons(IP_DF);
    ipv4Header->ip_ttl = IPDEFTTL;
    ipv4Header->ip_p = IPPROTO_ICMP;
    ipv4Header->ip_sum = htons(0);
    ipv4Header->ip_src = srcIP.sin_addr;
    ipv4Header->ip_dst = dstIP.sin_addr;
    ipv4Header->ip_sum = htons(CalculateIPv4Checksum(ipv4Header, ipHeaderLenInBytes));

    AddLayer(PC_ICMPV4, icmpv4HeaderLenInBytes);
    icmpv4Header = (icmphdr*)GetLayerStart(2);
    icmpv4Header->type = icmpv4Type;
    icmpv4Header->code = 0;
    icmpv4Header->un.echo.id = 0;
    icmpv4Header->un.echo.sequence = 0;
    icmpv4Header->checksum = 0;
    icmpv4Header->checksum = htons(CalculateIPv4Checksum(icmpv4Header, icmpv4HeaderLenInBytes));

    return NO_ERROR;
}

int PacketCraft::IPv4PingPacket::Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, 
    const uint32_t ipHeaderLenInBytes, const uint32_t icmpv4HeaderLenInBytes, uint8_t icmpv4Type)
{
    ether_addr srcMAC{};
    ether_addr dstMAC{};
    sockaddr_in srcIP{};
    sockaddr_in dstIP{};

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

    if(inet_pton(AF_INET, srcIPStr, &srcIP.sin_addr) <= 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    if(inet_pton(AF_INET, dstIPStr, &dstIP.sin_addr) <= 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    return Create(srcMAC, dstMAC, srcIP, dstIP, ipHeaderLenInBytes, icmpv4HeaderLenInBytes, icmpv4Type);
}

uint16_t PacketCraft::IPv4PingPacket::CalculateIPv4Checksum(void* ipv4Header, size_t ipv4HeaderSizeInBytes)
{
    uint16_t* header16 = (uint16_t*)ipv4Header;
    uint32_t sum = 0;
    while(ipv4HeaderSizeInBytes > 1)  
    {
        sum += *header16++;
        ipv4HeaderSizeInBytes -= 2;
    }

    if(ipv4HeaderSizeInBytes > 0)
        sum += *(uint8_t*)header16;

    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~(uint16_t)sum;
}

bool32 PacketCraft::IPv4PingPacket::VerifyIPv4Checksum(void* ipv4Header, size_t ipv4HeaderSizeInBytes) const
{
    uint16_t* header16 = (uint16_t*)ipv4Header;
    uint32_t sum = 0;
    while(ipv4HeaderSizeInBytes > 1)  
    {
        sum += *header16++;
        ipv4HeaderSizeInBytes -= 2;
    }

    if(ipv4HeaderSizeInBytes > 0)
        sum += *(uint8_t*)header16;

    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    if((uint16_t)sum == 0xffff)
        return TRUE;
    else
        return FALSE;
}

int PacketCraft::IPv4PingPacket::Send(const int socket, const char* interfaceName) const
{
    int ifIndex = if_nametoindex(interfaceName);
    if(ifIndex == 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "if_nametoindex() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_in dstInfo;
    memcpy(&dstInfo.sin_addr.s_addr, &ipv4Header->ip_dst.s_addr, IPV4_ALEN);
    dstInfo.sin_family = PF_PACKET;

    return Packet::Send(socket, 0, (sockaddr*)&dstInfo, sizeof(dstInfo));
}

void PacketCraft::IPv4PingPacket::ResetPacketBuffer()
{
    PacketCraft::Packet::ResetPacketBuffer();
    ethHeader = nullptr;
    ipv4Header = nullptr;
    icmpv4Header = nullptr;
}

int PacketCraft::IPv4PingPacket::PrintPacketData() const
{
    char ethDstAddr[ETH_ADDR_STR_LEN]{};    /* destination eth addr	*/
    char ethSrcAddr[ETH_ADDR_STR_LEN]{};    /* source ether addr	*/

    if(ether_ntoa_r((ether_addr*)ethHeader->ether_dhost, ethDstAddr) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r((ether_addr*)ethHeader->ether_shost, ethSrcAddr) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

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

    uint32_t icmpvHeaderSizeInBytes = htons(ipv4Header->ip_len) - ETH_HLEN - htonl(ipv4Header->ip_hl);
    const char* ipv4ChecksumVerified = VerifyIPv4Checksum(ipv4Header, ipv4Header->ip_hl) == TRUE ? "verified" : "unverified";
    const char* icmpv4ChecksumVerified = VerifyIPv4Checksum(icmpv4Header, icmpvHeaderSizeInBytes) == TRUE ? "verified" : "unverified";

    // TODO: format nicely with iomanip perhaps?
    std::cout
        << " = = = = = = = = = = = = = = = = = = = = \n"
        << "[ETHERNET]:\n"
        << "destination: "          << ethDstAddr << "\n"
        << "source: "               << ethSrcAddr << "\n"
        << "type: "                 << ntohs(ethHeader->ether_type) << "\n"
        << " - - - - - - - - - - - - - - - - - - - - \n"
        << "[IPv4]:\n"
        << "ip version: " << ipv4Header->ip_v << "\n"
        << "header length: " << ipv4Header->ip_hl << "\n"
        << "ToS: " << std::hex << ipv4Header->ip_tos << std::dec << "\n"  // TODO: print DSCP and ECN separately
        << "total length: " << htons(ipv4Header->ip_len) << "\n"
        << "identification: " << htons(ipv4Header->ip_id) << "\n"
        << "flags: " << std::hex << htons(ipv4Header->ip_off) << std::dec << "(" << htons(ipv4Header->ip_off) << ")\n"
        << "\t bit 1(Don't Fragment): " << (htons(ipv4Header->ip_off) & 0x4000) << " bit 2(More Fragments): " << (htons(ipv4Header->ip_off) & 0x2000) << "\n"
        << "time to live: " << ipv4Header->ip_ttl << "\n"
        << "protocol: " << ipv4Header->ip_p << "\n"
        << "checksum: " << htons(ipv4Header->ip_sum) << "(" << ipv4ChecksumVerified << ")" << "\n"
        << "source: " << srcIPStr << " " << "destination: " << dstIPStr << "\n"
        << " - - - - - - - - - - - - - - - - - - - - \n"
        << "[ICMPv4]:\n"
        << "type: " << icmpv4Header->type << "\n"
        << "code: " << icmpv4Header->code << "\n"
        << "checksum: " << htons(icmpv4Header->checksum) << "(" << icmpv4ChecksumVerified << ")" << "\n"
        << "id: " << htons(icmpv4Header->un.echo.id) << " sequence: " << htons(icmpv4Header->un.echo.sequence) << std::endl;

    return NO_ERROR;
}

int PacketCraft::IPv4PingPacket::ProcessReceivedPacket(uint8_t* packet, unsigned short nextHeader)
{
    return NO_ERROR;
}

void PacketCraft::IPv4PingPacket::FreePacket()
{
    PacketCraft::Packet::FreePacket();
    ethHeader = nullptr;
    ipv4Header = nullptr;
    icmpv4Header = nullptr;
}