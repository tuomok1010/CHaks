#include "IPv4PingPacket.h"
#include "Utils.h"
#include "NetworkUtils.h"

#include <iomanip>
#include <iostream>
#include <cstring>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>

PacketCraft::IPv4PingPacket::IPv4PingPacket() :
    ethHeader(nullptr),
    ipv4Header(nullptr),
    icmpv4Header(nullptr)
{

}

PacketCraft::IPv4PingPacket::~IPv4PingPacket()
{

}

int PacketCraft::IPv4PingPacket::Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, PingType type)
{
    AddLayer(PC_ETHER_II, sizeof(*ethHeader));
    ethHeader = (EthHeader*)GetLayerStart(0);
    memcpy(ethHeader->ether_shost, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(ethHeader->ether_dhost, dstMAC.ether_addr_octet, ETH_ALEN);
    ethHeader->ether_type = htons(ETH_P_IP);

    AddLayer(PC_IPV4, sizeof(*ipv4Header));
    ipv4Header = (IPv4Header*)GetLayerStart(1);
    ipv4Header->ip_hl = sizeof(*ipv4Header) * 8 / 32;
    ipv4Header->ip_v = IPVERSION;                       
    ipv4Header->ip_tos = IPTOS_CLASS_CS0;
    ipv4Header->ip_len = htons(sizeof(*ipv4Header) + sizeof(*icmpv4Header));
    ipv4Header->ip_id = htons(0);
    ipv4Header->ip_off = htons(IP_DF);
    ipv4Header->ip_ttl = IPDEFTTL;
    ipv4Header->ip_p = IPPROTO_ICMP;
    ipv4Header->ip_sum = htons(0);
    ipv4Header->ip_src = srcIP.sin_addr;
    ipv4Header->ip_dst = dstIP.sin_addr;
    ipv4Header->ip_sum = CalculateChecksum(ipv4Header, sizeof(*ipv4Header));

    AddLayer(PC_ICMPV4, sizeof(*icmpv4Header));
    icmpv4Header = (ICMPv4Header*)GetLayerStart(2);
    icmpv4Header->type = type == PingType::ECHO_REQUEST ? ICMP_ECHO : ICMP_ECHOREPLY;
    icmpv4Header->code = 0;
    icmpv4Header->un.echo.id = 0;
    icmpv4Header->un.echo.sequence = 0;
    icmpv4Header->checksum = 0;
    icmpv4Header->checksum = CalculateChecksum(icmpv4Header, sizeof(*icmpv4Header));

    return NO_ERROR;
}

int PacketCraft::IPv4PingPacket::Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, PingType type)
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

    return Create(srcMAC, dstMAC, srcIP, dstIP, type);
}

int PacketCraft::IPv4PingPacket::Send(const int socket, const char* interfaceName) const
{
    int ifIndex = if_nametoindex(interfaceName);
    if(ifIndex == 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "if_nametoindex() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_ll sockAddr{};
    sockAddr.sll_family = PF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_IP);
    sockAddr.sll_ifindex = ifIndex;
    sockAddr.sll_halen = ETH_ALEN;
    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    memcpy(sockAddr.sll_addr, ethHeader->ether_shost, ETH_ALEN);

    return Packet::Send(socket, 0, (sockaddr*)&sockAddr, sizeof(sockAddr));
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

    uint32_t icmpvHeaderSizeInBytes = htons(ipv4Header->ip_len) - ETH_HLEN - ipv4Header->ip_hl;
    const char* ipv4ChecksumVerified = VerifyChecksum(ipv4Header, ipv4Header->ip_hl) == TRUE ? "verified" : "unverified";
    const char* icmpv4ChecksumVerified = VerifyChecksum(icmpv4Header, icmpvHeaderSizeInBytes) == TRUE ? "verified" : "unverified";
    bool32 flagDFSet = ((ntohs(ipv4Header->ip_off)) & (IP_DF)) != 0;
    bool32 flagMFSet = ((ntohs(ipv4Header->ip_off)) & (IP_MF)) != 0;

    // TODO: test
    bool32 hasIpv4Options = ipv4Header->ip_hl > 5 ? TRUE : FALSE;
    uint32_t ipv4OptionsSize = ipv4Header->ip_hl - 5;

    // TODO: test
    bool32 hasIcmpv4Data = htons(ipv4Header->ip_len) - ipv4Header->ip_hl > (int)sizeof(ICMPv4Header) ? TRUE : FALSE;
    uint32_t icmpv4DataSize = htons(ipv4Header->ip_len) - ipv4Header->ip_hl - sizeof(ICMPv4Header);

    // TODO: format nicely with iomanip perhaps?
    std::cout
        << " = = = = = = = = = = = = = = = = = = = = \n"
        << "[ETHERNET]:\n"
        << "destination: "    << ethDstAddr << "\n"
        << "source: "         << ethSrcAddr << "\n"
        << "type: 0x"         << std::hex << ntohs(ethHeader->ether_type) << "(" << std::dec << ntohs(ethHeader->ether_type) << ")\n"
        << " - - - - - - - - - - - - - - - - - - - - \n"
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
        << "source: "         << srcIPStr << " " << "destination: " << dstIPStr << "\n";

    if(hasIpv4Options == TRUE)
    {
        int newLineAt = 7;
        for(unsigned int i = 0; i < ipv4OptionsSize; ++i)
        {
            std::cout << std::hex << ipv4Header->options[i];
            if(i % newLineAt == 0)
                std::cout << "\n";
        }
        std::cout << std::dec;
    }

    std::cout
        << " - - - - - - - - - - - - - - - - - - - - \n"
        << "[ICMPv4]:\n"
        << "type: "           << (uint16_t)icmpv4Header->type << "\n"
        << "code: "           << (uint16_t)icmpv4Header->code << "\n"
        << "checksum: "       << ntohs(icmpv4Header->checksum) << "(" << icmpv4ChecksumVerified << ")" << "\n"
        << "id: "             << ntohs(icmpv4Header->un.echo.id) << " sequence: " << ntohs(icmpv4Header->un.echo.sequence) << "\n";

    if(hasIcmpv4Data == TRUE)
    {
        int newLineAt = 7;
        for(unsigned int i = 0; i < icmpv4DataSize; ++i)
        {
            std::cout << std::hex << icmpv4Header->data[i];
            if(i % newLineAt == 0)
                std::cout << "\n";
        }
        std::cout << std::dec << std::flush;
    }

    return NO_ERROR;
}

int PacketCraft::IPv4PingPacket::ProcessReceivedPacket(uint8_t* packet, int layerSize, unsigned short protocol)
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
        case ETH_P_IP:
        {
            IPv4Header* ipHeader = (IPv4Header*)packet;
            AddLayer(PC_IPV4, ipHeader->ip_hl * 32 / 8);
            memcpy(GetLayerStart(GetNLayers() - 1), packet, ipHeader->ip_hl * 32 / 8);
            protocol = ipHeader->ip_p;
            ipv4Header = (IPv4Header*)GetLayerStart(GetNLayers() - 1);

            // this is the next layer size
            layerSize = ntohs(ipHeader->ip_len) - (ipHeader->ip_hl * 32 / 8);

            if(ipHeader->ip_hl > 5)
            {   
                // checks if there is an options field present. TODO: do we need to do anything?
            }

            packet += (uint32_t)ipHeader->ip_hl * 32 / 8;
            break;
        }
        case IPPROTO_ICMP:
        {
            AddLayer(PC_ICMPV4, layerSize);
            memcpy(GetLayerStart(GetNLayers() - 1), packet, layerSize);
            icmpv4Header = (ICMPv4Header*)GetLayerStart(GetNLayers() - 1);

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

void PacketCraft::IPv4PingPacket::FreePacket()
{
    // NOTE: are these necessary?
    if(ipv4Header->options != nullptr)
        free(ipv4Header->options);
    
    if(icmpv4Header->data != nullptr)
        free(icmpv4Header->data);
    //////////////////////////////

    PacketCraft::Packet::FreePacket();
    ethHeader = nullptr;
    ipv4Header = nullptr;
    icmpv4Header = nullptr;
}