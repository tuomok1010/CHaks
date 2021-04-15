#include "ARP.h"
#include "Utils.h"

#include <cstring>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

PacketCraft::ARPPacket::ARPPacket():
    ethHeader(nullptr),
    arpHeader(nullptr)
{

}

PacketCraft::ARPPacket::~ARPPacket()
{
    FreePacket();
}

int PacketCraft::ARPPacket::Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, ARPType type)
{
    FreePacket();

    ether_addr srcMAC;
    ether_addr dstMAC;
    sockaddr_in srcIP;
    sockaddr_in dstIP;

    if(ether_aton_r(srcMACStr, &srcMAC) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_aton_r(dstMACStr, &dstMAC) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    if(inet_pton(AF_INET, srcIPStr, &srcIP) <= 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    if(inet_pton(AF_INET, dstIPStr, &dstIP) <= 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    // NOTE: there is also a struct called ethhdr. Which one should we use?
    AddLayer(PC_ETHER_II, sizeof(ether_header));
    ethHeader = (ether_header*)GetLayerStart(0);
    memcpy(ethHeader->ether_shost, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(ethHeader->ether_dhost, dstMAC.ether_addr_octet, ETH_ALEN);
    ethHeader->ether_type = htons(ETH_P_ARP);

    AddLayer(PC_ARP, sizeof(ARPHeader));
    arpHeader = (ARPHeader*)GetLayerStart(1);
    arpHeader->arpHdr.ar_hrd = htons(ARPHRD_ETHER);
    arpHeader->arpHdr.ar_pro = htons(ETH_P_IP);
    arpHeader->arpHdr.ar_hln = ETH_ALEN;
    arpHeader->arpHdr.ar_pln = IPV4_ALEN;
    arpHeader->arpHdr.ar_op = htons(type == ARPType::ARP_REQUEST ? ARPOP_REQUEST : ARPOP_REPLY);
    memcpy(arpHeader->ar_sha, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_sip, &srcIP.sin_addr.s_addr, IPV4_ALEN);
    memcpy(arpHeader->ar_tha, dstMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_tip, &dstIP.sin_addr.s_addr, IPV4_ALEN);

    return NO_ERROR;
}

int PacketCraft::ARPPacket::Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, ARPType type)
{
    FreePacket();

    AddLayer(PC_ETHER_II, sizeof(ether_header));
    ethHeader = (ether_header*)GetLayerStart(0);
    memcpy(ethHeader->ether_shost, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(ethHeader->ether_dhost, dstMAC.ether_addr_octet, ETH_ALEN);
    ethHeader->ether_type = htons(ETH_P_ARP);

    AddLayer(PC_ARP, sizeof(ARPHeader));
    arpHeader = (ARPHeader*)GetLayerStart(1);
    arpHeader->arpHdr.ar_hrd = htons(ARPHRD_ETHER);
    arpHeader->arpHdr.ar_pro = htons(ETH_P_IP);
    arpHeader->arpHdr.ar_hln = ETH_ALEN;
    arpHeader->arpHdr.ar_pln = IPV4_ALEN;
    arpHeader->arpHdr.ar_op = htons(type == ARPType::ARP_REQUEST ? ARPOP_REQUEST : ARPOP_REPLY);
    memcpy(arpHeader->ar_sha, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_sip, &srcIP.sin_addr.s_addr, IPV4_ALEN);
    memcpy(arpHeader->ar_tha, dstMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_tip, &dstIP.sin_addr.s_addr, IPV4_ALEN);

    return NO_ERROR;
}

int PacketCraft::ARPPacket::Send(const int socket, const char* interfaceName) const
{
    int ifIndex = if_nametoindex(interfaceName);
    if(ifIndex == 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "if_nametoindex() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_ll sockAddr;
    sockAddr.sll_family = PF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_ARP);
    sockAddr.sll_ifindex = ifIndex;
    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    sockAddr.sll_halen = ETH_ALEN;

    return Packet::Send(socket, 0, (sockaddr*)&sockAddr, sizeof(sockAddr));
}

void PacketCraft::ARPPacket::PrintPacketData() const
{
    char ethDstMAC[ETH_ADDR_STR_LEN]{};
    char ethSrcMAC[ETH_ADDR_STR_LEN]{};
    uint16_t packetType{};


}

// TODO: extensive testing! This needs to be bulletproof!!!
int PacketCraft::ARPPacket::ProcessReceivedPacket(uint8_t* packet, unsigned short protocol)
{
    switch(protocol)
    {
        case 0:
        {
            AddLayer(PC_ETHER_II, ETH_HLEN);
            memcpy(GetData(), packet, ETH_HLEN);
            protocol = ((ether_header*)packet)->ether_type;
            ethHeader = (ether_header*)GetLayerStart(GetNLayers() - 1);
            (ether_header*)packet++;
        }
        case ETH_P_ARP:
        {
            AddLayer(PC_ARP, sizeof(ARPHeader));
            memcpy(GetLayerStart(GetNLayers() - 1), packet, sizeof(ARPHeader));
            arpHeader = (ARPHeader*)GetLayerStart(GetNLayers() - 1);
            return NO_ERROR;
        }
        default:
        {
            FreePacket();
            LOG_ERROR(APPLICATION_ERROR, "unsupported packet layer type received! Packet data cleared.");
            return APPLICATION_ERROR;
        }
    }

    return ProcessReceivedPacket(packet, protocol);

}